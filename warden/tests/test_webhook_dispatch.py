"""
warden/tests/test_webhook_dispatch.py
══════════════════════════════════════
Tests for per-tenant outbound webhooks (WebhookStore + dispatch_event).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

import pytest

from warden.webhook_dispatch import WebhookStore, _sign, dispatch_event

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def store(tmp_path):
    """WebhookStore backed by a temp SQLite DB."""
    db = str(tmp_path / "webhooks.db")
    with patch("warden.webhook_dispatch._DB_PATH", db):
        yield WebhookStore()


# ── WebhookStore CRUD ─────────────────────────────────────────────────────────

class TestWebhookStore:
    def test_register_and_get(self, store):
        store.register("acme", "https://hooks.acme.com/warden", "s3cr3t-key-16chars")
        cfg = store.get("acme")
        assert cfg is not None
        assert cfg["url"] == "https://hooks.acme.com/warden"
        assert cfg["min_risk"] == "high"
        assert cfg["tenant_id"] == "acme"
        assert "created_at" in cfg
        assert "secret" not in cfg   # secret not exposed via get()

    def test_register_updates_existing(self, store):
        store.register("acme", "https://v1.acme.com", "s3cr3t-key-16chars")
        store.register("acme", "https://v2.acme.com", "new-secret-16chars", min_risk="medium")
        cfg = store.get("acme")
        assert cfg["url"] == "https://v2.acme.com"
        assert cfg["min_risk"] == "medium"

    def test_get_nonexistent_returns_none(self, store):
        assert store.get("no-such-tenant") is None

    def test_deregister_existing(self, store):
        store.register("acme", "https://hooks.acme.com", "s3cr3t-key-16chars")
        assert store.deregister("acme") is True
        assert store.get("acme") is None

    def test_deregister_nonexistent_returns_false(self, store):
        assert store.deregister("ghost") is False

    def test_multiple_tenants_isolated(self, store):
        store.register("acme", "https://acme.com", "s3cr3t-key-16chars")
        store.register("beta", "https://beta.com", "beta-secret-16char")
        assert store.get("acme")["url"] == "https://acme.com"
        assert store.get("beta")["url"] == "https://beta.com"
        store.deregister("acme")
        assert store.get("acme") is None
        assert store.get("beta") is not None


# ── Signature ─────────────────────────────────────────────────────────────────

class TestSignature:
    def test_sign_format(self):
        sig = _sign(b'{"test":1}', "mysecret")
        assert sig.startswith("sha256=")
        assert len(sig) == 7 + 64   # "sha256=" + 64 hex chars

    def test_sign_deterministic(self):
        body = b'{"event_id":"abc"}'
        assert _sign(body, "secret") == _sign(body, "secret")

    def test_sign_different_secret(self):
        body = b'{"event_id":"abc"}'
        assert _sign(body, "secret1") != _sign(body, "secret2")

    def test_sign_verification_receiver_side(self):
        secret = "mysecret"
        body   = b'{"event_id":"abc"}'
        sig    = _sign(body, secret)
        _, hex_digest = sig.split("=", 1)
        expected = hmac.new(secret.encode(), body, "sha256").hexdigest()
        assert hex_digest == expected


# ── dispatch_event ────────────────────────────────────────────────────────────

class TestDispatchEvent:
    @pytest.mark.asyncio
    async def test_no_webhook_registered(self, store):
        # Should return without raising even if no webhook is registered
        await dispatch_event(
            tenant_id="unknown", risk_level="high",
            owasp_categories=[], reason="test",
            content="hello", processing_ms=5.0, store=store,
        )

    @pytest.mark.asyncio
    async def test_below_min_risk_not_delivered(self, store):
        store.register("acme", "https://hooks.acme.com", "s3cr3t-key-16chars", min_risk="high")
        with patch("warden.webhook_dispatch._deliver", new_callable=AsyncMock) as mock_deliver:
            await dispatch_event(
                tenant_id="acme", risk_level="medium",
                owasp_categories=[], reason="test",
                content="hello", processing_ms=5.0, store=store,
            )
        mock_deliver.assert_not_called()

    @pytest.mark.asyncio
    async def test_high_risk_delivered(self, store):
        store.register("acme", "https://hooks.acme.com", "s3cr3t-key-16chars", min_risk="high")
        with patch("warden.webhook_dispatch._deliver", new_callable=AsyncMock) as mock_deliver:
            await dispatch_event(
                tenant_id="acme", risk_level="high",
                owasp_categories=["LLM02"], reason="xss detected",
                content="hello world", processing_ms=5.0, store=store,
            )
        mock_deliver.assert_called_once()
        url, body_bytes, sig = mock_deliver.call_args[0]
        assert url == "https://hooks.acme.com"
        payload = json.loads(body_bytes)
        assert payload["tenant_id"] == "acme"
        assert payload["risk_level"] == "high"
        assert payload["owasp_categories"] == ["LLM02"]
        assert payload["content_hash"].startswith("sha256:")
        assert "hello world" not in body_bytes.decode()   # GDPR: no raw content
        assert sig.startswith("sha256=")

    @pytest.mark.asyncio
    async def test_block_delivered_with_medium_threshold(self, store):
        store.register("acme", "https://hooks.acme.com", "s3cr3t-key-16chars", min_risk="medium")
        with patch("warden.webhook_dispatch._deliver", new_callable=AsyncMock) as mock_deliver:
            await dispatch_event(
                tenant_id="acme", risk_level="block",
                owasp_categories=[], reason="jailbreak",
                content="ignore instructions", processing_ms=10.0, store=store,
            )
        mock_deliver.assert_called_once()

    @pytest.mark.asyncio
    async def test_content_hash_correct(self, store):
        store.register("acme", "https://hooks.acme.com", "s3cr3t-key-16chars")
        content = "test payload"
        with patch("warden.webhook_dispatch._deliver", new_callable=AsyncMock) as mock_deliver:
            await dispatch_event(
                tenant_id="acme", risk_level="high",
                owasp_categories=[], reason="",
                content=content, processing_ms=1.0, store=store,
            )
        _, body_bytes, _ = mock_deliver.call_args[0]
        payload = json.loads(body_bytes)
        expected_hash = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
        assert payload["content_hash"] == expected_hash

    @pytest.mark.asyncio
    async def test_low_risk_not_delivered_with_high_threshold(self, store):
        store.register("acme", "https://hooks.acme.com", "s3cr3t-key-16chars", min_risk="high")
        with patch("warden.webhook_dispatch._deliver", new_callable=AsyncMock) as mock_deliver:
            await dispatch_event(
                tenant_id="acme", risk_level="low",
                owasp_categories=[], reason="",
                content="safe", processing_ms=1.0, store=store,
            )
        mock_deliver.assert_not_called()


# ── API endpoints ─────────────────────────────────────────────────────────────

class TestWebhookRoutes:
    @pytest.fixture(autouse=True)
    def _client(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        import warden.main as main_mod
        import warden.webhook_dispatch as wd_mod
        from warden.main import app

        db = str(tmp_path / "webhooks_test.db")
        # Patch _DB_PATH for the entire test — covers both __init__ and later calls
        monkeypatch.setattr(wd_mod, "_DB_PATH", db)

        self._orig_store = main_mod._webhook_store
        main_mod._webhook_store = WebhookStore()
        with TestClient(app, raise_server_exceptions=True) as c:
            self.client = c
            yield
        main_mod._webhook_store = self._orig_store

    def test_register_webhook(self):
        resp = self.client.post(
            "/webhook",
            json={"url": "https://hooks.acme.com", "secret": "s3cr3t-key-16chars"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["url"] == "https://hooks.acme.com"
        assert data["min_risk"] == "high"

    def test_get_webhook(self):
        self.client.post(
            "/webhook",
            json={"url": "https://hooks.acme.com", "secret": "s3cr3t-key-16chars"},
        )
        resp = self.client.get("/webhook")
        assert resp.status_code == 200
        assert resp.json()["url"] == "https://hooks.acme.com"

    def test_get_webhook_not_found(self):
        resp = self.client.get("/webhook")
        assert resp.status_code == 404

    def test_delete_webhook(self):
        self.client.post(
            "/webhook",
            json={"url": "https://hooks.acme.com", "secret": "s3cr3t-key-16chars"},
        )
        resp = self.client.delete("/webhook")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"
        assert self.client.get("/webhook").status_code == 404

    def test_delete_nonexistent_returns_404(self):
        resp = self.client.delete("/webhook")
        assert resp.status_code == 404

    def test_register_with_medium_min_risk(self):
        resp = self.client.post(
            "/webhook",
            json={
                "url": "https://hooks.acme.com",
                "secret": "s3cr3t-key-16chars",
                "min_risk": "medium",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["min_risk"] == "medium"
