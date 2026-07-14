"""
warden/tests/test_security_hardening.py
────────────────────────────────────────
Regression tests for the security-hardening pass:

  1. net_guard SSRF filter (private / loopback / metadata / scheme).
  2. Webhook engine rejects SSRF URLs at registration.
  3. secret_keys fail-closed signing-key resolver.
  4. action_whitelist admin gate fails closed + constant-time.
  5. SemanticQueryEngine.compile_query escapes filter literals (SQLi).
"""
from __future__ import annotations

import pytest

# ── 1. net_guard ────────────────────────────────────────────────────────────

class TestNetGuard:
    @pytest.fixture(autouse=True)
    def _enforce(self, monkeypatch):
        # Turn the guard ON for these tests (conftest disables it globally).
        monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "false")

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/x",
        "http://127.0.0.1:8001/filter",
        "http://10.0.0.5/internal",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",   # cloud metadata
        "http://[::1]/x",                              # IPv6 loopback
        "http://0.0.0.0/",
        "ftp://example.com/x",                         # bad scheme
        "file:///etc/passwd",                          # bad scheme
        "gopher://127.0.0.1/",
        "http:///nohost",                              # no host
    ])
    def test_blocks_unsafe(self, url):
        from warden.net_guard import SSRFError, assert_public_url
        with pytest.raises(SSRFError):
            assert_public_url(url)

    @pytest.mark.parametrize("url", [
        "https://8.8.8.8/",       # public IP literal — no DNS needed
        "http://1.1.1.1/path",
    ])
    def test_allows_public_ip(self, url):
        from warden.net_guard import assert_public_url
        assert_public_url(url)  # must not raise

    def test_is_public_url_bool(self):
        from warden.net_guard import is_public_url
        assert is_public_url("https://8.8.8.8/") is True
        assert is_public_url("http://127.0.0.1/") is False

    def test_bypass_flag_allows_private(self, monkeypatch):
        monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "true")
        from warden.net_guard import assert_public_url
        assert_public_url("http://127.0.0.1:8001/")  # bypass → no raise


# ── 2. Webhook engine SSRF guard ────────────────────────────────────────────

class TestWebhookSSRF:
    def test_create_endpoint_rejects_private(self, monkeypatch):
        monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "false")
        from warden.net_guard import SSRFError
        from warden.webhooks.engine import create_endpoint
        with pytest.raises(SSRFError):
            create_endpoint("t1", "http://169.254.169.254/latest/", "sekret", ["filter.blocked"])

    def test_create_endpoint_allows_public_ip(self, monkeypatch):
        monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "false")
        from warden.webhooks.engine import create_endpoint
        ep = create_endpoint("t1", "https://8.8.8.8/hook", "sekret", ["filter.blocked"])
        assert ep.url == "https://8.8.8.8/hook"

    @pytest.mark.asyncio
    async def test_delivery_uses_pinned_send(self, monkeypatch):
        """SR-2.3: _deliver_once must route through send_pinned_async (validate + pin),
        not a bare httpx.post that would re-resolve at connect time."""
        import warden.net_guard as ng
        from warden.webhooks.engine import WebhookEndpoint, _deliver_once

        seen = {}

        async def _fake_send(method, url, *, content, headers, timeout):
            seen.update(method=method, url=url, content=content, headers=headers)

            class _Resp:
                status_code = 202
            return _Resp()

        monkeypatch.setattr(ng, "send_pinned_async", _fake_send)
        ep = WebhookEndpoint(id="w1", tenant_id="t1", url="https://8.8.8.8/hook",
                             secret="sekret", events=["filter.blocked"], enabled=True,
                             created_at="2026-01-01T00:00:00Z")
        code = await _deliver_once(ep, {"event_type": "filter.blocked"}, attempt=1)
        assert code == 202
        assert seen["method"] == "POST"
        assert seen["url"] == "https://8.8.8.8/hook"
        assert seen["headers"]["X-Warden-Signature"].startswith("sha256=")

    @pytest.mark.asyncio
    async def test_delivery_ssrf_returns_zero(self, monkeypatch):
        """A rebind detected at delivery time (SSRFError) must fail the delivery, not raise."""
        import warden.net_guard as ng
        from warden.webhooks.engine import WebhookEndpoint, _deliver_once

        async def _raise(*a, **k):
            raise ng.SSRFError("rebind to private IP")

        monkeypatch.setattr(ng, "send_pinned_async", _raise)
        ep = WebhookEndpoint(id="w2", tenant_id="t1", url="https://evil.example.com/hook",
                             secret="sekret", events=["filter.blocked"], enabled=True,
                             created_at="2026-01-01T00:00:00Z")
        assert await _deliver_once(ep, {"event_type": "filter.blocked"}, attempt=1) == 0


# ── 3. secret_keys resolver ─────────────────────────────────────────────────

class TestSecretKeys:
    def test_explicit_env_wins(self, monkeypatch):
        monkeypatch.setenv("L402_HMAC_KEY", "operator-override")
        from warden.secret_keys import resolve_key
        assert resolve_key("L402_HMAC_KEY", purpose="l402") == b"operator-override"

    def test_derives_from_master_when_unset(self, monkeypatch):
        monkeypatch.delenv("L402_HMAC_KEY", raising=False)
        monkeypatch.setenv("VAULT_MASTER_KEY", "master-secret-xyz")
        from warden.secret_keys import resolve_key
        key = resolve_key("L402_HMAC_KEY", purpose="l402")
        assert isinstance(key, bytes) and len(key) == 32
        assert b"shadow-warden-l402-dev" not in key   # no public constant

    def test_domain_separation(self, monkeypatch):
        monkeypatch.delenv("L402_HMAC_KEY", raising=False)
        monkeypatch.delenv("KYA_TRUST_HMAC_KEY", raising=False)
        monkeypatch.setenv("VAULT_MASTER_KEY", "master-secret-xyz")
        from warden.secret_keys import resolve_key
        k_l402 = resolve_key("L402_HMAC_KEY", purpose="l402")
        k_kya  = resolve_key("KYA_TRUST_HMAC_KEY", purpose="kya_trust")
        assert k_l402 != k_kya   # distinct subkeys per purpose

    def test_fail_closed_in_production(self, monkeypatch):
        monkeypatch.delenv("L402_HMAC_KEY", raising=False)
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.delenv("COMMUNITY_VAULT_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
        monkeypatch.setenv("ALLOW_INSECURE_SECRETS", "false")
        from warden.secret_keys import InsecureKeyError, resolve_key
        with pytest.raises(InsecureKeyError):
            resolve_key("L402_HMAC_KEY", purpose="l402")

    def test_dev_mode_allows_derivation(self, monkeypatch):
        monkeypatch.delenv("L402_HMAC_KEY", raising=False)
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.delenv("COMMUNITY_VAULT_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")
        from warden.secret_keys import resolve_key
        key = resolve_key("L402_HMAC_KEY", purpose="l402")
        assert isinstance(key, bytes) and len(key) == 32


# ── 4. action_whitelist admin gate ──────────────────────────────────────────

class TestAdminGate:
    def test_fail_closed_when_unset_in_prod(self, monkeypatch):
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
        from fastapi import HTTPException

        from warden.api.action_whitelist import _require_admin
        with pytest.raises(HTTPException) as exc:
            _require_admin(x_admin_key="")
        assert exc.value.status_code == 503

    def test_wrong_key_rejected(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "correct-key")
        from fastapi import HTTPException

        from warden.api.action_whitelist import _require_admin
        with pytest.raises(HTTPException) as exc:
            _require_admin(x_admin_key="wrong-key")
        assert exc.value.status_code == 403

    def test_correct_key_accepted(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "correct-key")
        from warden.api.action_whitelist import _require_admin
        assert _require_admin(x_admin_key="correct-key") is None

    def test_dev_mode_allows_unset(self, monkeypatch):
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")
        from warden.api.action_whitelist import _require_admin
        assert _require_admin(x_admin_key="") is None


# ── 5. SemanticQueryEngine SQLi ─────────────────────────────────────────────

class TestSemanticSQLi:
    def _model(self):
        from warden.semantic_layer.models import Dimension, Metric, SemanticModel
        return SemanticModel(
            id="t", name="t", source_table="events",
            metrics=[Metric(name="cnt", expression="COUNT(*)")],
            dimensions=[Dimension(name="verdict", column="verdict")],
        )

    def test_filter_value_is_escaped(self):
        from warden.semantic_layer.engine import SemanticQueryEngine
        from warden.semantic_layer.models import Filter, QueryObject
        q = QueryObject(
            model_id="t", metrics=["cnt"], dimensions=["verdict"],
            filters=[Filter(dimension="verdict", operator="=", value="x' OR '1'='1")],
        )
        sql = SemanticQueryEngine().compile_query(q, self._model())
        # The injected quote must be doubled, not left to break out of the literal.
        assert "'x'' OR ''1''=''1'" in sql
        assert "OR '1'='1'" not in sql

    def test_bad_operator_rejected(self):
        from warden.semantic_layer.engine import SemanticQueryEngine
        from warden.semantic_layer.models import Filter, QueryObject
        q = QueryObject(
            model_id="t", metrics=["cnt"], dimensions=["verdict"],
            filters=[Filter(dimension="verdict", operator="; DROP TABLE events;--", value="1")],
        )
        with pytest.raises(ValueError):
            SemanticQueryEngine().compile_query(q, self._model())

    def test_unsafe_identifier_rejected(self):
        from warden.semantic_layer.engine import SemanticQueryEngine
        from warden.semantic_layer.models import Filter, QueryObject
        q = QueryObject(
            model_id="t", metrics=["cnt"],
            dimensions=[],
            filters=[Filter(dimension="v; DROP TABLE x", operator="=", value="1")],
        )
        with pytest.raises(ValueError):
            SemanticQueryEngine().compile_query(q, self._model())
