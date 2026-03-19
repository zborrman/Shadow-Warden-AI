"""
warden/tests/test_stripe_billing.py
─────────────────────────────────────
Unit + integration tests for PaddleBilling.

All Paddle API calls are mocked — no network or real Paddle account needed.

Coverage
────────
  • get_plan / get_quota    — free, pro, msp, cancelled, past_due, trialing
  • get_status              — unknown tenant, known tenant
  • create_checkout_session — disabled, invalid plan, success
  • get_portal_url          — no customer, with customer
  • handle_webhook          — bad sig, transaction.completed, subscription.canceled,
                              subscription.past_due, unknown event
  • HTTP endpoints          — /billing/status, /billing/checkout,
                              /billing/webhook (via TestClient)
"""
from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest

from warden.paddle_billing import PLAN_QUOTAS, PaddleBilling

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def store(tmp_path: Path) -> Generator[PaddleBilling, None, None]:
    """Disabled PaddleBilling (no API key) — for plan/quota/DB tests."""
    pb = PaddleBilling(db_path=tmp_path / "test_paddle.db")
    yield pb
    pb.close()


@pytest.fixture
def enabled_store(tmp_path: Path) -> Generator[PaddleBilling, None, None]:
    """PaddleBilling with fake keys — simulates a configured deployment."""
    with (
        patch("warden.paddle_billing._PADDLE_API_KEY",        "pdl_test_fake"),
        patch("warden.paddle_billing._PADDLE_PRICE_PRO",      "pri_pro_fake"),
        patch("warden.paddle_billing._PADDLE_PRICE_MSP",      "pri_msp_fake"),
        patch("warden.paddle_billing._PRICE_TO_PLAN",
              {"pri_pro_fake": "pro", "pri_msp_fake": "msp"}),
        patch("warden.paddle_billing._PADDLE_WEBHOOK_SECRET", ""),  # skip sig check
    ):
        pb = PaddleBilling(db_path=tmp_path / "test_paddle_enabled.db")
        pb._enabled = True
        yield pb
        pb.close()


# ── get_plan ──────────────────────────────────────────────────────────────────

class TestGetPlan:
    def test_unknown_tenant_is_free(self, store: PaddleBilling) -> None:
        assert store.get_plan("nobody") == "free"

    def test_active_pro(self, store: PaddleBilling) -> None:
        store._upsert("t1", "ctm_1", "sub_1", "pro", "active", None)
        assert store.get_plan("t1") == "pro"

    def test_active_msp(self, store: PaddleBilling) -> None:
        store._upsert("t1", "ctm_1", "sub_1", "msp", "active", None)
        assert store.get_plan("t1") == "msp"

    def test_trialing_returns_plan(self, store: PaddleBilling) -> None:
        store._upsert("t1", "ctm_1", "sub_1", "pro", "trialing", None)
        assert store.get_plan("t1") == "pro"

    def test_cancelled_falls_back_to_free(self, store: PaddleBilling) -> None:
        store._upsert("t1", "ctm_1", "sub_1", "pro", "cancelled", None)
        assert store.get_plan("t1") == "free"

    def test_past_due_falls_back_to_free(self, store: PaddleBilling) -> None:
        store._upsert("t1", "ctm_1", "sub_1", "msp", "past_due", None)
        assert store.get_plan("t1") == "free"


# ── get_quota ─────────────────────────────────────────────────────────────────

class TestGetQuota:
    def test_free_quota(self, store: PaddleBilling) -> None:
        assert store.get_quota("nobody") == PLAN_QUOTAS["free"]
        assert store.get_quota("nobody") == 1_000

    def test_pro_quota(self, store: PaddleBilling) -> None:
        store._upsert("t1", "ctm_1", "sub_1", "pro", "active", None)
        assert store.get_quota("t1") == PLAN_QUOTAS["pro"]
        assert store.get_quota("t1") == 50_000

    def test_msp_unlimited(self, store: PaddleBilling) -> None:
        store._upsert("t1", "ctm_1", "sub_1", "msp", "active", None)
        assert store.get_quota("t1") is None


# ── get_status ────────────────────────────────────────────────────────────────

class TestGetStatus:
    def test_unknown_tenant(self, store: PaddleBilling) -> None:
        s = store.get_status("new")
        assert s["plan"]        == "free"
        assert s["status"]      == "free"
        assert s["quota"]       == 1_000
        assert s["customer_id"] is None

    def test_known_tenant(self, store: PaddleBilling) -> None:
        store._upsert("t1", "ctm_x", "sub_x", "pro", "active", "2026-04-01T00:00:00+00:00")
        s = store.get_status("t1")
        assert s["plan"]        == "pro"
        assert s["customer_id"] == "ctm_x"
        assert s["period_end"]  == "2026-04-01T00:00:00+00:00"
        assert s["quota"]       == 50_000


# ── create_checkout_session ───────────────────────────────────────────────────

class TestCreateCheckoutSession:
    def test_disabled_raises(self, store: PaddleBilling) -> None:
        with pytest.raises(RuntimeError, match="not configured"):
            store.create_checkout_session("t1", "pro", "https://ok", "https://cancel")

    def test_invalid_plan_raises(self, enabled_store: PaddleBilling) -> None:
        with pytest.raises(ValueError, match="Invalid plan"):
            enabled_store.create_checkout_session("t1", "enterprise", "https://ok", "https://c")

    def test_returns_checkout_url(self, enabled_store: PaddleBilling) -> None:
        fake_resp = {"data": {"checkout": {"url": "https://buy.paddle.com/checkout/cs_test_123"}}}
        with patch("warden.paddle_billing._paddle_request", return_value=fake_resp):
            url = enabled_store.create_checkout_session("t1", "pro", "https://ok", "https://c")
        assert url == "https://buy.paddle.com/checkout/cs_test_123"

    def test_customer_email_forwarded(self, enabled_store: PaddleBilling) -> None:
        fake_resp = {"data": {"checkout": {"url": "https://buy.paddle.com/checkout/cs_456"}}}
        with patch("warden.paddle_billing._paddle_request", return_value=fake_resp) as mock_req:
            enabled_store.create_checkout_session(
                "t1", "pro", "https://ok", "https://c",
                customer_email="user@example.com",
            )
        _, _, body = mock_req.call_args[0]
        assert body.get("customer", {}).get("email") == "user@example.com"

    def test_custom_data_contains_tenant_id(self, enabled_store: PaddleBilling) -> None:
        fake_resp = {"data": {"checkout": {"url": "https://buy.paddle.com/checkout/cs_789"}}}
        with patch("warden.paddle_billing._paddle_request", return_value=fake_resp) as mock_req:
            enabled_store.create_checkout_session("acme", "pro", "https://ok", "https://c")
        _, _, body = mock_req.call_args[0]
        assert body["custom_data"]["tenant_id"] == "acme"

    def test_missing_checkout_url_raises(self, enabled_store: PaddleBilling) -> None:
        with patch("warden.paddle_billing._paddle_request", return_value={"data": {}}), \
             pytest.raises(RuntimeError, match="checkout URL"):
            enabled_store.create_checkout_session("t1", "pro", "https://ok", "https://c")


# ── get_portal_url ────────────────────────────────────────────────────────────

class TestGetPortalUrl:
    def test_no_customer_returns_generic_portal(self, enabled_store: PaddleBilling) -> None:
        url = enabled_store.get_portal_url("unknown_tenant")
        assert "customer.paddle.com" in url

    def test_with_customer_calls_auth_token(self, enabled_store: PaddleBilling) -> None:
        enabled_store._upsert("t1", "ctm_abc", "sub_abc", "pro", "active", None)
        fake_resp = {"data": {"customer_auth_token": "tok_xyz"}}
        with patch("warden.paddle_billing._paddle_request", return_value=fake_resp):
            url = enabled_store.get_portal_url("t1")
        assert "customerAuthToken=tok_xyz" in url

    def test_api_failure_falls_back_to_generic(self, enabled_store: PaddleBilling) -> None:
        enabled_store._upsert("t1", "ctm_abc", "sub_abc", "pro", "active", None)
        with patch("warden.paddle_billing._paddle_request", side_effect=RuntimeError("500")):
            url = enabled_store.get_portal_url("t1")
        assert "customer.paddle.com" in url


# ── handle_webhook ────────────────────────────────────────────────────────────

class TestWebhookHandler:
    """No signature secret set in enabled_store fixture — skips HMAC check."""

    def _handle(self, pb: PaddleBilling, etype: str, data: dict) -> str:
        event   = {"event_type": etype, "data": data}
        payload = json.dumps(event).encode()
        return pb.handle_webhook(payload, "")

    def test_transaction_completed_activates_plan(self, enabled_store: PaddleBilling) -> None:
        self._handle(enabled_store, "transaction.completed", {
            "custom_data":     {"tenant_id": "t1"},
            "customer_id":     "ctm_new",
            "subscription_id": "sub_new",
            "items":           [{"price": {"id": "pri_pro_fake"}}],
        })
        assert enabled_store.get_plan("t1") == "pro"

    def test_subscription_canceled_reverts_to_free(self, enabled_store: PaddleBilling) -> None:
        enabled_store._upsert("t1", "ctm_1", "sub_1", "pro", "active", None)
        self._handle(enabled_store, "subscription.canceled", {"id": "sub_1"})
        assert enabled_store.get_plan("t1") == "free"

    def test_subscription_past_due_sets_status(self, enabled_store: PaddleBilling) -> None:
        enabled_store._upsert("t1", "ctm_1", "sub_1", "pro", "active", None)
        self._handle(enabled_store, "subscription.past_due", {"id": "sub_1"})
        assert enabled_store.get_plan("t1") == "free"

    def test_subscription_updated_changes_plan(self, enabled_store: PaddleBilling) -> None:
        enabled_store._upsert("t1", "ctm_1", "sub_1", "pro", "active", None)
        self._handle(enabled_store, "subscription.updated", {
            "id":          "sub_1",
            "customer_id": "ctm_1",
            "status":      "active",
            "custom_data": {"tenant_id": "t1"},
            "items":       [{"price": {"id": "pri_msp_fake"}}],
            "current_billing_period": {"ends_at": "2026-06-01T00:00:00Z"},
        })
        assert enabled_store.get_plan("t1") == "msp"

    def test_unknown_event_passes_through(self, enabled_store: PaddleBilling) -> None:
        result = self._handle(enabled_store, "ping.pong", {})
        assert result == "ping.pong"

    def test_missing_tenant_id_logs_warning(self, enabled_store: PaddleBilling) -> None:
        # Should not raise — just log warning and skip
        self._handle(enabled_store, "transaction.completed", {
            "customer_id": "ctm_x",
            "items":       [{"price": {"id": "pri_pro_fake"}}],
        })

    def test_invalid_signature_raises(self, enabled_store: PaddleBilling) -> None:
        with patch("warden.paddle_billing._PADDLE_WEBHOOK_SECRET", "real_secret"):
            enabled_store._enabled = True
            with pytest.raises(ValueError, match="signature"):
                enabled_store.handle_webhook(b'{"event_type":"ping","data":{}}', "ts=1;h1=badhash")


# ── HTTP endpoints (via TestClient) ──────────────────────────────────────────

class TestBillingEndpoints:
    @pytest.fixture(autouse=True)
    def _client(self):
        from fastapi.testclient import TestClient
        from warden.main import app
        self.client = TestClient(app, raise_server_exceptions=True)

    def test_status_unknown_tenant_returns_free(self) -> None:
        resp = self.client.get("/billing/status?tenant_id=nobody")
        assert resp.status_code == 200
        data = resp.json()
        assert data["plan"]  == "free"
        assert data["quota"] == 1_000

    def test_checkout_paddle_disabled_returns_503(self) -> None:
        resp = self.client.post("/billing/checkout", json={
            "tenant_id":   "t1",
            "plan":        "pro",
            "success_url": "https://example.com/ok",
            "cancel_url":  "https://example.com/cancel",
        })
        assert resp.status_code == 503

    def test_portal_returns_url(self) -> None:
        resp = self.client.get("/billing/portal?tenant_id=nobody")
        assert resp.status_code == 200
        assert "portal_url" in resp.json()

    def test_webhook_accepts_empty_payload(self) -> None:
        resp = self.client.post(
            "/billing/webhook",
            content=b'{"event_type":"ping","data":{}}',
            headers={"Paddle-Signature": ""},
        )
        assert resp.status_code == 200

    def test_checkout_invalid_plan_disabled_returns_503(self) -> None:
        """Paddle disabled in test env — 503 fires before plan validation."""
        resp = self.client.post("/billing/checkout", json={
            "tenant_id":   "t1",
            "plan":        "enterprise",
            "success_url": "https://example.com/ok",
            "cancel_url":  "https://example.com/cancel",
        })
        assert resp.status_code == 503
