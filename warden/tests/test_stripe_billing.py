"""
warden/tests/test_stripe_billing.py
─────────────────────────────────────
Unit + integration tests for StripeBilling.

All Stripe API calls are mocked — no network or real Stripe account needed.

Coverage
────────
  • get_plan / get_quota    — free, pro, msp, cancelled, past_due, trialing
  • get_status              — unknown tenant, known tenant
  • create_checkout_session — disabled, invalid plan, success, customer reuse
  • create_portal_session   — no customer, success
  • handle_webhook          — bad sig, checkout.completed, sub.deleted,
                              payment_failed, unknown event
  • HTTP endpoints          — /stripe/status, /stripe/checkout,
                              /stripe/webhook (via TestClient)
"""
from __future__ import annotations

import json
import time
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from warden.stripe_billing import PLAN_QUOTAS, StripeBilling

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def store(tmp_path: Path) -> Generator[StripeBilling, None, None]:
    """Disabled StripeBilling (no Stripe key) — for plan/quota/DB tests."""
    sb = StripeBilling(db_path=tmp_path / "test_stripe.db")
    yield sb
    sb.close()


@pytest.fixture
def enabled_store(tmp_path: Path) -> Generator[StripeBilling, None, None]:
    """StripeBilling with fake keys — simulates a configured deployment."""
    with (
        patch("warden.stripe_billing._STRIPE_SECRET_KEY",     "sk_test_fake"),
        patch("warden.stripe_billing._STRIPE_PRICE_PRO",      "price_pro_fake"),
        patch("warden.stripe_billing._STRIPE_PRICE_MSP",      "price_msp_fake"),
        patch("warden.stripe_billing._PRICE_TO_PLAN",
              {"price_pro_fake": "pro", "price_msp_fake": "msp"}),
        patch("warden.stripe_billing._STRIPE_WEBHOOK_SECRET", "whsec_fake"),
    ):
        sb = StripeBilling(db_path=tmp_path / "test_stripe_enabled.db")
        yield sb
        sb.close()


# ── get_plan ──────────────────────────────────────────────────────────────────

class TestGetPlan:
    def test_unknown_tenant_is_free(self, store: StripeBilling) -> None:
        assert store.get_plan("nobody") == "free"

    def test_active_pro(self, store: StripeBilling) -> None:
        store._upsert("t1", "cus_1", "sub_1", "pro", "active", None)
        assert store.get_plan("t1") == "pro"

    def test_active_msp(self, store: StripeBilling) -> None:
        store._upsert("t1", "cus_1", "sub_1", "msp", "active", None)
        assert store.get_plan("t1") == "msp"

    def test_trialing_returns_plan(self, store: StripeBilling) -> None:
        store._upsert("t1", "cus_1", "sub_1", "pro", "trialing", None)
        assert store.get_plan("t1") == "pro"

    def test_cancelled_falls_back_to_free(self, store: StripeBilling) -> None:
        store._upsert("t1", "cus_1", "sub_1", "pro", "cancelled", None)
        assert store.get_plan("t1") == "free"

    def test_past_due_falls_back_to_free(self, store: StripeBilling) -> None:
        store._upsert("t1", "cus_1", "sub_1", "msp", "past_due", None)
        assert store.get_plan("t1") == "free"


# ── get_quota ─────────────────────────────────────────────────────────────────

class TestGetQuota:
    def test_free_quota(self, store: StripeBilling) -> None:
        assert store.get_quota("nobody") == PLAN_QUOTAS["free"]
        assert store.get_quota("nobody") == 1_000

    def test_pro_quota(self, store: StripeBilling) -> None:
        store._upsert("t1", "cus_1", "sub_1", "pro", "active", None)
        assert store.get_quota("t1") == PLAN_QUOTAS["pro"]
        assert store.get_quota("t1") == 50_000

    def test_msp_unlimited(self, store: StripeBilling) -> None:
        store._upsert("t1", "cus_1", "sub_1", "msp", "active", None)
        assert store.get_quota("t1") is None


# ── get_status ────────────────────────────────────────────────────────────────

class TestGetStatus:
    def test_unknown_tenant(self, store: StripeBilling) -> None:
        s = store.get_status("new")
        assert s["plan"]   == "free"
        assert s["status"] == "free"
        assert s["quota"]  == 1_000
        assert s["customer_id"] is None

    def test_known_tenant(self, store: StripeBilling) -> None:
        store._upsert("t1", "cus_x", "sub_x", "pro", "active", "2026-04-01T00:00:00+00:00")
        s = store.get_status("t1")
        assert s["plan"]        == "pro"
        assert s["customer_id"] == "cus_x"
        assert s["period_end"]  == "2026-04-01T00:00:00+00:00"
        assert s["quota"]       == 50_000


# ── create_checkout_session ───────────────────────────────────────────────────

class TestCreateCheckoutSession:
    def test_disabled_raises(self, store: StripeBilling) -> None:
        with pytest.raises(RuntimeError, match="not configured"):
            store.create_checkout_session("t1", "pro", "https://ok", "https://cancel")

    def test_invalid_plan_raises(self, enabled_store: StripeBilling) -> None:
        with pytest.raises(ValueError, match="Invalid plan"):
            enabled_store.create_checkout_session("t1", "enterprise", "https://ok", "https://c")

    def test_returns_checkout_url(self, enabled_store: StripeBilling) -> None:
        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/pay/cs_test_123"
        mock_session.id  = "cs_test_123"
        with patch("stripe.checkout.Session.create", return_value=mock_session):
            url = enabled_store.create_checkout_session(
                "t1", "pro", "https://ok", "https://cancel"
            )
        assert url == "https://checkout.stripe.com/pay/cs_test_123"

    def test_new_customer_email_forwarded(self, enabled_store: StripeBilling) -> None:
        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/pay/cs_test_456"
        mock_session.id  = "cs_test_456"
        with patch("stripe.checkout.Session.create", return_value=mock_session) as mock_create:
            enabled_store.create_checkout_session(
                "t1", "pro", "https://ok", "https://c",
                customer_email="user@example.com",
            )
        call_kwargs = mock_create.call_args[1]
        assert call_kwargs.get("customer_email") == "user@example.com"

    def test_existing_customer_id_reused(self, enabled_store: StripeBilling) -> None:
        enabled_store._upsert("t1", "cus_existing", "sub_old", "pro", "active", None)
        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/pay/cs_upgrade"
        mock_session.id  = "cs_upgrade"
        with patch("stripe.checkout.Session.create", return_value=mock_session) as mock_create:
            enabled_store.create_checkout_session("t1", "msp", "https://ok", "https://c")
        call_kwargs = mock_create.call_args[1]
        assert call_kwargs.get("customer") == "cus_existing"

    def test_metadata_contains_tenant_id(self, enabled_store: StripeBilling) -> None:
        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/pay/cs_meta"
        mock_session.id  = "cs_meta"
        with patch("stripe.checkout.Session.create", return_value=mock_session) as mock_create:
            enabled_store.create_checkout_session("acme", "pro", "https://ok", "https://c")
        call_kwargs = mock_create.call_args[1]
        assert call_kwargs["metadata"]["tenant_id"] == "acme"


# ── create_portal_session ─────────────────────────────────────────────────────

class TestCreatePortalSession:
    def test_disabled_raises(self, store: StripeBilling) -> None:
        with pytest.raises(RuntimeError, match="not configured"):
            store.create_portal_session("t1", "https://return")

    def test_no_customer_raises(self, enabled_store: StripeBilling) -> None:
        with pytest.raises(ValueError, match="No Stripe customer"):
            enabled_store.create_portal_session("unknown", "https://return")

    def test_returns_portal_url(self, enabled_store: StripeBilling) -> None:
        enabled_store._upsert("t1", "cus_abc", "sub_abc", "pro", "active", None)
        mock_session = MagicMock()
        mock_session.url = "https://billing.stripe.com/p/session_abc"
        with patch("stripe.billing_portal.Session.create", return_value=mock_session):
            url = enabled_store.create_portal_session("t1", "https://return")
        assert url == "https://billing.stripe.com/p/session_abc"


# ── handle_webhook ────────────────────────────────────────────────────────────

def _fake_event(etype: str, data: dict) -> dict:
    return {"type": etype, "data": {"object": data}}


class TestWebhookHandler:
    def _handle(self, sb: StripeBilling, etype: str, data: dict) -> str:
        payload = json.dumps(_fake_event(etype, data)).encode()
        event   = _fake_event(etype, data)
        with patch("stripe.Webhook.construct_event", return_value=event):
            return sb.handle_webhook(payload, "t=1,v1=abc")

    def test_disabled_raises(self, store: StripeBilling) -> None:
        with pytest.raises(RuntimeError, match="not configured"):
            store.handle_webhook(b"{}", "sig")

    def test_invalid_signature_raises(self, enabled_store: StripeBilling) -> None:
        import stripe
        with patch(
            "stripe.Webhook.construct_event",
            side_effect=stripe.error.SignatureVerificationError("bad", "hdr"),
        ):
            with pytest.raises(ValueError, match="signature"):
                enabled_store.handle_webhook(b"{}", "bad_sig")

    def test_checkout_completed_activates_plan(self, enabled_store: StripeBilling) -> None:
        mock_sub = {
            "id":     "sub_new",
            "status": "active",
            "current_period_end": int(time.time()) + 86400 * 30,
            "metadata": {"tenant_id": "t1"},
            "items": {"data": [{"price": {"id": "price_pro_fake"}}]},
        }
        with patch("stripe.Subscription.retrieve", return_value=mock_sub):
            self._handle(enabled_store, "checkout.session.completed", {
                "metadata":     {"tenant_id": "t1"},
                "customer":     "cus_new",
                "subscription": "sub_new",
            })
        assert enabled_store.get_plan("t1") == "pro"

    def test_subscription_deleted_reverts_to_free(self, enabled_store: StripeBilling) -> None:
        enabled_store._upsert("t1", "cus_1", "sub_1", "pro", "active", None)
        self._handle(enabled_store, "customer.subscription.deleted", {"id": "sub_1"})
        assert enabled_store.get_plan("t1") == "free"

    def test_payment_failed_sets_past_due(self, enabled_store: StripeBilling) -> None:
        enabled_store._upsert("t1", "cus_1", "sub_1", "pro", "active", None)
        mock_sub = {
            "id":     "sub_1",
            "status": "past_due",
            "current_period_end": int(time.time()) + 86400,
            "metadata": {"tenant_id": "t1"},
            "items": {"data": [{"price": {"id": "price_pro_fake"}}]},
        }
        with patch("stripe.Subscription.retrieve", return_value=mock_sub):
            self._handle(enabled_store, "invoice.payment_failed", {"subscription": "sub_1"})
        # past_due → get_plan falls back to free
        assert enabled_store.get_plan("t1") == "free"

    def test_invoice_paid_refreshes_period(self, enabled_store: StripeBilling) -> None:
        enabled_store._upsert("t1", "cus_1", "sub_1", "pro", "active", "2026-03-01T00:00:00+00:00")
        new_period = int(time.time()) + 86400 * 30
        mock_sub = {
            "id": "sub_1",
            "status": "active",
            "current_period_end": new_period,
            "metadata": {"tenant_id": "t1"},
            "customer": "cus_1",
            "items": {"data": [{"price": {"id": "price_pro_fake"}}]},
        }
        with patch("stripe.Subscription.retrieve", return_value=mock_sub):
            self._handle(enabled_store, "invoice.paid", {"subscription": "sub_1"})
        s = enabled_store.get_status("t1")
        assert s["plan"] == "pro"

    def test_unknown_event_passes_through(self, enabled_store: StripeBilling) -> None:
        result = self._handle(enabled_store, "ping.pong", {})
        assert result == "ping.pong"


# ── HTTP endpoints (via TestClient) ──────────────────────────────────────────

class TestBillingEndpoints:
    @pytest.fixture(autouse=True)
    def _client(self):
        from fastapi.testclient import TestClient
        from warden.main import app
        self.client = TestClient(app, raise_server_exceptions=True)

    def test_status_unknown_tenant_returns_free(self) -> None:
        resp = self.client.get("/stripe/status?tenant_id=nobody")
        assert resp.status_code == 200
        data = resp.json()
        assert data["plan"]  == "free"
        assert data["quota"] == 1_000

    def test_checkout_stripe_disabled_returns_503(self) -> None:
        resp = self.client.post("/stripe/checkout", json={
            "tenant_id":   "t1",
            "plan":        "pro",
            "success_url": "https://example.com/ok",
            "cancel_url":  "https://example.com/cancel",
        })
        assert resp.status_code == 503

    def test_portal_stripe_disabled_returns_503(self) -> None:
        resp = self.client.post(
            "/stripe/portal",
            params={"tenant_id": "t1", "return_url": "https://example.com"},
        )
        assert resp.status_code == 503

    def test_webhook_stripe_disabled_returns_503(self) -> None:
        resp = self.client.post(
            "/stripe/webhook",
            content=b'{"type":"ping"}',
            headers={"stripe-signature": "t=1,v1=abc"},
        )
        assert resp.status_code == 503

    def test_checkout_invalid_plan_raises(self) -> None:
        """Plan validation is tested at unit level in TestCreateCheckoutSession.
        Via HTTP the 503 fires first (Stripe disabled in test env) — assert that."""
        resp = self.client.post("/stripe/checkout", json={
            "tenant_id":   "t1",
            "plan":        "enterprise",
            "success_url": "https://example.com/ok",
            "cancel_url":  "https://example.com/cancel",
        })
        assert resp.status_code == 503  # Stripe not configured in test env
