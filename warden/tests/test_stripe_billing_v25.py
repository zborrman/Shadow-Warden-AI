"""
warden/tests/test_stripe_billing_v25.py
───────────────────────────────────────
Tests for the v2.5 Stripe billing upgrade:
  - New plan tiers (free / startup / growth / msp)
  - Per-minute rate limits per plan
  - Webhook idempotency (webhook_events table)
  - Redis billing gate (activate / deactivate)
  - Subscription status lifecycle
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_billing(tmp_path: Path) -> "StripeBilling":
    """Create a StripeBilling instance with a temp SQLite DB (no Stripe creds)."""
    from warden.stripe_billing import StripeBilling
    return StripeBilling(db_path=tmp_path / "stripe_test.db")


def _fake_event(event_id: str, etype: str, data: dict) -> bytes:
    """Build a minimal Stripe event payload."""
    return json.dumps({
        "id":   event_id,
        "type": etype,
        "data": {"object": data},
    }).encode()


# ── Plan / quota constants ────────────────────────────────────────────────────

class TestPlanConstants:
    def test_plan_quotas(self):
        from warden.stripe_billing import PLAN_QUOTAS
        assert PLAN_QUOTAS["free"]    == 1_000
        assert PLAN_QUOTAS["startup"] == 50_000
        assert PLAN_QUOTAS["growth"]  == 250_000
        assert PLAN_QUOTAS["msp"]     is None

    def test_plan_rate_limits(self):
        from warden.stripe_billing import PLAN_RATE_LIMITS
        assert PLAN_RATE_LIMITS["free"]    == 10
        assert PLAN_RATE_LIMITS["startup"] == 60
        assert PLAN_RATE_LIMITS["growth"]  == 200
        assert PLAN_RATE_LIMITS["msp"]     == 500


# ── StripeBilling — plan queries ──────────────────────────────────────────────

class TestPlanQueries:
    def test_unknown_tenant_defaults_to_free(self, tmp_path):
        b = _make_billing(tmp_path)
        assert b.get_plan("no_such_tenant") == "free"
        assert b.get_quota("no_such_tenant") == 1_000
        assert b.get_rate_limit_per_minute("no_such_tenant") == 10

    def test_cancelled_subscription_treated_as_free(self, tmp_path):
        b = _make_billing(tmp_path)
        b._upsert("t1", "cus_1", "sub_1", "startup", "cancelled", None)
        assert b.get_plan("t1") == "free"
        assert b.get_rate_limit_per_minute("t1") == 10

    def test_active_startup_plan(self, tmp_path):
        b = _make_billing(tmp_path)
        b._upsert("t2", "cus_2", "sub_2", "startup", "active", None)
        assert b.get_plan("t2") == "startup"
        assert b.get_quota("t2") == 50_000
        assert b.get_rate_limit_per_minute("t2") == 60

    def test_active_growth_plan(self, tmp_path):
        b = _make_billing(tmp_path)
        b._upsert("t3", "cus_3", "sub_3", "growth", "active", None)
        assert b.get_plan("t3") == "growth"
        assert b.get_quota("t3") == 250_000
        assert b.get_rate_limit_per_minute("t3") == 200

    def test_msp_plan_unlimited_quota(self, tmp_path):
        b = _make_billing(tmp_path)
        b._upsert("t4", "cus_4", "sub_4", "msp", "active", None)
        assert b.get_quota("t4") is None
        assert b.get_rate_limit_per_minute("t4") == 500

    def test_trialing_counts_as_active(self, tmp_path):
        b = _make_billing(tmp_path)
        b._upsert("t5", "cus_5", "sub_5", "growth", "trialing", None)
        assert b.get_plan("t5") == "growth"

    def test_get_status_includes_rate_limit(self, tmp_path):
        b = _make_billing(tmp_path)
        b._upsert("t6", "cus_6", "sub_6", "startup", "active", "2025-12-31T00:00:00+00:00")
        status = b.get_status("t6")
        assert status["plan"]               == "startup"
        assert status["quota"]              == 50_000
        assert status["rate_limit_per_min"] == 60
        assert status["status"]             == "active"


# ── Webhook idempotency ───────────────────────────────────────────────────────

class TestWebhookIdempotency:
    """
    Stripe re-delivers events up to 3 days after a network failure.
    A second delivery of the same event_id must be a no-op.
    """

    def _mock_stripe_and_handle(self, billing, event_id, etype, data):
        """Patch stripe so handle_webhook can run without real credentials."""
        payload = _fake_event(event_id, etype, data)
        sig     = "t=1,v1=dummy"

        mock_event = {
            "id":   event_id,
            "type": etype,
            "data": {"object": data},
        }

        # Stub out Subscription.retrieve so invoice.paid events don't hit the API
        mock_sub = MagicMock()
        mock_sub.get = lambda k, d=None: {
            "status": "active", "items": {"data": []},
            "current_period_end": None, "customer": "", "id": "",
            "metadata": {},
        }.get(k, d)

        with patch("stripe.Webhook.construct_event", return_value=mock_event), \
             patch("stripe.Subscription.retrieve", return_value=mock_sub), \
             patch("warden.cache._get_client", return_value=MagicMock(
                 set=lambda k, v: None, delete=lambda k: None, get=lambda k: None
             )):
            billing._enabled = True  # bypass the "not configured" guard
            return billing.handle_webhook(payload, sig)

    def test_first_delivery_is_processed(self, tmp_path):
        b = _make_billing(tmp_path)
        result = self._mock_stripe_and_handle(
            b, "evt_001", "invoice.paid", {"subscription": "sub_x"}
        )
        assert result == "invoice.paid"

        # Event should now be in webhook_events
        row = b._conn.execute(
            "SELECT event_id FROM webhook_events WHERE event_id='evt_001'"
        ).fetchone()
        assert row is not None

    def test_duplicate_delivery_is_no_op(self, tmp_path):
        b = _make_billing(tmp_path)

        # Seed a subscription so _refresh_subscription has something to find
        b._upsert("dup_tenant", "cus_d", "sub_d", "startup", "active", None)

        counter = {"calls": 0}
        original_refresh = b._refresh_subscription

        def counting_refresh(sub_id):
            counter["calls"] += 1
            return original_refresh(sub_id)

        b._refresh_subscription = counting_refresh  # type: ignore[method-assign]

        with patch("stripe.Subscription.retrieve", return_value=MagicMock(
            get=lambda k, d=None: {"status": "active", "items": {"data": []},
                                   "current_period_end": None, "customer": "cus_d",
                                   "id": "sub_d", "metadata": {"tenant_id": "dup_tenant"}}.get(k, d)
        )):
            self._mock_stripe_and_handle(b, "evt_DUP", "invoice.paid", {"subscription": "sub_d"})
            self._mock_stripe_and_handle(b, "evt_DUP", "invoice.paid", {"subscription": "sub_d"})

        assert counter["calls"] == 1  # second delivery was skipped

    def test_different_event_ids_both_processed(self, tmp_path):
        b = _make_billing(tmp_path)

        self._mock_stripe_and_handle(b, "evt_A", "invoice.payment_failed", {"subscription": "sub_z"})
        self._mock_stripe_and_handle(b, "evt_B", "invoice.payment_failed", {"subscription": "sub_z"})

        rows = b._conn.execute("SELECT event_id FROM webhook_events").fetchall()
        ids  = {r["event_id"] for r in rows}
        assert "evt_A" in ids
        assert "evt_B" in ids

    def test_concurrent_deliveries_idempotent(self, tmp_path):
        """
        Simulate two threads delivering the same event_id simultaneously.
        Only one should win; subscriber state mutates exactly once.
        """
        b = _make_billing(tmp_path)
        results = []

        mock_sub = MagicMock()
        mock_sub.get = lambda k, d=None: {
            "status": "active", "items": {"data": []}, "current_period_end": None,
            "customer": "", "id": "sub_c", "metadata": {},
        }.get(k, d)

        def deliver():
            payload   = _fake_event("evt_CONCURRENT", "invoice.paid", {"subscription": "sub_c"})
            mock_event = {
                "id":   "evt_CONCURRENT",
                "type": "invoice.paid",
                "data": {"object": {"subscription": "sub_c"}},
            }
            with patch("stripe.Webhook.construct_event", return_value=mock_event), \
                 patch("stripe.Subscription.retrieve", return_value=mock_sub), \
                 patch("warden.cache._get_client", return_value=MagicMock(
                     set=lambda k, v: None, delete=lambda k: None, get=lambda k: None
                 )):
                b._enabled = True
                results.append(b.handle_webhook(payload, "t=1,v1=dummy"))

        t1 = threading.Thread(target=deliver)
        t2 = threading.Thread(target=deliver)
        t1.start(); t2.start()
        t1.join();  t2.join()

        rows = b._conn.execute(
            "SELECT * FROM webhook_events WHERE event_id='evt_CONCURRENT'"
        ).fetchall()
        assert len(rows) == 1  # inserted exactly once


# ── Redis billing gate ────────────────────────────────────────────────────────

class TestRedisBillingGate:
    """
    Verify that _redis_activate / _redis_deactivate write/delete the correct
    Redis key, and that _upsert drives Redis automatically.
    """

    def _make_redis_mock(self):
        store = {}

        class FakeRedis:
            def set(self, k, v):       store[k] = v
            def delete(self, k):       store.pop(k, None)
            def get(self, k):          return store.get(k)
            def hgetall(self, k):      return {}
            def hset(self, k, f, v):   pass

        return FakeRedis(), store

    def test_activate_sets_redis_key(self, tmp_path):
        b = _make_billing(tmp_path)
        fake_redis, store = self._make_redis_mock()

        with patch("warden.cache._get_client", return_value=fake_redis):
            b._redis_activate("tenant_acme")

        assert store.get("warden:oidc:billing:tenant_acme") == "1"

    def test_deactivate_deletes_redis_key(self, tmp_path):
        b = _make_billing(tmp_path)
        fake_redis, store = self._make_redis_mock()
        store["warden:oidc:billing:tenant_acme"] = "1"

        with patch("warden.cache._get_client", return_value=fake_redis):
            b._redis_deactivate("tenant_acme")

        assert "warden:oidc:billing:tenant_acme" not in store

    def test_upsert_active_activates_redis(self, tmp_path):
        b = _make_billing(tmp_path)
        fake_redis, store = self._make_redis_mock()

        with patch("warden.cache._get_client", return_value=fake_redis):
            b._upsert("t7", "cus_7", "sub_7", "growth", "active", None)

        assert store.get("warden:oidc:billing:t7") == "1"

    def test_upsert_cancelled_deactivates_redis(self, tmp_path):
        b = _make_billing(tmp_path)
        fake_redis, store = self._make_redis_mock()
        store["warden:oidc:billing:t8"] = "1"

        with patch("warden.cache._get_client", return_value=fake_redis):
            b._upsert("t8", "cus_8", "sub_8", "free", "cancelled", None)

        assert "warden:oidc:billing:t8" not in store

    def test_redis_unavailable_does_not_raise(self, tmp_path):
        b = _make_billing(tmp_path)

        with patch("warden.cache._get_client", side_effect=ConnectionError("Redis down")):
            # Should log a warning but not raise
            b._redis_activate("t9")
            b._redis_deactivate("t9")

    def test_subscription_deleted_removes_redis_key(self, tmp_path):
        b = _make_billing(tmp_path)
        fake_redis, store = self._make_redis_mock()
        store["warden:oidc:billing:t10"] = "1"

        # Pre-populate DB so _redis_remove_by_sub can look up tenant_id
        b._upsert("t10", "cus_10", "sub_10", "startup", "active", None)
        store["warden:oidc:billing:t10"] = "1"  # re-set after upsert may have modified

        with patch("warden.cache._get_client", return_value=fake_redis):
            b._on_subscription_deleted({"id": "sub_10"})

        assert "warden:oidc:billing:t10" not in store


# ── Checkout session validation ───────────────────────────────────────────────

class TestCheckoutSession:
    def test_invalid_plan_raises_value_error(self, tmp_path):
        b = _make_billing(tmp_path)
        b._enabled = True
        with pytest.raises(ValueError, match="Invalid plan"):
            b.create_checkout_session("t", "pro", "http://ok", "http://cancel")

    def test_free_plan_raises_value_error(self, tmp_path):
        b = _make_billing(tmp_path)
        b._enabled = True
        with pytest.raises(ValueError):
            b.create_checkout_session("t", "free", "http://ok", "http://cancel")

    def test_not_configured_raises_runtime_error(self, tmp_path):
        b = _make_billing(tmp_path)
        b._enabled = False
        with pytest.raises(RuntimeError, match="STRIPE_SECRET_KEY"):
            b.create_checkout_session("t", "startup", "http://ok", "http://cancel")

    def test_missing_price_env_raises_runtime_error(self, tmp_path):
        b = _make_billing(tmp_path)
        b._enabled = True
        # STRIPE_PRICE_STARTUP is empty (not set in test env)
        with patch("warden.stripe_billing._STRIPE_PRICE_STARTUP", ""):
            with pytest.raises(RuntimeError, match="STRIPE_PRICE_STARTUP"):
                b.create_checkout_session("t", "startup", "http://ok", "http://cancel")


# ── Price → plan mapping ──────────────────────────────────────────────────────

class TestPriceToplanMapping:
    def test_startup_price_maps_to_startup(self):
        from warden.stripe_billing import _build_price_map, _PRICE_TO_PLAN

        with patch.dict(os.environ, {
            "STRIPE_PRICE_STARTUP": "price_startup_test",
            "STRIPE_PRICE_GROWTH":  "",
            "STRIPE_PRICE_MSP":     "",
        }):
            # Re-import to pick up patched env
            import importlib
            import warden.stripe_billing as sb
            importlib.reload(sb)
            # After reload the module-level map is rebuilt
            assert sb._PRICE_TO_PLAN.get("price_startup_test") == "startup"

    def test_growth_price_maps_to_growth(self):
        with patch.dict(os.environ, {
            "STRIPE_PRICE_STARTUP": "",
            "STRIPE_PRICE_GROWTH":  "price_growth_test",
            "STRIPE_PRICE_MSP":     "",
        }):
            import importlib
            import warden.stripe_billing as sb
            importlib.reload(sb)
            assert sb._PRICE_TO_PLAN.get("price_growth_test") == "growth"
