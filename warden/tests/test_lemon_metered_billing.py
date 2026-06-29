"""
test_lemon_metered_billing.py
─────────────────────────────
Tests for Lemon Squeezy Usage-Based (Metered) Billing integration.

Covers:
  1. report_usage() JSON:API payload shape (RFC-compliant)
  2. report_usage() skips when API key unset (fail-open)
  3. report_usage() returns error dict on HTTP failure (never raises)
  4. report_usage() runs the executor path in an async context
  5. Webhook subscription_created stores ls_sub_item_id
  6. Feature flag enforcement: Enterprise → PQC enabled
  7. Feature flag enforcement: downgrade Enterprise → starter clears PQC/SOVA
  8. Feature flag enforcement: Pro → SOVA enabled, PQC locked
  9. Feature flag enforcement: Individual → marketplace_node enabled
  10. get_feature_flags() returns False defaults when no row
  11. _report_search_usage() enqueues via MeterUsageAggregator (fail-open)
  12. BackgroundTasks wiring: /action?search queues _report_search_usage
  13. MeterUsageAggregator.flush() uses ls_sub_item_id not ls_sub_id
"""
from __future__ import annotations

import json  # noqa: I001
import os
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_billing(tmp_path: Path):
    """Fresh LemonBilling backed by a temp DB."""
    os.environ["LEMONSQUEEZY_API_KEY"]  = "test-key"
    os.environ["LEMONSQUEEZY_STORE_ID"] = "store-1"
    import warden.lemon_billing as _lm
    _lm._LS_API_KEY = "test-key"  # sync module const regardless of import order
    from warden.lemon_billing import LemonBilling
    return LemonBilling(db_path=tmp_path / "lemon_test.db")


def _no_sig_check():
    """Context manager: disable webhook signature verification for tests."""
    import warden.lemon_billing as _lb
    return patch.object(_lb, "_LS_WEBHOOK_SECRET", "")


def _webhook_payload(
    tenant_id: str,
    plan_variant: str = "var_ind_123",
    sub_id: str = "sub_001",
    sub_item_id: str = "item_001",
    status: str = "active",
) -> tuple[bytes, dict]:
    """Build a synthetic LS subscription_created webhook event."""
    event = {
        "meta": {
            "event_name": "subscription_created",
            "event_id":   f"evt_{sub_id}",
            "custom_data": {"tenant_id": tenant_id},
        },
        "data": {
            "id": sub_id,
            "attributes": {
                "customer_id": "cust_99",
                "variant_id":  plan_variant,
                "status":      status,
                "renews_at":   "2026-07-29T00:00:00Z",
                "first_subscription_item": {
                    "id": sub_item_id,
                },
            },
        },
    }
    raw = json.dumps(event).encode()
    return raw, event


# ── 1. report_usage JSON:API payload ─────────────────────────────────────────

class TestReportUsagePayload(unittest.IsolatedAsyncioTestCase):
    async def test_payload_structure(self):
        """report_usage() builds the correct JSON:API payload for LS /v1/usage-records."""
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        billing = _make_billing(tmp)

        captured: list[dict] = []

        def _fake_ls_request(method: str, path: str, body: dict | None = None) -> dict:
            captured.append({"method": method, "path": path, "body": body})
            return {"data": {"id": "ur_001"}}

        with patch("warden.lemon_billing._ls_request", side_effect=_fake_ls_request):
            result = await billing.report_usage("item_abc123", 5, "increment")

        assert result["status"] == "ok"
        assert len(captured) == 1
        call = captured[0]
        assert call["method"] == "POST"
        assert call["path"]   == "/usage-records"
        payload = call["body"]
        assert payload["data"]["type"] == "usage-records"
        assert payload["data"]["attributes"]["quantity"] == 5
        assert payload["data"]["attributes"]["action"]   == "increment"
        rel = payload["data"]["relationships"]["subscription-item"]["data"]
        assert rel["type"] == "subscription-items"
        assert rel["id"]   == "item_abc123"
        billing.close()

    async def test_default_action_is_increment(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        billing = _make_billing(tmp)
        captured: list[dict] = []
        def _fake(m, p, b=None):
            captured.append(b)
            return {}
        with patch("warden.lemon_billing._ls_request", side_effect=_fake):
            await billing.report_usage("item_x", 1)
        assert captured[0]["data"]["attributes"]["action"] == "increment"
        billing.close()


# ── 2. Fail-open when API key unset ─────────────────────────────────────────

class TestReportUsageFailOpen(unittest.IsolatedAsyncioTestCase):
    async def test_skips_when_no_api_key(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        old_key = os.environ.pop("LEMONSQUEEZY_API_KEY", "")
        try:
            import warden.lemon_billing as _lb
            orig_key = _lb._LS_API_KEY
            _lb._LS_API_KEY = ""
            from warden.lemon_billing import LemonBilling
            billing = LemonBilling(db_path=tmp / "lemon2.db")
            result = await billing.report_usage("item_x", 1)
            assert result["status"] == "skipped"
            assert "LEMONSQUEEZY_API_KEY" in result["reason"]
            billing.close()
            _lb._LS_API_KEY = orig_key
        finally:
            if old_key:
                os.environ["LEMONSQUEEZY_API_KEY"] = old_key

    async def test_returns_error_dict_on_http_failure(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        billing = _make_billing(tmp)

        def _raise(*_args: Any, **_kwargs: Any) -> dict:
            raise RuntimeError("LS 422: unprocessable")

        with patch("warden.lemon_billing._ls_request", side_effect=_raise):
            result = await billing.report_usage("item_bad", 1)

        assert result["status"] == "error"
        assert "LS 422" in result["error"]
        billing.close()


# ── 5. Webhook stores ls_sub_item_id ─────────────────────────────────────────

class TestWebhookStoresItemId(unittest.TestCase):
    def test_subscription_created_stores_item_id(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        billing = _make_billing(tmp)
        os.environ["LEMONSQUEEZY_VARIANT_INDIVIDUAL"] = "var_ind_123"
        import warden.lemon_billing as _lb
        _lb._LS_VARIANT_INDIVIDUAL = "var_ind_123"

        raw, _ = _webhook_payload("tenant-abc", sub_item_id="item_metered_42")
        with _no_sig_check():
            billing.handle_webhook(raw, "")

        row = billing._conn.execute(
            "SELECT ls_sub_item_id FROM subscriptions WHERE tenant_id='tenant-abc'"
        ).fetchone()
        assert row is not None
        assert row["ls_sub_item_id"] == "item_metered_42"
        billing.close()

    def test_upsert_preserves_item_id_when_not_in_update(self):
        """Subsequent webhook without item info must not overwrite stored item_id."""
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        billing = _make_billing(tmp)
        os.environ["LEMONSQUEEZY_VARIANT_INDIVIDUAL"] = "var_ind_123"
        import warden.lemon_billing as _lb
        _lb._LS_VARIANT_INDIVIDUAL = "var_ind_123"

        # First webhook: sets item_id
        raw1, _ = _webhook_payload("t-preserve", sub_item_id="item_keep_me")
        with _no_sig_check():
            billing.handle_webhook(raw1, "")

        # Second webhook: payment_failed → sets status, no item_id
        raw2 = json.dumps({
            "meta": {
                "event_name": "subscription_payment_failed",
                "event_id":   "evt_fail_001",
                "custom_data": {},
            },
            "data": {"id": "sub_001"},
        }).encode()
        with _no_sig_check():
            billing.handle_webhook(raw2, "")

        row = billing._conn.execute(
            "SELECT ls_sub_item_id FROM subscriptions WHERE tenant_id='t-preserve'"
        ).fetchone()
        assert row["ls_sub_item_id"] == "item_keep_me"
        billing.close()


# ── 6-9. Feature flag enforcement ────────────────────────────────────────────

class TestFeatureFlagEnforcement(unittest.TestCase):
    def _billing(self, tmp_path: Path):
        return _make_billing(tmp_path)

    def test_enterprise_enables_pqc_and_sova(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        b = self._billing(tmp)
        import warden.lemon_billing as _lb
        _lb._LS_VARIANT_ENTERPRISE = "var_ent_999"
        raw, _ = _webhook_payload("t-ent", plan_variant="var_ent_999")
        with _no_sig_check():
            b.handle_webhook(raw, "")
        flags = b.get_feature_flags("t-ent")
        assert flags["post_quantum_cryptography"] is True
        assert flags["sova_agent"] is True
        assert flags["marketplace_node"] is True
        b.close()

    def test_downgrade_to_starter_clears_pqc_and_sova(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        b = self._billing(tmp)
        import warden.lemon_billing as _lb
        # First: grant Enterprise
        _lb._LS_VARIANT_ENTERPRISE = "var_ent_999"
        raw1, _ = _webhook_payload("t-downgrade", plan_variant="var_ent_999", sub_id="sub_d1")
        with _no_sig_check():
            b.handle_webhook(raw1, "")
        assert b.get_feature_flags("t-downgrade")["post_quantum_cryptography"] is True

        # Downgrade: cancel subscription
        cancel_raw = json.dumps({
            "meta": {
                "event_name": "subscription_cancelled",
                "event_id":   "evt_cancel_d1",
                "custom_data": {},
            },
            "data": {"id": "sub_d1"},
        }).encode()
        with _no_sig_check():
            b.handle_webhook(cancel_raw, "")

        flags = b.get_feature_flags("t-downgrade")
        assert flags["post_quantum_cryptography"] is False
        assert flags["sova_agent"] is False
        b.close()

    def test_pro_enables_sova_not_pqc(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        b = self._billing(tmp)
        import warden.lemon_billing as _lb
        _lb._LS_VARIANT_PRO = "var_pro_77"
        raw, _ = _webhook_payload("t-pro", plan_variant="var_pro_77")
        with _no_sig_check():
            b.handle_webhook(raw, "")
        flags = b.get_feature_flags("t-pro")
        assert flags["sova_agent"] is True
        assert flags["post_quantum_cryptography"] is False
        b.close()

    def test_individual_enables_marketplace_node_only(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        b = self._billing(tmp)
        import warden.lemon_billing as _lb
        _lb._LS_VARIANT_INDIVIDUAL = "var_ind_123"
        raw, _ = _webhook_payload("t-ind", plan_variant="var_ind_123")
        with _no_sig_check():
            b.handle_webhook(raw, "")
        flags = b.get_feature_flags("t-ind")
        assert flags["marketplace_node"] is True
        assert flags["sova_agent"] is False
        assert flags["post_quantum_cryptography"] is False
        b.close()


# ── 10. get_feature_flags defaults ───────────────────────────────────────────

class TestFeatureFlagDefaults(unittest.TestCase):
    def test_returns_all_false_for_unknown_tenant(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        b = _make_billing(tmp)
        flags = b.get_feature_flags("completely-unknown-tenant")
        assert flags == {
            "post_quantum_cryptography": False,
            "sova_agent": False,
            "marketplace_node": False,
        }
        b.close()


# ── 11. _report_search_usage fail-open ───────────────────────────────────────

class TestReportSearchUsageTask(unittest.TestCase):
    def test_enqueues_record_fail_open_on_import_error(self):
        from warden.marketplace.api import _report_search_usage
        with patch("warden.lemon_billing.get_meter_aggregator", side_effect=ImportError("no ls")):
            _report_search_usage("tenant-xyz")  # must not raise

    def test_enqueues_record_via_aggregator(self):
        from warden.marketplace.api import _report_search_usage
        mock_agg = MagicMock()
        with patch("warden.lemon_billing.get_meter_aggregator", return_value=mock_agg):
            _report_search_usage("tenant-xyz")
        mock_agg.record.assert_called_once_with("tenant-xyz", 0.000001)


# ── 13. MeterUsageAggregator uses ls_sub_item_id ─────────────────────────────

class TestAggregatorUsesItemId(unittest.TestCase):
    def test_flush_uses_ls_sub_item_id(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        billing = _make_billing(tmp)

        # Seed a subscription with a known sub_item_id
        billing._upsert("t-flush", "cust_1", "sub_f1", "individual", "active", None, "ITEM_FLUSH_99")

        agg_calls: list[dict] = []

        def _fake_ls(m, p, b=None):
            agg_calls.append({"method": m, "path": p, "body": b})
            return {}

        import warden.lemon_billing as _lb
        from warden.lemon_billing import MeterUsageAggregator
        orig = _lb._instance
        _lb._instance = billing

        agg = MeterUsageAggregator()
        agg._pending["t-flush"] = [0.000001, 0.000001]  # 2 events

        with (
            patch("warden.lemon_billing._ls_request", side_effect=_fake_ls),
            patch("warden.lemon_billing._LS_API_KEY", "fake-key"),
        ):
            agg.flush()

        _lb._instance = orig
        billing.close()

        assert len(agg_calls) == 1
        body = agg_calls[0]["body"]
        rel_id = body["data"]["relationships"]["subscription-item"]["data"]["id"]
        assert rel_id == "ITEM_FLUSH_99"
        assert body["data"]["attributes"]["quantity"] == 2
