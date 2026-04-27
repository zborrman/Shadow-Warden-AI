"""
warden/tests/test_lemon_billing.py
────────────────────────────────────
Unit tests for the Lemon Squeezy billing stack:
  • LemonBilling (lemon_billing.py)
  • FeatureGate / TIER_LIMITS (billing/feature_gate.py)
  • Referral flywheel (billing/referral.py)
  • Quota middleware helpers (billing/quota_middleware.py)
  • Billing API router (billing/router.py) via TestClient
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from unittest.mock import patch

import pytest

# ── LemonBilling ──────────────────────────────────────────────────────────────

class TestLemonBilling:
    @pytest.fixture()
    def billing(self, tmp_path):
        """Fresh in-memory LemonBilling backed by a temp SQLite file."""
        from warden.lemon_billing import LemonBilling
        return LemonBilling(db_path=tmp_path / "test_lemon.db")

    def test_default_plan_is_starter(self, billing):
        assert billing.get_plan("tenant-xyz") == "starter"

    def test_upsert_and_get_plan(self, billing):
        billing._upsert("t1", "cust-1", "sub-1", "pro", "active", None)
        assert billing.get_plan("t1") == "pro"

    def test_cancelled_reverts_to_starter(self, billing):
        billing._upsert("t2", "cust-2", "sub-2", "pro", "active", None)
        billing._upsert("t2", "cust-2", "sub-2", "pro", "cancelled", None)
        assert billing.get_plan("t2") == "starter"

    def test_on_trial_is_valid(self, billing):
        billing._upsert("t3", "cust-3", "sub-3", "individual", "on_trial", None)
        assert billing.get_plan("t3") == "individual"

    def test_quota_for_known_plans(self, billing):
        billing._upsert("t4", "c", "s", "enterprise", "active", None)
        assert billing.get_quota("t4") is None  # unlimited

        billing._upsert("t5", "c", "s", "pro", "active", None)
        assert billing.get_quota("t5") == 50_000

    def test_get_status_shape(self, billing):
        billing._upsert("t6", "cust-6", "sub-6", "individual", "active", "2025-02-01")
        s = billing.get_status("t6")
        assert s["plan"]      == "individual"
        assert s["status"]    == "active"
        assert s["renews_at"] == "2025-02-01"

    def test_webhook_invalid_signature_raises(self, billing):
        payload = b'{"meta":{"event_name":"subscription_created"},"data":{}}'
        with patch.dict(os.environ, {"LEMONSQUEEZY_WEBHOOK_SECRET": "secret"}):
            # Rebuild the module-level var isn't needed — billing validates directly
            import warden.lemon_billing as lb_mod
            old = lb_mod._LS_WEBHOOK_SECRET
            lb_mod._LS_WEBHOOK_SECRET = "secret"
            with pytest.raises(ValueError, match="Invalid"):
                billing.handle_webhook(payload, "badhex")
            lb_mod._LS_WEBHOOK_SECRET = old

    def test_webhook_valid_signature_processes(self, billing):
        import warden.lemon_billing as lb_mod
        secret  = "test-webhook-secret"
        payload = json.dumps({
            "meta": {
                "event_name":  "subscription_created",
                "custom_data": {"tenant_id": "t-webhook"},
            },
            "data": {
                "id": "sub-99",
                "attributes": {
                    "customer_id": "cust-99",
                    "variant_id":  "",
                    "status":      "active",
                    "renews_at":   None,
                },
            },
        }).encode()
        sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        old = lb_mod._LS_WEBHOOK_SECRET
        lb_mod._LS_WEBHOOK_SECRET = secret
        try:
            event = billing.handle_webhook(payload, sig)
            assert event == "subscription_created"
        finally:
            lb_mod._LS_WEBHOOK_SECRET = old

    def test_checkout_raises_when_not_configured(self, billing):
        import warden.lemon_billing as lb_mod
        old = lb_mod._LS_API_KEY
        lb_mod._LS_API_KEY = ""
        billing._enabled = False
        with pytest.raises(RuntimeError, match="not configured"):
            billing.create_checkout_session("t", "pro", "https://ok", "https://cancel")
        lb_mod._LS_API_KEY = old

    def test_checkout_invalid_plan_raises(self, billing):
        import warden.lemon_billing as lb_mod
        lb_mod._LS_API_KEY = "fake"
        billing._enabled = True
        with pytest.raises(ValueError, match="Invalid plan"):
            billing.create_checkout_session("t", "unknown_plan", "https://ok", "https://cancel")
        lb_mod._LS_API_KEY = ""
        billing._enabled = False

    def test_webhook_idempotency_duplicate_skipped(self, billing):
        """Duplicate event_id must be silently skipped — subscription not updated twice."""
        import warden.lemon_billing as lb_mod
        secret  = "idem-secret"
        payload = json.dumps({
            "meta": {
                "event_name":  "subscription_created",
                "event_id":    "evt-idem-001",
                "custom_data": {"tenant_id": "t-idem"},
            },
            "data": {
                "id": "sub-idem",
                "attributes": {
                    "customer_id": "cust-idem",
                    "variant_id":  "",
                    "status":      "active",
                    "renews_at":   None,
                },
            },
        }).encode()
        sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

        old = lb_mod._LS_WEBHOOK_SECRET
        lb_mod._LS_WEBHOOK_SECRET = secret
        try:
            # First call — should process and upsert the subscription
            result1 = billing.handle_webhook(payload, sig)
            assert result1 == "subscription_created"
            assert billing.get_plan("t-idem") == "individual"  # default from empty variant

            # Manually downgrade to simulate a state change between retries
            billing._upsert("t-idem", "cust-idem", "sub-idem", "starter", "active", None)
            assert billing.get_plan("t-idem") == "starter"

            # Second call with same event_id — must be skipped, plan stays "starter"
            result2 = billing.handle_webhook(payload, sig)
            assert result2 == "subscription_created"
            assert billing.get_plan("t-idem") == "starter"  # NOT upgraded again
        finally:
            lb_mod._LS_WEBHOOK_SECRET = old

    def test_portal_url_includes_customer_id(self, billing):
        """get_portal_url must return customer-scoped URL when subscription exists."""
        billing._upsert("t-portal", "cust-42", "sub-p", "pro", "active", None)
        url = billing.get_portal_url("t-portal")
        assert "customer_id=cust-42" in url

    def test_portal_url_fallback_for_unknown_tenant(self, billing):
        url = billing.get_portal_url("no-such-tenant")
        assert url == "https://app.lemonsqueezy.com/my-orders"


# ── FeatureGate ───────────────────────────────────────────────────────────────

class TestFeatureGate:
    def test_tier_normalization(self):
        from warden.billing.feature_gate import FeatureGate
        assert FeatureGate.for_tier("free").tier  == "starter"
        assert FeatureGate.for_tier("msp").tier   == "enterprise"
        assert FeatureGate.for_tier("business").tier == "pro"

    def test_boolean_features_per_tier(self):
        from warden.billing.feature_gate import FeatureGate
        starter    = FeatureGate.for_tier("starter")
        individual = FeatureGate.for_tier("individual")
        pro        = FeatureGate.for_tier("pro")
        enterprise = FeatureGate.for_tier("enterprise")

        assert not starter.is_enabled("audit_trail")
        assert     individual.is_enabled("audit_trail")
        assert not starter.is_enabled("siem_integration")
        assert     pro.is_enabled("siem_integration")
        assert not pro.is_enabled("on_prem_deployment")
        assert     enterprise.is_enabled("on_prem_deployment")

    def test_require_raises_permission_error(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("individual")
        with pytest.raises(PermissionError, match="siem_integration"):
            gate.require("siem_integration")

    def test_meets_minimum(self):
        from warden.billing.feature_gate import FeatureGate
        pro = FeatureGate.for_tier("pro")
        assert     pro.meets_minimum("starter")
        assert     pro.meets_minimum("individual")
        assert     pro.meets_minimum("pro")
        assert not pro.meets_minimum("enterprise")

    def test_quota_req_per_month(self):
        from warden.billing.feature_gate import FeatureGate
        assert FeatureGate.for_tier("starter").quota_req_per_month()    == 1_000
        assert FeatureGate.for_tier("pro").quota_req_per_month()        == 50_000
        assert FeatureGate.for_tier("enterprise").quota_req_per_month() is None

    def test_as_dict_has_tier(self):
        from warden.billing.feature_gate import FeatureGate
        d = FeatureGate.for_tier("pro").as_dict()
        assert d["tier"]      == "pro"
        assert "siem_integration" in d
        assert "overage_prices"   in d

    def test_require_capacity(self):
        from warden.billing.feature_gate import FeatureGate
        pro = FeatureGate.for_tier("pro")
        pro.require_capacity("max_tenants", 10)   # 10 < 50 — OK
        with pytest.raises(PermissionError, match="Capacity limit reached"):
            pro.require_capacity("max_tenants", 50)  # 50 >= 50


# ── Referral flywheel ─────────────────────────────────────────────────────────

class TestReferral:
    """Tests use the in-memory fallback (no Redis required)."""

    def _clear(self):
        import warden.billing.referral as ref_mod
        ref_mod._CODE_STORE.clear()

    def test_generate_and_redeem(self):
        self._clear()
        from warden.billing.referral import (
            generate_referral_code,
            redeem_referral_code,
        )
        code   = generate_referral_code("referrer-1", "individual")
        assert code.startswith("REF-")
        result = redeem_referral_code(code, "new-tenant-1")
        assert result["referrer_tenant_id"]   == "referrer-1"
        assert result["referrer_bonus_req"]   == 500  # individual tier
        assert result["new_tenant_bonus_req"] == 500

    def test_code_is_one_time_use(self):
        self._clear()
        from warden.billing.referral import (
            generate_referral_code,
            redeem_referral_code,
        )
        code = generate_referral_code("referrer-2", "pro")
        redeem_referral_code(code, "new-tenant-2")
        with pytest.raises(ValueError, match="invalid"):
            redeem_referral_code(code, "new-tenant-3")

    def test_self_referral_rejected(self):
        self._clear()
        from warden.billing.referral import (
            generate_referral_code,
            redeem_referral_code,
        )
        code = generate_referral_code("solo-1", "individual")
        with pytest.raises(ValueError, match="Self-referral"):
            redeem_referral_code(code, "solo-1")

    def test_enterprise_cannot_generate(self):
        self._clear()
        from warden.billing.referral import generate_referral_code
        with pytest.raises(PermissionError, match="not available on the ENTERPRISE"):
            generate_referral_code("ent-tenant", "enterprise")

    def test_pro_bonus_is_2000(self):
        self._clear()
        from warden.billing.referral import (
            generate_referral_code,
            redeem_referral_code,
        )
        code   = generate_referral_code("pro-referrer", "pro")
        result = redeem_referral_code(code, "new-pro-1")
        assert result["referrer_bonus_req"] == 2_000


# ── Billing API router ────────────────────────────────────────────────────────

class TestBillingRouter:
    def test_tiers_endpoint(self, client):
        resp = client.get("/billing/tiers")
        assert resp.status_code == 200
        data = resp.json()
        assert "tiers" in data
        tiers_by_name = {t["tier"]: t for t in data["tiers"]}
        assert set(tiers_by_name.keys()) == {"starter", "individual", "community_business", "pro", "enterprise"}
        assert tiers_by_name["pro"]["siem_integration"] is True
        assert tiers_by_name["starter"]["siem_integration"] is False
        assert tiers_by_name["enterprise"]["referral_program"] is False

    def test_quota_requires_tenant_id(self, client):
        resp = client.get("/billing/quota")
        assert resp.status_code == 401

    def test_quota_returns_usage(self, client):
        resp = client.get("/billing/quota", headers={"X-Tenant-ID": "test-tenant"})
        assert resp.status_code == 200
        data = resp.json()
        assert "plan"            in data
        assert "used"            in data
        assert "effective_limit" in data

    def test_status_requires_tenant_id(self, client):
        resp = client.get("/billing/status")
        assert resp.status_code == 401

    def test_status_returns_plan(self, client):
        resp = client.get("/billing/status", headers={"X-Tenant-ID": "test-tenant"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["plan"] in ("starter", "individual", "community_business", "pro", "enterprise")
        assert "features" in data

    def test_referral_generate_requires_tenant_id(self, client):
        resp = client.post("/billing/referral/generate")
        assert resp.status_code == 401

    def test_referral_generate_returns_code(self, client):
        resp = client.post(
            "/billing/referral/generate",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["code"].startswith("REF-")
        assert "share_url" in data

    def test_referral_redeem_invalid_code(self, client):
        resp = client.post(
            "/billing/referral/redeem",
            json={"code": "REF-INVALID0", "new_tenant_id": "new-t"},
        )
        assert resp.status_code == 422

    def test_referral_redeem_valid_code(self, client):
        import warden.billing.referral as ref_mod
        ref_mod._CODE_STORE.clear()

        # Generate a code first
        gen_resp = client.post(
            "/billing/referral/generate",
            headers={"X-Tenant-ID": "referrer-test"},
        )
        assert gen_resp.status_code == 200
        code = gen_resp.json()["code"]

        # Redeem it
        redeem_resp = client.post(
            "/billing/referral/redeem",
            json={"code": code, "new_tenant_id": "brand-new-tenant"},
        )
        assert redeem_resp.status_code == 200
        data = redeem_resp.json()
        assert data["referrer_tenant_id"] == "referrer-test"

    def test_referral_stats(self, client):
        resp = client.get(
            "/billing/referral/stats",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "total_referrals"   in data
        assert "bonus_per_referral" in data

    def test_upgrade_redirect_when_ls_not_configured(self, client):
        """When LS is not configured, /billing/upgrade should redirect to pricing page."""
        resp = client.get(
            "/billing/upgrade",
            params={"plan": "pro"},
            headers={"X-Tenant-ID": "test-tenant"},
            follow_redirects=False,
        )
        assert resp.status_code in (303, 302, 307)
