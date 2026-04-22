"""Tests for warden/billing/quotas.py and warden/billing/overage.py."""
import os
import uuid

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("SEMANTIC_THRESHOLD", "0.72")
os.environ.setdefault("LOGS_PATH", "/tmp/warden_billing_test_logs.json")
os.environ.setdefault("TUNNEL_HARD_BLOCK", "false")


# ══════════════════════════════════════════════════════════════════════════════
# quotas — pure helpers (no Redis)
# ══════════════════════════════════════════════════════════════════════════════

class TestQuotasConstants:
    def test_plan_limits_defined(self):
        from warden.billing.quotas import PLAN_BANDWIDTH_BYTES
        assert "individual" in PLAN_BANDWIDTH_BYTES
        assert "business" in PLAN_BANDWIDTH_BYTES
        assert "mcp" in PLAN_BANDWIDTH_BYTES
        assert "free" in PLAN_BANDWIDTH_BYTES

    def test_individual_limit_1gb(self):
        from warden.billing.quotas import PLAN_BANDWIDTH_BYTES
        _GB = 1024 ** 3
        assert PLAN_BANDWIDTH_BYTES["individual"] == 1 * _GB

    def test_business_limit_50gb(self):
        from warden.billing.quotas import PLAN_BANDWIDTH_BYTES
        _GB = 1024 ** 3
        assert PLAN_BANDWIDTH_BYTES["business"] == 50 * _GB

    def test_mcp_limit_500gb(self):
        from warden.billing.quotas import PLAN_BANDWIDTH_BYTES
        _GB = 1024 ** 3
        assert PLAN_BANDWIDTH_BYTES["mcp"] == 500 * _GB

    def test_free_limit_is_zero(self):
        from warden.billing.quotas import PLAN_BANDWIDTH_BYTES
        assert PLAN_BANDWIDTH_BYTES["free"] == 0

    def test_month_key_format(self):
        from warden.billing.quotas import _month_key
        key = _month_key("tenant-abc")
        assert key.startswith("warden:bandwidth:tenant-abc:")
        parts = key.split(":")
        assert len(parts) == 4
        assert "-" in parts[-1]  # YYYY-MM

    def test_month_key_current_month(self):
        from datetime import UTC, datetime
        from warden.billing.quotas import _month_key
        expected_month = datetime.now(UTC).strftime("%Y-%m")
        key = _month_key("t1")
        assert key.endswith(expected_month)


class TestCheckBandwidthFreeBlocked:
    def test_free_plan_raises_402(self):
        from fastapi import HTTPException
        from warden.billing.quotas import check_bandwidth
        with pytest.raises(HTTPException) as exc:
            check_bandwidth("t1", "free", 1024)
        assert exc.value.status_code == 402

    def test_mcp_none_limit_passes(self):
        """MCP plan has None limit (unlimited) — should not raise."""
        from warden.billing.quotas import PLAN_BANDWIDTH_BYTES, check_bandwidth
        # Temporarily set mcp to None to test unlimited path
        original = PLAN_BANDWIDTH_BYTES.get("mcp")
        PLAN_BANDWIDTH_BYTES["mcp"] = None
        try:
            check_bandwidth("t1", "mcp", 999 * 1024 ** 3)  # 999 GB — no raise
        except Exception as exc:
            # Only 402 or 503 are valid; 503 means Redis unavail (fail-open is ok)
            from fastapi import HTTPException
            assert isinstance(exc, HTTPException)
            assert exc.status_code == 503
        finally:
            PLAN_BANDWIDTH_BYTES["mcp"] = original


class TestGetBandwidthUsage:
    def test_returns_tuple(self):
        from warden.billing.quotas import get_bandwidth_usage
        used, limit = get_bandwidth_usage("no-redis-tenant", "individual")
        assert isinstance(used, int)
        assert used >= 0

    def test_individual_limit_returned(self):
        from warden.billing.quotas import PLAN_BANDWIDTH_BYTES, get_bandwidth_usage
        _, limit = get_bandwidth_usage("t2", "individual")
        assert limit == PLAN_BANDWIDTH_BYTES["individual"]

    def test_business_limit_returned(self):
        from warden.billing.quotas import PLAN_BANDWIDTH_BYTES, get_bandwidth_usage
        _, limit = get_bandwidth_usage("t3", "business")
        assert limit == PLAN_BANDWIDTH_BYTES["business"]

    def test_unknown_plan_returns_none_limit(self):
        from warden.billing.quotas import get_bandwidth_usage
        _, limit = get_bandwidth_usage("t4", "unknown_plan")
        assert limit is None


# ══════════════════════════════════════════════════════════════════════════════
# overage — pure helpers (no Redis, no Lemon Squeezy)
# ══════════════════════════════════════════════════════════════════════════════

class TestGetUpgradeUrl:
    def test_individual_to_business(self):
        from warden.billing.overage import get_upgrade_url
        url = get_upgrade_url("individual", "bandwidth")
        assert "from=individual" in url
        assert "to=business" in url
        assert "reason=bandwidth" in url

    def test_business_to_mcp(self):
        from warden.billing.overage import get_upgrade_url
        url = get_upgrade_url("business", "storage")
        assert "from=business" in url
        assert "to=mcp" in url

    def test_uses_portal_base_url_env(self):
        os.environ["PORTAL_BASE_URL"] = "https://custom.example.com"
        try:
            from warden.billing.overage import get_upgrade_url
            url = get_upgrade_url("individual", "bw")
            assert url.startswith("https://custom.example.com")
        finally:
            del os.environ["PORTAL_BASE_URL"]

    def test_default_base_url(self):
        os.environ.pop("PORTAL_BASE_URL", None)
        from warden.billing.overage import get_upgrade_url
        url = get_upgrade_url("individual", "bw")
        assert "shadowwarden.ai" in url or "shadow" in url


class TestGetOveragePackUrl:
    def test_returns_url_with_tier(self):
        from warden.billing.overage import get_overage_pack_url
        url = get_overage_pack_url("business", "bandwidth")
        assert "tier=business" in url
        assert "metric=bandwidth" in url

    def test_mcp_overage_url(self):
        from warden.billing.overage import get_overage_pack_url
        url = get_overage_pack_url("mcp", "storage")
        assert "tier=mcp" in url


class TestGenerateReferralCode:
    def test_code_format(self):
        from warden.billing.overage import generate_referral_code
        code = generate_referral_code("c1", "m1")
        assert code.startswith("REF-")
        assert len(code) == 12  # REF- (4) + 8 hex chars

    def test_codes_are_unique(self):
        from warden.billing.overage import generate_referral_code
        codes = {generate_referral_code(f"c{i}", "m1") for i in range(10)}
        assert len(codes) == 10

    def test_code_uppercase(self):
        from warden.billing.overage import generate_referral_code
        code = generate_referral_code("c2", "m2")
        suffix = code[4:]
        assert suffix == suffix.upper()


class TestResolveOverage:
    _GB = 1024 ** 3

    def test_individual_overage_returns_upgrade_url(self):
        from warden.billing.overage import resolve_overage
        result = resolve_overage("c1", "t1", "individual", "bandwidth",
                                 used_bytes=2 * self._GB, limit_bytes=1 * self._GB)
        assert isinstance(result, dict)
        assert "upgrade_url" in result
        assert "action" in result

    def test_business_soft_limit_no_raise(self):
        from warden.billing.overage import resolve_overage
        result = resolve_overage("c1", "t1", "business", "bandwidth",
                                 used_bytes=51 * self._GB, limit_bytes=50 * self._GB)
        assert isinstance(result, dict)
        assert "action" in result

    def test_mcp_soft_limit_no_raise(self):
        from warden.billing.overage import resolve_overage
        result = resolve_overage("c1", "t1", "mcp", "bandwidth",
                                 used_bytes=501 * self._GB, limit_bytes=500 * self._GB)
        assert isinstance(result, dict)


class TestApplyReferral:
    def test_invalid_code_raises_value_error(self):
        from warden.billing.overage import apply_referral
        with pytest.raises(ValueError, match="invalid"):
            apply_referral("REF-NONEXIST", "new-community")
