"""Tests for STAFF-01: Authorization Boundary Registry + Velocity Guard."""
from __future__ import annotations

import time
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from warden.staff.boundaries import (
    DEFAULT_BOUNDARIES,
    AgentRole,
    AuthorizationBoundary,
    BoundaryRegistry,
    BoundaryViolationError,
)
from warden.staff.velocity import VelocityGuard

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_registry():
    import warden.staff.boundaries as _b
    _b._registry_instance = None
    yield
    _b._registry_instance = None


@pytest.fixture
def reg():
    return BoundaryRegistry(redis=None)


# ── AuthorizationBoundary ─────────────────────────────────────────────────────

class TestAuthorizationBoundary:
    def test_check_tool_allowed(self, reg):
        b = reg.get("bdr")
        assert b is not None
        b.check_tool("crm_search")  # must not raise

    def test_check_tool_denied_raises(self, reg):
        b = reg.get("bdr")
        with pytest.raises(BoundaryViolationError, match="not authorized"):
            b.check_tool("issue_refund")

    def test_suspended_agent_raises_on_any_tool(self, reg):
        reg.suspend("bdr")
        b = reg.get("bdr")
        with pytest.raises(BoundaryViolationError, match="suspended"):
            b.check_tool("crm_search")

    def test_redis_roundtrip(self):
        b = AuthorizationBoundary(
            agent_id="test_agent",
            role=AgentRole.SUPPORT,
            allowed_tools=frozenset({"tool_a", "tool_b"}),
            spend_ceiling_usd_daily=Decimal("25.50"),
            refund_cap_usd=Decimal("10.00"),
            autonomy_level=2,
        )
        serialized = b.to_redis()
        restored = AuthorizationBoundary.from_redis(serialized)
        assert restored.agent_id == "test_agent"
        assert restored.role == AgentRole.SUPPORT
        assert "tool_a" in restored.allowed_tools
        assert restored.spend_ceiling_usd_daily == Decimal("25.50")
        assert restored.autonomy_level == 2


# ── BoundaryRegistry ──────────────────────────────────────────────────────────

class TestBoundaryRegistry:
    def test_defaults_loaded(self, reg):
        assert reg.get("bdr") is not None
        assert reg.get("growth") is not None
        assert reg.get("compliance") is not None
        assert reg.get("qa") is not None
        assert reg.get("support") is not None

    def test_get_nonexistent_returns_none(self, reg):
        assert reg.get("nonexistent_agent") is None

    def test_put_and_get(self, reg):
        b = AuthorizationBoundary(
            agent_id="custom",
            role=AgentRole.BDR,
            allowed_tools=frozenset({"my_tool"}),
        )
        reg.put(b)
        got = reg.get("custom")
        assert got is not None
        assert "my_tool" in got.allowed_tools

    def test_suspend_sets_flag(self, reg):
        assert reg.get("growth").suspended is False
        reg.suspend("growth")
        assert reg.get("growth").suspended is True

    def test_restore_clears_flag(self, reg):
        reg.suspend("support")
        reg.restore("support")
        assert reg.get("support").suspended is False

    def test_suspend_nonexistent_returns_false(self, reg):
        assert reg.suspend("nobody") is False

    def test_list_all_returns_all_defaults(self, reg):
        items = reg.list_all()
        ids = {x["agent_id"] for x in items}
        assert {"bdr", "growth", "compliance", "qa", "support"}.issubset(ids)

    def test_check_and_dispatch_allowed(self, reg):
        b = reg.check_and_dispatch("support", "get_ticket")
        assert b.role == AgentRole.SUPPORT

    def test_check_and_dispatch_denied(self, reg):
        with pytest.raises(BoundaryViolationError):
            reg.check_and_dispatch("qa", "issue_refund")

    def test_check_and_dispatch_unregistered(self, reg):
        with pytest.raises(BoundaryViolationError, match="No boundary"):
            reg.check_and_dispatch("ghost_agent", "any_tool")


# ── Refund intent (Rec-3) ─────────────────────────────────────────────────────

class TestRefundIntent:
    def test_within_cap_returns_intent(self, reg):
        b = reg.get("support")
        result = b.sign_refund_intent("tenant-1", Decimal("5.00"), "duplicate charge")
        assert result["requires_backend_countersign"] is True
        assert result["intent"]["amount_usd"] == "5.00"
        assert "sig" in result
        assert len(result["sig"]) == 64  # sha256 hex

    def test_exceeds_cap_raises(self, reg):
        b = reg.get("support")
        with pytest.raises(BoundaryViolationError, match="exceeds cap"):
            b.sign_refund_intent("tenant-2", Decimal("50.00"), "large refund")

    def test_intent_has_issued_at(self, reg):
        b = reg.get("support")
        result = b.sign_refund_intent("t", Decimal("1.00"), "test")
        assert abs(result["intent"]["issued_at"] - int(time.time())) < 5

    def test_sig_changes_with_different_amount(self, reg):
        b = reg.get("support")
        r1 = b.sign_refund_intent("t", Decimal("1.00"), "r")
        r2 = b.sign_refund_intent("t", Decimal("2.00"), "r")
        assert r1["sig"] != r2["sig"]


# ── Velocity Guard (Rec-2) ────────────────────────────────────────────────────

class TestVelocityGuard:
    def test_no_redis_returns_none(self):
        vg = VelocityGuard(redis=None)
        result = vg.record_and_check("bdr", "crm_search", {}, 100, 60, 5)
        assert result is None

    def test_rate_exceeded_detection(self):
        mock_r = MagicMock()
        vg = VelocityGuard(redis=mock_r)
        mock_pipe = MagicMock()
        mock_r.pipeline.return_value = mock_pipe
        # Simulate 250 calls in window (limit is 200)
        mock_pipe.execute.return_value = [1, 0, 250, 1]
        alert = vg.record_and_check("growth", "fetch_market_signals", {}, 200, 60, 5)
        assert alert is not None
        assert alert.kind == "rate_exceeded"
        assert alert.agent_id == "growth"
        assert alert.count == 250

    def test_loop_detected(self):
        mock_r = MagicMock()
        vg = VelocityGuard(redis=mock_r)
        mock_pipe = MagicMock()
        mock_r.pipeline.return_value = mock_pipe
        # Hourly fine (count=3), loop bad (count=8)
        mock_pipe.execute.side_effect = [
            [1, 0, 3, 1],   # hourly check: 3 calls OK
            [1, 0, 8, 1],   # loop check: 8 identical calls (limit 5)
        ]
        alert = vg.record_and_check("compliance", "screen_sanctions_list", {"doc": "x"}, 200, 60, 5)
        assert alert is not None
        assert alert.kind == "loop_detected"
        assert "loop" in alert.detail.lower()

    def test_within_limits_returns_none(self):
        mock_r = MagicMock()
        vg = VelocityGuard(redis=mock_r)
        mock_pipe = MagicMock()
        mock_r.pipeline.return_value = mock_pipe
        mock_pipe.execute.side_effect = [
            [1, 0, 10, 1],  # hourly fine
            [1, 0, 2, 1],   # loop fine
        ]
        result = vg.record_and_check("support", "get_ticket", {}, 200, 60, 5)
        assert result is None

    def test_redis_error_fails_open(self):
        mock_r = MagicMock()
        mock_r.pipeline.side_effect = RuntimeError("Redis down")
        vg = VelocityGuard(redis=mock_r)
        result = vg.record_and_check("bdr", "crm_search", {}, 100, 60, 5)
        assert result is None  # fail-open


# ── Default boundary correctness ──────────────────────────────────────────────

class TestDefaultBoundaries:
    def test_bdr_cannot_issue_refund(self):
        b = DEFAULT_BOUNDARIES["bdr"]
        assert "issue_refund" not in b.allowed_tools

    def test_support_can_issue_refund(self):
        b = DEFAULT_BOUNDARIES["support"]
        assert "issue_refund" in b.allowed_tools

    def test_qa_cannot_issue_refund_or_adjust_budget(self):
        b = DEFAULT_BOUNDARIES["qa"]
        assert "issue_refund" not in b.allowed_tools
        assert "adjust_ad_budget" not in b.allowed_tools

    def test_growth_has_spend_ceiling(self):
        b = DEFAULT_BOUNDARIES["growth"]
        assert b.spend_ceiling_usd_daily == Decimal("50.00")

    def test_compliance_is_l2_autonomy(self):
        b = DEFAULT_BOUNDARIES["compliance"]
        assert b.autonomy_level == 2
        assert b.escalation_threshold == "MEDIUM"

    def test_bdr_escalation_is_low(self):
        # All BDR commitments → human
        b = DEFAULT_BOUNDARIES["bdr"]
        assert b.escalation_threshold == "LOW"


# ── API endpoints ─────────────────────────────────────────────────────────────

class TestStaffAPI:
    @pytest.fixture(autouse=True)
    def _client(self):
        from fastapi.testclient import TestClient

        from warden.main import app
        self.client = TestClient(app, raise_server_exceptions=True)

    def test_list_boundaries_returns_defaults(self):
        r = self.client.get("/staff/boundaries", headers={"X-Tenant-Tier": "pro"})
        assert r.status_code == 200
        ids = {b["agent_id"] for b in r.json()}
        assert "bdr" in ids and "support" in ids

    def test_get_single_boundary(self):
        r = self.client.get("/staff/boundaries/growth", headers={"X-Tenant-Tier": "pro"})
        assert r.status_code == 200
        assert r.json()["role"] == "GROWTH"

    def test_get_unknown_boundary_404(self):
        r = self.client.get("/staff/boundaries/ghost", headers={"X-Tenant-Tier": "pro"})
        assert r.status_code == 404

    def test_suspend_and_restore(self):
        r = self.client.post("/staff/boundaries/qa/suspend", headers={"X-Tenant-Tier": "pro"})
        assert r.status_code == 200
        assert r.json()["suspended"] is True

        r = self.client.post("/staff/boundaries/qa/restore", headers={"X-Tenant-Tier": "pro"})
        assert r.status_code == 200
        assert r.json()["suspended"] is False

    def test_suspend_unknown_404(self):
        r = self.client.post("/staff/boundaries/nobody/suspend", headers={"X-Tenant-Tier": "pro"})
        assert r.status_code == 404

    def test_sign_refund_intent_within_cap(self):
        payload = {
            "agent_id": "support",
            "tenant_id": "t-test",
            "amount_usd": "5.00",
            "reason": "duplicate",
        }
        r = self.client.post("/staff/intent/refund", json=payload, headers={"X-Tenant-Tier": "pro"})
        assert r.status_code == 200
        data = r.json()
        assert data["requires_backend_countersign"] is True
        assert "sig" in data

    def test_sign_refund_intent_exceeds_cap_403(self):
        payload = {
            "agent_id": "support",
            "tenant_id": "t-test",
            "amount_usd": "100.00",
            "reason": "large refund",
        }
        r = self.client.post("/staff/intent/refund", json=payload, headers={"X-Tenant-Tier": "pro"})
        assert r.status_code == 403
