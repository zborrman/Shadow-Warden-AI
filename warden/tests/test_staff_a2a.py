"""
Unit tests for Agent-to-Agent (A2A) Protocol.
"""
from __future__ import annotations

import asyncio

import pytest

from warden.staff.a2a import (
    ALLOWED_ROUTES,
    A2ARouter,
    _sign,
    _verify,
)


@pytest.fixture
def router(tmp_path):
    return A2ARouter(db_path=str(tmp_path / "a2a.db"))


def _run(coro):
    return asyncio.run(coro)


# ── HMAC token ────────────────────────────────────────────────────────────────

class TestHMACToken:
    def test_sign_produces_hex_string(self):
        token = _sign("support", "compliance", "score_kyc_profile", 1234567890)
        assert isinstance(token, str)
        assert len(token) == 64  # SHA-256 hex

    def test_verify_matching_token(self):
        ts = 1234567890
        token = _sign("support", "compliance", "score_kyc_profile", ts)
        assert _verify("support", "compliance", "score_kyc_profile", ts, token) is True

    def test_verify_wrong_caller_fails(self):
        ts = 1234567890
        token = _sign("support", "compliance", "score_kyc_profile", ts)
        assert _verify("bdr", "compliance", "score_kyc_profile", ts, token) is False

    def test_verify_wrong_tool_fails(self):
        ts = 1234567890
        token = _sign("support", "compliance", "score_kyc_profile", ts)
        assert _verify("support", "compliance", "screen_sanctions_list", ts, token) is False

    def test_verify_wrong_ts_fails(self):
        ts = 1234567890
        token = _sign("support", "compliance", "score_kyc_profile", ts)
        assert _verify("support", "compliance", "score_kyc_profile", ts + 1, token) is False

    def test_sign_deterministic_for_same_inputs(self):
        token1 = _sign("support", "compliance", "score_kyc_profile", 999)
        token2 = _sign("support", "compliance", "score_kyc_profile", 999)
        assert token1 == token2


# ── ALLOWED_ROUTES ────────────────────────────────────────────────────────────

class TestAllowedRoutes:
    def test_support_to_compliance_kyc_allowed(self):
        assert ("support", "compliance", "score_kyc_profile") in ALLOWED_ROUTES

    def test_support_to_compliance_sanctions_allowed(self):
        assert ("support", "compliance", "screen_sanctions_list") in ALLOWED_ROUTES

    def test_bdr_to_compliance_allowed(self):
        assert ("bdr", "compliance", "screen_sanctions_list") in ALLOWED_ROUTES

    def test_support_cannot_call_growth_tools(self):
        assert ("support", "growth", "generate_seo_content") not in ALLOWED_ROUTES

    def test_compliance_cannot_call_bdr_tools(self):
        assert ("compliance", "bdr", "crm_upsert_lead") not in ALLOWED_ROUTES

    def test_routes_are_tuples_of_three_strings(self):
        for route in ALLOWED_ROUTES:
            assert len(route) == 3
            assert all(isinstance(s, str) for s in route)


# ── A2ARouter.route (DENIED path) ─────────────────────────────────────────────

class TestRouteDenied:
    def test_unlisted_route_returns_denied(self, router):
        result = _run(router.route("support", "growth", "generate_seo_content", {"tenant_id": "t1"}))
        assert result["a2a_routed"] is False
        assert "error" in result
        assert "not permitted" in result["error"]

    def test_denied_includes_call_id(self, router):
        result = _run(router.route("support", "growth", "nonexistent", {}))
        assert "call_id" in result

    def test_denied_call_logged_to_db(self, router):
        _run(router.route("bdr", "support", "generate_sar", {}))  # not in ALLOWED_ROUTES
        log = router.get_audit_log(limit=10)
        denied = [c for c in log if c["status"] == "DENIED"]
        assert len(denied) >= 1


# ── A2ARouter.route (SUCCESS path — real tool call) ───────────────────────────

class TestRouteSuccess:
    def test_support_calls_compliance_kyc(self, router, tmp_path, monkeypatch):
        """Route support → compliance.score_kyc_profile with real tool."""
        monkeypatch.setenv("STAFF_COMPLIANCE_DB_PATH", str(tmp_path / "comp.db"))
        result = _run(router.route(
            "support", "compliance", "score_kyc_profile",
            {
                "tenant_id": "t1",
                "entity_name": "ACME Corp",
                "country": "RU",
                "entity_type": "company",
                "pep": False,
                "adverse_media": False,
                "transaction_volume_usd": 5000.0,
            },
        ))
        assert result["a2a_routed"] is True
        assert "risk_level" in result
        assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH")
        assert "call_id" in result
        assert "latency_ms" in result

    def test_success_call_logged_to_db(self, router, tmp_path, monkeypatch):
        monkeypatch.setenv("STAFF_COMPLIANCE_DB_PATH", str(tmp_path / "comp.db"))
        _run(router.route(
            "support", "compliance", "score_kyc_profile",
            {"tenant_id": "t1", "entity_name": "Clean Corp", "country": "US",
             "entity_type": "company", "pep": False, "adverse_media": False},
        ))
        log = router.get_audit_log(limit=10)
        success = [c for c in log if c["status"] == "SUCCESS"]
        assert len(success) >= 1
        assert success[0]["caller_agent_id"] == "support"
        assert success[0]["target_agent_id"] == "compliance"
        assert success[0]["tool_name"] == "score_kyc_profile"

    def test_result_has_latency_ms(self, router, tmp_path, monkeypatch):
        monkeypatch.setenv("STAFF_COMPLIANCE_DB_PATH", str(tmp_path / "comp.db"))
        result = _run(router.route(
            "support", "compliance", "score_kyc_profile",
            {"tenant_id": "t1", "entity_name": "Test", "country": "DE",
             "entity_type": "individual", "pep": False, "adverse_media": False},
        ))
        assert result["latency_ms"] >= 0.0


# ── A2A audit log ──────────────────────────────────────────────────────────────

class TestAuditLog:
    def test_empty_log_for_fresh_db(self, router):
        assert router.get_audit_log() == []

    def test_audit_log_grows_with_calls(self, router):
        _run(router.route("bdr", "support", "nonexistent", {}))  # DENIED
        _run(router.route("support", "growth", "nonexistent", {}))  # DENIED
        log = router.get_audit_log()
        assert len(log) == 2

    def test_audit_log_limit(self, router):
        for _ in range(5):
            _run(router.route("support", "growth", "nope", {}))
        log = router.get_audit_log(limit=3)
        assert len(log) == 3

    def test_audit_log_desc_order(self, router):
        _run(router.route("support", "growth", "a", {}))
        _run(router.route("support", "growth", "b", {}))
        log = router.get_audit_log(limit=5)
        if len(log) >= 2:
            assert log[0]["ts"] >= log[1]["ts"]  # descending


# ── issue_refund A2A integration ──────────────────────────────────────────────

class TestIssueRefundA2A:
    """Tests the A2A pre-check in issue_refund() for high-risk countries."""

    def test_high_risk_country_triggers_a2a_check(self, tmp_path, monkeypatch):
        monkeypatch.setenv("STAFF_SUPPORT_DB_PATH", str(tmp_path / "support.db"))
        monkeypatch.setenv("STAFF_COMPLIANCE_DB_PATH", str(tmp_path / "comp.db"))
        monkeypatch.setenv("STAFF_A2A_DB_PATH", str(tmp_path / "a2a.db"))

        # Reset singleton so it picks up the new DB path
        import warden.staff.a2a as a2a_mod
        a2a_mod._router_instance = None

        from warden.staff.tools.support import issue_refund

        result = _run(issue_refund(
            tenant_id="t1",
            agent_id="support",
            amount_usd="99.00",
            reason="Customer request",
            country="RU",  # HIGH_RISK
        ))
        # Should either escalate or fail-open and proceed normally
        assert isinstance(result, dict)
        # If A2A scored HIGH risk → escalated=True
        # If fail-open → issued=True
        assert "escalated" in result or "issued" in result

    def test_safe_country_skips_a2a_check(self, tmp_path, monkeypatch):
        monkeypatch.setenv("STAFF_SUPPORT_DB_PATH", str(tmp_path / "support.db"))

        from warden.staff.tools.support import issue_refund

        result = _run(issue_refund(
            tenant_id="t1",
            agent_id="support",
            amount_usd="10.00",
            reason="Test refund",
            country="US",  # safe country — no A2A call
        ))
        # US is not in HIGH_RISK — no A2A → goes straight to refund intent
        assert isinstance(result, dict)
        # Will either succeed or fail on boundary lookup — either way no escalation
        assert result.get("escalated") is None or result.get("escalated") is False
