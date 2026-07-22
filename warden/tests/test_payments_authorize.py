"""Tests for warden/payments/authorize.py — the FT-6 authorize_payment() chokepoint."""
from __future__ import annotations

import pytest


class TestEnforcementFlag:
    def test_disabled_by_default(self):
        from warden.payments.authorize import enforcement_enabled
        assert enforcement_enabled() is False

    def test_enabled_via_env(self, monkeypatch):
        from warden.payments.authorize import enforcement_enabled
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        assert enforcement_enabled() is True


class TestAuthorizePaymentDisabled:
    def test_noop_returns_allow(self):
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("tenant-1", "agent-1", "purchase", 10.0)
        assert result.verdict == "ALLOW"
        assert result.reasons == ["enforcement_disabled"]
        assert result.checks == {}


def _stub_autonomy(monkeypatch, verdict):
    import warden.marketplace.autonomy as autonomy_mod
    monkeypatch.setattr(autonomy_mod, "check_action", lambda *a, **k: verdict)


def _stub_budget(monkeypatch, allowed, action, reason="ok"):
    import warden.business_community.agentic_commerce.semantic_budget as budget_mod
    from warden.business_community.agentic_commerce.semantic_budget import BudgetDecision
    monkeypatch.setattr(
        budget_mod, "check_budget",
        lambda *a, **k: BudgetDecision(allowed=allowed, action=action, reason=reason),
    )


class TestAuthorizePaymentComposition:
    @pytest.fixture(autouse=True)
    def _enforce(self, monkeypatch):
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")

    def test_both_allow(self, monkeypatch):
        _stub_autonomy(monkeypatch, "ALLOW")
        _stub_budget(monkeypatch, True, "allow")
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0)
        assert result.verdict == "ALLOW"
        assert result.checks == {"autonomy": "ALLOW", "budget": "ALLOW"}

    def test_autonomy_block_denies(self, monkeypatch):
        _stub_autonomy(monkeypatch, "BLOCK")
        _stub_budget(monkeypatch, True, "allow")
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0)
        assert result.verdict == "DENY"

    def test_budget_block_denies(self, monkeypatch):
        _stub_autonomy(monkeypatch, "ALLOW")
        _stub_budget(monkeypatch, False, "block", reason="monthly_budget_exceeded")
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0)
        assert result.verdict == "DENY"
        assert any("monthly_budget_exceeded" in r for r in result.reasons)

    def test_autonomy_require_approval_propagates(self, monkeypatch):
        _stub_autonomy(monkeypatch, "REQUIRE_APPROVAL")
        _stub_budget(monkeypatch, True, "allow")
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0)
        assert result.verdict == "REQUIRE_APPROVAL"

    def test_budget_require_approval_propagates(self, monkeypatch):
        _stub_autonomy(monkeypatch, "ALLOW")
        _stub_budget(monkeypatch, True, "require_approval", reason="approval_threshold_exceeded")
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0)
        assert result.verdict == "REQUIRE_APPROVAL"

    def test_most_restrictive_verdict_wins(self, monkeypatch):
        """autonomy says REQUIRE_APPROVAL, budget says DENY -> overall DENY."""
        _stub_autonomy(monkeypatch, "REQUIRE_APPROVAL")
        _stub_budget(monkeypatch, False, "block", reason="per_transaction_limit_exceeded")
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0)
        assert result.verdict == "DENY"

    def test_autonomy_error_fails_soft_to_require_approval(self, monkeypatch):
        import warden.marketplace.autonomy as autonomy_mod
        def _boom(*a, **k):
            raise RuntimeError("autonomy backend down")
        monkeypatch.setattr(autonomy_mod, "check_action", _boom)
        _stub_budget(monkeypatch, True, "allow")
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0)
        assert result.verdict == "REQUIRE_APPROVAL"

    def test_budget_error_fails_soft_to_require_approval(self, monkeypatch):
        _stub_autonomy(monkeypatch, "ALLOW")
        import warden.business_community.agentic_commerce.semantic_budget as budget_mod
        def _boom(*a, **k):
            raise RuntimeError("budget backend down")
        monkeypatch.setattr(budget_mod, "check_budget", _boom)
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0)
        assert result.verdict == "REQUIRE_APPROVAL"


class TestMandateCheck:
    @pytest.fixture(autouse=True)
    def _enforce(self, monkeypatch):
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")

    def test_no_mandate_id_skips_mandate_check(self, monkeypatch):
        _stub_autonomy(monkeypatch, "ALLOW")
        _stub_budget(monkeypatch, True, "allow")
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0)
        assert "mandate" not in result.checks

    def test_valid_mandate_allows(self, monkeypatch):
        _stub_autonomy(monkeypatch, "ALLOW")
        _stub_budget(monkeypatch, True, "allow")
        import warden.business_community.agentic_commerce.ap2 as ap2_mod
        monkeypatch.setattr(
            ap2_mod.AP2Processor, "verify_mandate",
            lambda self, mandate_id, tenant_id: {"valid": True, "remaining": 100.0},
        )
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0, mandate_id="mnd-1")
        assert result.verdict == "ALLOW"
        assert result.checks["mandate"] == "ALLOW"

    def test_invalid_mandate_denies(self, monkeypatch):
        _stub_autonomy(monkeypatch, "ALLOW")
        _stub_budget(monkeypatch, True, "allow")
        import warden.business_community.agentic_commerce.ap2 as ap2_mod
        monkeypatch.setattr(
            ap2_mod.AP2Processor, "verify_mandate",
            lambda self, mandate_id, tenant_id: {"valid": False, "reason": "expired"},
        )
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0, mandate_id="mnd-1")
        assert result.verdict == "DENY"

    def test_mandate_error_fails_soft_to_require_approval(self, monkeypatch):
        _stub_autonomy(monkeypatch, "ALLOW")
        _stub_budget(monkeypatch, True, "allow")
        import warden.business_community.agentic_commerce.ap2 as ap2_mod
        def _boom(self, mandate_id, tenant_id):
            raise RuntimeError("mandate backend down")
        monkeypatch.setattr(ap2_mod.AP2Processor, "verify_mandate", _boom)
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "a1", "purchase", 5.0, mandate_id="mnd-1")
        assert result.verdict == "REQUIRE_APPROVAL"
