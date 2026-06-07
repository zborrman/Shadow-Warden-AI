"""
Targeted coverage tests for Community Hub v5.6 modules.
Covers uncovered branches in:
  - warden/business_community/agentic_commerce/semantic_budget.py
  - warden/business_community/agentic_commerce/ucp.py
  - warden/communities/community_factory.py  (patch_community, update_community_status)
  - warden/communities/community_compliance.py
  - warden/communities/community_evolution.py (extra branches)
"""
from __future__ import annotations

import uuid

import pytest


def _tid() -> str:
    return f"t-{uuid.uuid4().hex[:8]}"


def _cid() -> str:
    return uuid.uuid4().hex[:32]


# ══════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _tmp_db(tmp_path, monkeypatch):
    db = str(tmp_path / "cv2.db")
    monkeypatch.setenv("COMM_DB_PATH", db)
    monkeypatch.setenv("COMMERCE_DB_PATH", str(tmp_path / "commerce.db"))
    for mod in [
        "warden.communities.community_factory",
        "warden.communities.membership",
        "warden.communities.community_evolution",
        "warden.communities.community_compliance",
    ]:
        try:
            import sys
            if mod in sys.modules:
                sys.modules[mod].COMM_DB_PATH = db
        except Exception:
            pass
    yield db


# ══════════════════════════════════════════════════════════════
# community_factory — patch_community, update_community_status
# ══════════════════════════════════════════════════════════════

class TestCommunityFactoryPatching:
    def test_patch_name(self):
        from warden.communities.community_factory import (  # noqa: I001
            create_community, get_community, patch_community,
        )
        c = create_community("Orig", "desc", _tid())
        ok = patch_community(c.community_id, name="Updated")
        assert ok
        assert get_community(c.community_id).name == "Updated"

    def test_patch_description(self):
        from warden.communities.community_factory import (  # noqa: I001
            create_community, get_community, patch_community,
        )
        c = create_community("A", "old desc", _tid())
        patch_community(c.community_id, description="new desc")
        assert get_community(c.community_id).description == "new desc"

    def test_patch_both(self):
        from warden.communities.community_factory import (  # noqa: I001
            create_community, patch_community,
        )
        c = create_community("X", "", _tid())
        ok = patch_community(c.community_id, name="Y", description="Z")
        assert ok

    def test_patch_no_fields_returns_false(self):
        from warden.communities.community_factory import (  # noqa: I001
            create_community, patch_community,
        )
        c = create_community("N", "", _tid())
        assert patch_community(c.community_id) is False

    def test_update_status(self):
        from warden.communities.community_factory import (  # noqa: I001
            create_community, get_community, update_community_status,
        )
        c = create_community("S", "", _tid())
        ok = update_community_status(c.community_id, "suspended")
        assert ok
        assert get_community(c.community_id).status == "suspended"

    def test_update_status_nonexistent(self):
        from warden.communities.community_factory import update_community_status
        ok = update_community_status("nonexistent-id", "suspended")
        assert not ok


# ══════════════════════════════════════════════════════════════
# community_compliance — all 5 check functions + report
# ══════════════════════════════════════════════════════════════

class TestCommunityCompliance:
    def test_get_compliance_returns_report(self):
        from warden.communities.community_compliance import get_community_compliance
        from warden.communities.community_factory import create_community
        c = create_community("Comp", "", _tid())
        report = get_community_compliance(c.community_id)
        assert report.community_id == c.community_id
        assert report.score >= 0.0
        assert report.status in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT")
        assert len(report.controls) == 5

    def test_compliance_controls_have_required_fields(self):
        from warden.communities.community_compliance import get_community_compliance
        from warden.communities.community_factory import create_community
        c = create_community("C2", "", _tid())
        report = get_community_compliance(c.community_id)
        for ctrl in report.controls:
            assert "control" in ctrl
            assert "status" in ctrl
            assert "score" in ctrl

    def test_compliance_gaps_list(self):
        from warden.communities.community_compliance import get_community_compliance
        from warden.communities.community_factory import create_community
        c = create_community("C3", "", _tid())
        report = get_community_compliance(c.community_id)
        assert isinstance(report.gaps, list)

    def test_check_member_audit_no_members(self):
        from warden.communities.community_compliance import _check_member_audit
        ctrl = _check_member_audit(_cid())
        assert ctrl.control == "member_audit"
        assert ctrl.status in ("PASS", "FAIL", "WARN", "SKIP")

    def test_check_charter_missing(self):
        from warden.communities.community_compliance import _check_charter
        ctrl = _check_charter(_cid())
        assert ctrl.control == "charter_exists"

    def test_check_data_encryption(self):
        from warden.communities.community_compliance import _check_data_encryption
        ctrl = _check_data_encryption(_cid())
        assert ctrl.control == "data_encryption"
        assert ctrl.score > 0

    def test_check_stix_audit(self):
        from warden.communities.community_compliance import _check_stix_audit
        ctrl = _check_stix_audit(_cid())
        assert ctrl.control == "stix_audit_chain"

    def test_check_peering(self):
        from warden.communities.community_compliance import _check_peering
        ctrl = _check_peering(_cid())
        assert ctrl.control == "peering_verified"

    def test_compliance_with_members_improves_score(self):
        from warden.communities.community_compliance import get_community_compliance
        from warden.communities.community_factory import create_community
        from warden.communities.membership import add_member
        t = _tid()
        c = create_community("M", "", t)
        add_member(c.community_id, _tid(), "member")
        report = get_community_compliance(c.community_id)
        member_ctrl = next(
            (r for r in report.controls if r["control"] == "member_audit"), None
        )
        assert member_ctrl is not None
        assert member_ctrl["score"] >= 0.5


# ══════════════════════════════════════════════════════════════
# semantic_budget — BudgetDecision + check_budget branches
# ══════════════════════════════════════════════════════════════

class TestSemanticBudget:
    def test_budget_decision_dataclass(self):
        from warden.business_community.agentic_commerce.semantic_budget import BudgetDecision
        d = BudgetDecision(allowed=True, action="allow", reason="ok")
        assert d.allowed is True
        assert d.action == "allow"
        assert d.mtd_spend_usd == 0.0

    def test_commerce_not_enabled_returns_allow(self):
        from warden.business_community.agentic_commerce.semantic_budget import check_budget
        # No commerce settings configured → fail-open allow
        result = check_budget("tenant-no-commerce", 50.0)
        assert result.allowed is True

    def test_fetch_mtd_spend_direct_empty_db(self, tmp_path, monkeypatch):
        monkeypatch.setenv("COMMERCE_DB_PATH", str(tmp_path / "c.db"))
        from warden.business_community.agentic_commerce.semantic_budget import (
            _fetch_mtd_spend_direct,
        )
        spend = _fetch_mtd_spend_direct("t-abc")
        assert spend == 0.0

    def test_get_commerce_settings_fail_open(self):
        from warden.business_community.agentic_commerce.semantic_budget import (
            _get_commerce_settings,
        )
        cfg = _get_commerce_settings("nonexistent")
        assert isinstance(cfg, dict)

    def test_check_budget_per_tx_limit_block(self, monkeypatch):
        from warden.business_community.agentic_commerce.semantic_budget import (
            BudgetDecision,
            check_budget,
        )
        # Mock settings to return enabled=True with a low per_tx limit
        def _mock_settings(tid):
            return {
                "enabled": True,
                "per_transaction_limit_usd": 10.0,
                "monthly_budget_usd": 1000.0,
                "require_approval_above_usd": 500.0,
            }
        monkeypatch.setattr(
            "warden.business_community.agentic_commerce.semantic_budget._get_commerce_settings",
            _mock_settings,
        )
        result = check_budget("t-x", amount_usd=50.0)
        assert isinstance(result, BudgetDecision)
        assert not result.allowed
        assert result.action == "block"
        assert "per_transaction_limit_exceeded" in result.reason

    def test_check_budget_monthly_exceeded(self, monkeypatch):
        from warden.business_community.agentic_commerce.semantic_budget import check_budget

        monkeypatch.setattr(
            "warden.business_community.agentic_commerce.semantic_budget._get_commerce_settings",
            lambda tid: {
                "enabled": True,
                "per_transaction_limit_usd": 10000.0,
                "monthly_budget_usd": 5.0,
                "require_approval_above_usd": 10000.0,
            },
        )
        monkeypatch.setattr(
            "warden.business_community.agentic_commerce.semantic_budget._query_mtd_spend",
            lambda tid: 4.0,
        )
        result = check_budget("t-y", amount_usd=9.0)
        assert not result.allowed
        assert result.action == "block"

    def test_check_budget_approval_threshold(self, monkeypatch):
        from warden.business_community.agentic_commerce.semantic_budget import check_budget

        monkeypatch.setattr(
            "warden.business_community.agentic_commerce.semantic_budget._get_commerce_settings",
            lambda tid: {
                "enabled": True,
                "per_transaction_limit_usd": 10000.0,
                "monthly_budget_usd": 10000.0,
                "require_approval_above_usd": 50.0,
            },
        )
        monkeypatch.setattr(
            "warden.business_community.agentic_commerce.semantic_budget._query_mtd_spend",
            lambda tid: 0.0,
        )
        result = check_budget("t-z", amount_usd=100.0)
        assert result.allowed is True
        assert result.action == "require_approval"

    def test_check_budget_allow(self, monkeypatch):
        from warden.business_community.agentic_commerce.semantic_budget import check_budget

        monkeypatch.setattr(
            "warden.business_community.agentic_commerce.semantic_budget._get_commerce_settings",
            lambda tid: {
                "enabled": True,
                "per_transaction_limit_usd": 10000.0,
                "monthly_budget_usd": 10000.0,
                "require_approval_above_usd": 10000.0,
            },
        )
        monkeypatch.setattr(
            "warden.business_community.agentic_commerce.semantic_budget._query_mtd_spend",
            lambda tid: 0.0,
        )
        result = check_budget("t-ok", amount_usd=5.0)
        assert result.allowed is True
        assert result.action == "allow"


# ══════════════════════════════════════════════════════════════
# ucp.py — UCPCapabilities + UCPClient (sync/fail-open paths)
# ══════════════════════════════════════════════════════════════

class TestUCPCapabilities:
    def test_empty_data(self):
        from warden.business_community.agentic_commerce.ucp import UCPCapabilities
        c = UCPCapabilities({})
        assert c.search_url == ""
        assert c.cart_url == ""
        assert c.supports_ap2 is False

    def test_with_ap2_protocol(self):
        from warden.business_community.agentic_commerce.ucp import UCPCapabilities
        c = UCPCapabilities({
            "search_url": "https://store.example/search",
            "cart_url": "https://store.example/cart",
            "checkout_url": "https://store.example/checkout",
            "protocols": ["ap2", "ucp1"],
        })
        assert c.supports_ap2 is True
        assert "ap2" in c.supported_protocols

    def test_without_ap2(self):
        from warden.business_community.agentic_commerce.ucp import UCPCapabilities
        c = UCPCapabilities({"protocols": ["ucp1"]})
        assert c.supports_ap2 is False


class TestUCPClient:
    def test_instantiation(self):
        from warden.business_community.agentic_commerce.ucp import UCPClient
        client = UCPClient(timeout=5.0)
        assert client.timeout == 5.0

    def test_default_timeout(self):
        from warden.business_community.agentic_commerce.ucp import UCPClient
        client = UCPClient()
        assert client.timeout == 8.0

    @pytest.mark.asyncio
    async def test_discover_store_fail_open(self):
        from warden.business_community.agentic_commerce.ucp import UCPClient
        client = UCPClient(timeout=0.01)
        # Non-routable IP — must fail-open, not raise
        result = await client.discover_store("192.0.2.1")
        assert result is None

    @pytest.mark.asyncio
    async def test_search_no_url(self):
        from warden.business_community.agentic_commerce.ucp import UCPCapabilities, UCPClient
        client = UCPClient()
        store = UCPCapabilities({})  # no search_url
        items = await client.search_products(store, "test")
        assert items == []

    @pytest.mark.asyncio
    async def test_add_to_cart_no_url(self):
        from warden.business_community.agentic_commerce.ucp import UCPCapabilities, UCPClient
        client = UCPClient()
        store = UCPCapabilities({})  # no cart_url
        result = await client.add_to_cart(store, "prod-1")
        assert "error" in result


# ══════════════════════════════════════════════════════════════
# community_evolution — extra branches
# ══════════════════════════════════════════════════════════════

class TestCommunityEvolutionExtra:
    def test_list_bundles_empty(self):
        from warden.communities.community_evolution import list_bundles
        result = list_bundles(community_id=_cid())
        assert isinstance(result, list)

    def test_import_pending_rule_fails(self):
        from warden.communities.community_evolution import import_rule, share_rule
        cid = _cid()
        b = share_rule(cid, _tid(), "jailbreak_signature", "content")
        # Cannot import pending rule
        ok = import_rule(b.bundle_id, cid)
        assert not ok

    def test_reject_rule(self):
        from warden.communities.community_evolution import (  # noqa: I001
            list_bundles, reject_rule, share_rule,
        )
        cid = _cid()
        b = share_rule(cid, _tid(), "regex_pattern", "^test")
        ok = reject_rule(b.bundle_id)
        assert ok
        pending = list_bundles(community_id=cid, status="pending_review")
        assert all(x.bundle_id != b.bundle_id for x in pending)

    def test_evolution_stats_new_community(self):
        from warden.communities.community_evolution import get_evolution_stats
        stats = get_evolution_stats(_cid())
        assert stats["total"] == 0
        assert (stats["approved"] or 0) == 0
