"""Tests for shadow_ai/policy.py, billing/addons.py, agentic/mandate.py, agentic/registry.py."""
import hashlib
import hmac
import os
import time

import pytest

os.environ.setdefault("REDIS_URL", "memory://")


def _sign_mandate(invoice_hash: str, sku: str, amount: float, agent_id: str) -> str:
    secret = os.environ.get("MANDATE_SECRET", "")
    if not secret:
        return ""
    canonical = f"{invoice_hash}:{sku}:{amount}:{agent_id}"
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# shadow_ai/policy.py
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def clear_shadow_policy_store():
    import warden.shadow_ai.policy as pol
    pol._MEMORY_STORE.clear()
    yield
    pol._MEMORY_STORE.clear()


class TestShadowAIPolicy:
    def test_get_policy_returns_default(self):
        import warden.shadow_ai.policy as pol
        p = pol.get_policy("tenant-new")
        assert p["mode"] == "MONITOR"
        assert p["allowlist"] == []
        assert p["denylist"] == []
        assert p["risk_threshold"] == "LOW"
        assert p["notify_slack"] is False

    def test_update_policy_persists_to_memory(self):
        import warden.shadow_ai.policy as pol
        pol.update_policy("t1", {"mode": "BLOCK_DENYLIST", "denylist": ["huggingface"]})
        p = pol.get_policy("t1")
        assert p["mode"] == "BLOCK_DENYLIST"
        assert "huggingface" in p["denylist"]

    def test_update_policy_allowlist_mode(self):
        import warden.shadow_ai.policy as pol
        pol.update_policy("t2", {"mode": "ALLOWLIST_ONLY", "allowlist": ["OpenAI", "Anthropic"]})
        p = pol.get_policy("t2")
        assert p["mode"] == "ALLOWLIST_ONLY"
        assert "openai" in p["allowlist"]  # normalized to lowercase
        assert "anthropic" in p["allowlist"]

    def test_update_policy_invalid_mode(self):
        import warden.shadow_ai.policy as pol
        with pytest.raises(ValueError, match="Invalid mode"):
            pol.update_policy("t3", {"mode": "UNKNOWN"})

    def test_update_policy_invalid_risk_threshold(self):
        import warden.shadow_ai.policy as pol
        with pytest.raises(ValueError, match="Invalid risk_threshold"):
            pol.update_policy("t3", {"risk_threshold": "CRITICAL"})

    def test_update_policy_dedup_lists(self):
        import warden.shadow_ai.policy as pol
        pol.update_policy("t4", {"allowlist": ["OpenAI", "openai", "OPENAI"]})
        p = pol.get_policy("t4")
        assert p["allowlist"].count("openai") == 1

    def test_update_policy_sets_updated_at(self):
        import warden.shadow_ai.policy as pol
        p = pol.update_policy("t5", {"mode": "MONITOR"})
        assert p["updated_at"] != ""

    def test_is_allowed_monitor_mode(self):
        import warden.shadow_ai.policy as pol
        # Default = MONITOR → all allowed
        assert pol.is_allowed("huggingface", "t-mon") is True
        assert pol.is_allowed("anything", "t-mon") is True

    def test_is_allowed_block_denylist_mode(self):
        import warden.shadow_ai.policy as pol
        pol.update_policy("t-bl", {"mode": "BLOCK_DENYLIST", "denylist": ["localai"]})
        assert pol.is_allowed("localai", "t-bl") is False
        assert pol.is_allowed("openai", "t-bl") is True

    def test_is_allowed_allowlist_only_mode(self):
        import warden.shadow_ai.policy as pol
        pol.update_policy("t-al", {"mode": "ALLOWLIST_ONLY", "allowlist": ["anthropic"]})
        assert pol.is_allowed("anthropic", "t-al") is True
        assert pol.is_allowed("openai", "t-al") is False

    def test_get_verdict_on_allowlist(self):
        import warden.shadow_ai.policy as pol
        pol.update_policy("tv1", {"allowlist": ["openai"], "mode": "BLOCK_DENYLIST"})
        assert pol.get_verdict("openai", "tv1") == "APPROVED"

    def test_get_verdict_on_denylist_monitor(self):
        import warden.shadow_ai.policy as pol
        pol.update_policy("tv2", {"denylist": ["localai"], "mode": "MONITOR"})
        assert pol.get_verdict("localai", "tv2") == "FLAGGED"

    def test_get_verdict_on_denylist_block(self):
        import warden.shadow_ai.policy as pol
        pol.update_policy("tv3", {"denylist": ["localai"], "mode": "BLOCK_DENYLIST"})
        assert pol.get_verdict("localai", "tv3") == "BLOCKED"

    def test_get_verdict_allowlist_only_unknown(self):
        import warden.shadow_ai.policy as pol
        pol.update_policy("tv4", {"mode": "ALLOWLIST_ONLY", "allowlist": ["openai"]})
        assert pol.get_verdict("unknown-ai", "tv4") == "FLAGGED"

    def test_get_verdict_default_monitor_unknown(self):
        import warden.shadow_ai.policy as pol
        # Unknown provider, MONITOR mode → FLAGGED (not APPROVED)
        verdict = pol.get_verdict("mystery-ai", "tv5")
        assert verdict == "FLAGGED"


# ══════════════════════════════════════════════════════════════════════════════
# billing/addons.py
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def clear_addon_store():
    import warden.billing.addons as addons
    addons._MEMORY_ADDONS.clear()
    yield
    addons._MEMORY_ADDONS.clear()


class TestBillingAddons:
    def test_catalog_has_expected_keys(self):
        from warden.billing.addons import ADDON_CATALOG
        assert "shadow_ai_discovery" in ADDON_CATALOG
        assert "xai_audit" in ADDON_CATALOG
        # master_agent is included in Pro tier — not an add-on

    def test_catalog_has_price_and_tier(self):
        from warden.billing.addons import ADDON_CATALOG
        ai = ADDON_CATALOG["shadow_ai_discovery"]
        assert ai["usd_per_month"] == 15
        assert ai["min_tier"] == "pro"

    def test_grant_and_has_addon(self):
        from warden.billing.addons import grant_addon, has_addon
        grant_addon("t1", "xai_audit")
        assert has_addon("t1", "xai_audit") is True

    def test_has_addon_false_when_not_granted(self):
        from warden.billing.addons import has_addon
        assert has_addon("t-none", "xai_audit") is False

    def test_revoke_addon(self):
        from warden.billing.addons import grant_addon, has_addon, revoke_addon
        grant_addon("t2", "shadow_ai_discovery")
        assert has_addon("t2", "shadow_ai_discovery") is True
        revoke_addon("t2", "shadow_ai_discovery")
        assert has_addon("t2", "shadow_ai_discovery") is False

    def test_revoke_nonexistent_no_error(self):
        from warden.billing.addons import revoke_addon
        revoke_addon("ghost", "xai_audit")  # must not raise

    def test_grant_unknown_addon_raises(self):
        from warden.billing.addons import grant_addon
        with pytest.raises(ValueError, match="Unknown add-on"):
            grant_addon("t3", "nonexistent_addon")

    def test_get_tenant_addons_empty(self):
        from warden.billing.addons import get_tenant_addons
        assert get_tenant_addons("fresh-tenant") == set()

    def test_get_tenant_addons_multiple(self):
        from warden.billing.addons import get_tenant_addons, grant_addon
        grant_addon("t4", "xai_audit")
        grant_addon("t4", "shadow_ai_discovery")
        addons = get_tenant_addons("t4")
        assert "xai_audit" in addons
        assert "shadow_ai_discovery" in addons

    def test_require_addon_or_feature_enterprise_passes(self):
        """Enterprise tier has shadow_ai_enabled natively — no add-on needed."""
        from unittest.mock import MagicMock

        import warden.billing.addons as addons_mod
        from warden.billing.addons import require_addon_or_feature

        dep_factory = require_addon_or_feature(
            feature="shadow_ai_enabled",
            addon_key="shadow_ai_discovery",
            min_tier="pro",
        )
        # dep_factory is a Depends(...) wrapper; get the inner callable
        inner = dep_factory.dependency

        request = MagicMock()
        request.state.tenant = {"tenant_id": "ent-t1", "tier": "enterprise"}
        request.headers.get = MagicMock(return_value=None)

        # Patch _get_tenant_tier to return "enterprise"
        original = addons_mod._get_tenant_tier
        addons_mod._get_tenant_tier = lambda req: "enterprise"
        try:
            gate = inner(request)
            assert gate is not None
        finally:
            addons_mod._get_tenant_tier = original

    def test_require_addon_or_feature_tier_too_low_403(self):
        """Starter tier should get 403."""
        from unittest.mock import MagicMock

        from fastapi import HTTPException

        import warden.billing.addons as addons_mod
        from warden.billing.addons import require_addon_or_feature

        dep_factory = require_addon_or_feature(
            feature="shadow_ai_enabled",
            addon_key="shadow_ai_discovery",
            min_tier="pro",
        )
        inner = dep_factory.dependency

        request = MagicMock()
        request.headers.get = MagicMock(return_value="starter")
        addons_mod._get_tenant_tier = lambda req: "starter"
        try:
            with pytest.raises(HTTPException) as exc_info:
                inner(request)
            assert exc_info.value.status_code == 403
        finally:
            import importlib
            importlib.reload(addons_mod)

    def test_require_addon_or_feature_eligible_but_missing_402(self):
        """Pro tier + no add-on purchased → 402."""
        from unittest.mock import MagicMock

        from fastapi import HTTPException

        import warden.billing.addons as addons_mod
        from warden.billing.addons import require_addon_or_feature

        dep_factory = require_addon_or_feature(
            feature="shadow_ai_enabled",
            addon_key="shadow_ai_discovery",
            min_tier="pro",
        )
        inner = dep_factory.dependency

        request = MagicMock()
        request.state.tenant = {"tenant_id": "pro-t1"}
        request.headers.get = MagicMock(return_value=None)
        addons_mod._get_tenant_tier = lambda req: "pro"
        addons_mod._get_tenant_id_from_request = lambda req: "pro-t1"
        try:
            with pytest.raises(HTTPException) as exc_info:
                inner(request)
            assert exc_info.value.status_code == 402
        finally:
            import importlib
            importlib.reload(addons_mod)


# ══════════════════════════════════════════════════════════════════════════════
# agentic/mandate.py
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def clear_invoices():
    import warden.agentic.mandate as m
    m._invoices.clear()
    yield
    m._invoices.clear()


_ACTIVE_AGENT = {
    "agent_id":      "agent-001",
    "status":        "active",
    "max_per_item":  50.0,
    "monthly_budget": 200.0,
    "_monthly_spend": 0.0,
}


class TestMandate:
    def _make_mandate(self, invoice_hash, sku, amount, agent_id="agent-001", currency="USD"):
        sig = _sign_mandate(invoice_hash, sku, amount, agent_id)
        return {
            "invoice_hash": invoice_hash,
            "sku": sku,
            "amount": amount,
            "currency": currency,
            "agent_id": agent_id,
            "signature": sig,
        }

    def test_create_invoice_returns_hash(self):
        from warden.agentic.mandate import create_invoice
        inv = create_invoice("sku-pro", 9.99, "agent-001")
        assert len(inv["invoice_hash"]) == 64
        assert inv["sku"] == "sku-pro"
        assert inv["price"] == 9.99

    def test_validate_mandate_happy_path(self):
        from warden.agentic.mandate import create_invoice, validate_mandate
        inv = create_invoice("sku-pro", 9.99, "agent-001")
        mandate = self._make_mandate(inv["invoice_hash"], "sku-pro", 9.99)
        result = validate_mandate(mandate, _ACTIVE_AGENT)
        assert result.valid is True
        assert result.transaction_id != ""

    def test_validate_mandate_one_time_use(self):
        from warden.agentic.mandate import create_invoice, validate_mandate
        inv = create_invoice("sku-x", 5.0, "agent-001")
        mandate = self._make_mandate(inv["invoice_hash"], "sku-x", 5.0)
        r1 = validate_mandate(mandate, _ACTIVE_AGENT)
        r2 = validate_mandate(mandate, _ACTIVE_AGENT)
        assert r1.valid is True
        assert r2.valid is False
        assert "not found" in r2.reason.lower() or "expired" in r2.reason.lower()

    def test_validate_mandate_inactive_agent(self):
        from warden.agentic.mandate import create_invoice, validate_mandate
        inv = create_invoice("sku-y", 5.0, "agent-002")
        agent = {**_ACTIVE_AGENT, "agent_id": "agent-002", "status": "revoked"}
        mandate = self._make_mandate(inv["invoice_hash"], "sku-y", 5.0, agent_id="agent-002")
        result = validate_mandate(mandate, agent)
        assert result.valid is False
        assert "revoked" in result.reason.lower()

    def test_validate_mandate_missing_invoice_hash(self):
        from warden.agentic.mandate import validate_mandate
        # Missing invoice_hash is caught before HMAC check
        mandate = {"sku": "x", "amount": 1.0, "currency": "USD", "agent_id": "a", "signature": ""}
        result = validate_mandate(mandate, _ACTIVE_AGENT)
        assert result.valid is False
        assert "invoice_hash" in result.reason.lower()

    def test_validate_mandate_negative_amount(self):
        from warden.agentic.mandate import create_invoice, validate_mandate
        inv = create_invoice("sku-z", 5.0, "agent-001")
        # Negative amount caught before HMAC
        mandate = {
            "invoice_hash": inv["invoice_hash"],
            "sku": "sku-z",
            "amount": -1.0,
            "currency": "USD",
            "agent_id": "agent-001",
            "signature": "",
        }
        result = validate_mandate(mandate, _ACTIVE_AGENT)
        assert result.valid is False
        assert "non-negative" in result.reason.lower()

    def test_validate_mandate_exceeds_invoice_price(self):
        from warden.agentic.mandate import create_invoice, validate_mandate
        inv = create_invoice("sku-q", 5.0, "agent-001")
        mandate = self._make_mandate(inv["invoice_hash"], "sku-q", 10.0)
        result = validate_mandate(mandate, _ACTIVE_AGENT)
        assert result.valid is False
        assert "invoice price" in result.reason.lower()

    def test_validate_mandate_exceeds_per_item_limit(self):
        from warden.agentic.mandate import create_invoice, validate_mandate
        inv = create_invoice("sku-r", 100.0, "agent-001")
        agent = {**_ACTIVE_AGENT, "max_per_item": 10.0}
        mandate = self._make_mandate(inv["invoice_hash"], "sku-r", 100.0)
        result = validate_mandate(mandate, agent)
        assert result.valid is False
        assert "per-item limit" in result.reason.lower()

    def test_validate_mandate_exceeds_monthly_budget(self):
        from warden.agentic.mandate import create_invoice, validate_mandate
        inv = create_invoice("sku-s", 60.0, "agent-001")
        agent = {**_ACTIVE_AGENT, "max_per_item": 0.0, "monthly_budget": 50.0, "_monthly_spend": 40.0}
        mandate = self._make_mandate(inv["invoice_hash"], "sku-s", 60.0)
        result = validate_mandate(mandate, agent)
        assert result.valid is False
        assert "budget exhausted" in result.reason.lower()

    def test_validate_mandate_sku_mismatch(self):
        from warden.agentic.mandate import create_invoice, validate_mandate
        inv = create_invoice("sku-original", 5.0, "agent-001")
        # Sign with tampered sku so HMAC passes, but invoice sku won't match
        mandate = self._make_mandate(inv["invoice_hash"], "sku-tampered", 5.0)
        result = validate_mandate(mandate, _ACTIVE_AGENT)
        assert result.valid is False
        assert "sku mismatch" in result.reason.lower()

    def test_validate_mandate_agent_mismatch(self):
        from warden.agentic.mandate import create_invoice, validate_mandate
        inv = create_invoice("sku-t", 5.0, "agent-001")
        different_agent = {**_ACTIVE_AGENT, "agent_id": "agent-DIFFERENT"}
        # Sign with mandate's agent_id; invoice was created for agent-001
        mandate = self._make_mandate(inv["invoice_hash"], "sku-t", 5.0, agent_id="agent-001")
        result = validate_mandate(mandate, different_agent)
        assert result.valid is False
        assert "mismatch" in result.reason.lower()

    def test_validate_mandate_expired_invoice(self):
        from warden.agentic.mandate import create_invoice, validate_mandate
        inv = create_invoice("sku-u", 5.0, "agent-001", ttl_seconds=0)
        time.sleep(0.01)
        mandate = self._make_mandate(inv["invoice_hash"], "sku-u", 5.0)
        result = validate_mandate(mandate, _ACTIVE_AGENT)
        assert result.valid is False


# ══════════════════════════════════════════════════════════════════════════════
# agentic/registry.py
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture()
def reg(tmp_path):
    from warden.agentic.registry import AgentRegistry
    db = tmp_path / "test_registry.db"
    r = AgentRegistry(db_path=db)
    yield r
    r.close()


class TestAgentRegistry:
    def test_register_and_get_agent(self, reg):
        agent = reg.register_agent(
            tenant_id="t1",
            name="TestBot",
            provider="anthropic",
            max_per_item=25.0,
            monthly_budget=100.0,
        )
        assert agent["name"] == "TestBot"
        assert agent["status"] == "active"
        assert agent["max_per_item"] == 25.0
        assert agent["monthly_budget"] == 100.0
        assert agent["provider"] == "anthropic"

    def test_get_agent_missing(self, reg):
        assert reg.get_agent("nonexistent-uuid") is None

    def test_get_agents_for_tenant(self, reg):
        reg.register_agent("t2", "Bot1")
        reg.register_agent("t2", "Bot2")
        reg.register_agent("t3", "OtherBot")
        agents = reg.get_agents("t2")
        assert len(agents) == 2
        names = {a["name"] for a in agents}
        assert names == {"Bot1", "Bot2"}

    def test_get_agents_empty_tenant(self, reg):
        assert reg.get_agents("nobody") == []

    def test_update_agent(self, reg):
        agent = reg.register_agent("t4", "OldName")
        updated = reg.update_agent(agent["agent_id"], name="NewName", max_per_item=99.0)
        assert updated["name"] == "NewName"
        assert updated["max_per_item"] == 99.0

    def test_update_agent_no_fields_returns_current(self, reg):
        agent = reg.register_agent("t5", "Stable")
        same = reg.update_agent(agent["agent_id"])
        assert same["agent_id"] == agent["agent_id"]

    def test_update_agent_allowed_categories(self, reg):
        agent = reg.register_agent("t6", "CatBot")
        updated = reg.update_agent(agent["agent_id"], allowed_categories=["payments", "booking"])
        assert "payments" in updated["allowed_categories"]

    def test_update_agent_require_confirmation(self, reg):
        agent = reg.register_agent("t7", "ConfBot")
        updated = reg.update_agent(agent["agent_id"], require_confirmation=True)
        assert updated["require_confirmation"] is True

    def test_revoke_agent(self, reg):
        agent = reg.register_agent("t8", "Revokable")
        ok = reg.revoke_agent(agent["agent_id"])
        assert ok is True
        fetched = reg.get_agent(agent["agent_id"])
        assert fetched["status"] == "revoked"

    def test_revoke_agent_nonexistent(self, reg):
        ok = reg.revoke_agent("does-not-exist")
        assert ok is False

    def test_revoke_all(self, reg):
        reg.register_agent("t9", "A")
        reg.register_agent("t9", "B")
        reg.register_agent("t9", "C")
        count = reg.revoke_all("t9")
        assert count == 3
        agents = reg.get_agents("t9")
        for a in agents:
            assert a["status"] == "revoked"

    def test_revoke_all_only_active(self, reg):
        a1 = reg.register_agent("t10", "A1")
        reg.register_agent("t10", "A2")
        reg.revoke_agent(a1["agent_id"])
        count = reg.revoke_all("t10")
        assert count == 1

    def test_log_and_get_activity(self, reg):
        agent = reg.register_agent("t11", "Logger")
        reg.log_activity(
            tenant_id="t11",
            agent_id=agent["agent_id"],
            action="execute_mandate",
            sku="pro-plan",
            amount=9.99,
            currency="USD",
            status="approved",
            transaction_id="txn-123",
        )
        logs = reg.get_activity("t11")
        assert len(logs) == 1
        assert logs[0]["sku"] == "pro-plan"
        assert logs[0]["status"] == "approved"

    def test_get_activity_filter_by_agent(self, reg):
        a1 = reg.register_agent("t12", "A1")
        a2 = reg.register_agent("t12", "A2")
        reg.log_activity("t12", a1["agent_id"], "exec", "sku-1", 1.0, "USD", "approved")
        reg.log_activity("t12", a2["agent_id"], "exec", "sku-2", 2.0, "USD", "approved")
        logs = reg.get_activity("t12", agent_id=a1["agent_id"])
        assert len(logs) == 1
        assert logs[0]["agent_id"] == a1["agent_id"]

    def test_get_monthly_spend(self, reg):
        agent = reg.register_agent("t13", "Spender")
        reg.log_activity("t13", agent["agent_id"], "exec", "sku", 10.0, "USD", "approved")
        reg.log_activity("t13", agent["agent_id"], "exec", "sku", 5.0, "USD", "approved")
        reg.log_activity("t13", agent["agent_id"], "exec", "sku", 3.0, "USD", "rejected")
        spend = reg.get_monthly_spend(agent["agent_id"])
        assert abs(spend - 15.0) < 0.01  # only approved

    def test_get_monthly_spend_no_activity(self, reg):
        agent = reg.register_agent("t14", "Fresh")
        spend = reg.get_monthly_spend(agent["agent_id"])
        assert spend == 0.0

    def test_allowed_categories_parsed_from_json(self, reg):
        agent = reg.register_agent(
            "t15", "CatAgent",
            allowed_categories=["finance", "legal"],
        )
        fetched = reg.get_agent(agent["agent_id"])
        assert isinstance(fetched["allowed_categories"], list)
        assert "finance" in fetched["allowed_categories"]
