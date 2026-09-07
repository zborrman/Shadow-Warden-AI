"""
warden/tests/test_agent_commerce_agent.py
──────────────────────────────────────────
PR-8 — CommerceAgent sub-agent, the approval-gated commerce mutators, and the
supervised negotiation endpoint (which must never settle anything).
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.api.agent import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ── Sub-agent registration ───────────────────────────────────────────────────

def test_commerce_subagent_registered():
    from warden.agent.master import _AGENT_PROMPTS, _AGENT_TOOLS, SubAgent
    assert SubAgent.COMMERCE in _AGENT_TOOLS
    assert SubAgent.COMMERCE in _AGENT_PROMPTS
    assert "reconcile_orders" in _AGENT_TOOLS[SubAgent.COMMERCE]


def test_every_subagent_has_tools_and_a_prompt():
    from warden.agent.master import _AGENT_PROMPTS, _AGENT_TOOLS, SubAgent
    assert set(_AGENT_TOOLS) == set(SubAgent)
    assert set(_AGENT_PROMPTS) == set(SubAgent)


def test_subagent_tools_all_exist():
    from warden.agent import tools as t
    from warden.agent.master import _AGENT_TOOLS
    for agent, names in _AGENT_TOOLS.items():
        unknown = [n for n in names if n not in t.TOOL_HANDLERS]
        assert not unknown, f"{agent}: unknown tools {unknown}"


def test_data_privacy_tools_now_exist():
    """AG-23 listed 7 tools that were never implemented; the allowlist
    intersection dropped them, leaving the agent 4 of its 11 advertised tools."""
    from warden.agent import tools as t
    for name in ("get_gdpr_export", "run_gdpr_purge", "get_retention_policy",
                 "run_retention_enforce", "list_secrets_inventory",
                 "get_secrets_report", "get_compliance_posture"):
        assert name in t.TOOL_HANDLERS
        assert name in {d["name"] for d in t.TOOLS}


def test_destructive_privacy_tools_are_gated():
    from warden.agent import tools as t
    assert "run_gdpr_purge" in t.OPERATOR_TOOLS
    assert "run_retention_enforce" in t.OPERATOR_TOOLS
    assert "get_gdpr_export" not in t.OPERATOR_TOOLS


def test_decompose_choices_track_the_enum():
    """data_privacy was hand-omitted from both prompts, so it was never routed to."""
    from warden.agent.master import _AGENT_CHOICES, SubAgent
    for a in SubAgent:
        assert f'"{a.value}"' in _AGENT_CHOICES


# ── Commerce mutators are approval-gated ─────────────────────────────────────

def test_commerce_mutators_are_gated():
    from warden.agent import tools as t
    for name in ("revoke_mandate", "approve_purchase_intent"):
        assert name in t.OPERATOR_TOOLS, f"{name} must require approval"
        assert name in t.TOOL_HANDLERS


def test_commerce_read_tools_are_not_gated():
    from warden.agent import tools as t
    for name in ("list_mandates", "list_commerce_orders", "list_commerce_auctions",
                 "reconcile_orders", "get_spend_summary"):
        assert name in t.TOOL_HANDLERS
        assert name not in t.OPERATOR_TOOLS


def test_commerce_agent_read_surface_excludes_mutators():
    """Without operator approval the CommerceAgent can look but not touch."""
    from warden.agent import tools as t
    read_only = {d["name"] for d in t.tools_for(operator=False)}
    assert "revoke_mandate" not in read_only
    assert "reconcile_orders" in read_only


@pytest.mark.asyncio
async def test_revoke_mandate_returns_token_not_execution(monkeypatch):
    from warden.agent import approval
    from warden.agent import tools as t
    from warden.tests.test_agent_hardening import _MemRedis
    monkeypatch.setattr(approval, "_redis", lambda: _MemRedis({}))

    called = {"n": 0}

    async def _fake(**_kw):
        called["n"] += 1
        return {"revoked": True}

    monkeypatch.setitem(t.TOOL_HANDLERS, "revoke_mandate", _fake)
    out = await t.traced_dispatch(
        "revoke_mandate", {"tenant_id": "acme", "mandate_id": "m1"})
    assert out["status"] == "approval_required"
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_approve_purchase_intent_rejects_bad_action():
    from warden.agent import tools as t
    out = await t.approve_purchase_intent(workflow_id="w1", action="delete")
    assert "error" in out


# ── Auction risk enrichment ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrichment_is_written_where_it_is_persisted(monkeypatch):
    """Only p.raw is persisted; setting p.risk alone stored the bidder's own score."""
    from warden.business_community.agentic_commerce.multi_agent.connectors import AgentProposal
    from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
        MultiAgentOrchestrator,
    )
    p = AgentProposal("claude", {"recommended_vendor": "acme-corp",
                                 "estimated_price_usd": 100, "risk_score": 0.1})
    monkeypatch.setattr("warden.communities.supplier_risk.assess_supplier",
                        lambda _t, _v: {"composite_score": 0.9})

    out = await MultiAgentOrchestrator()._enrich_with_risk("acme", [p])
    assert out[0].risk == 0.9
    assert out[0].raw["risk_score"] == 0.9        # what actually gets stored
    assert out[0].raw["risk_source"] == "supplier_risk"


@pytest.mark.asyncio
async def test_unassessed_risk_is_labelled_self_reported(monkeypatch):
    from warden.business_community.agentic_commerce.multi_agent.connectors import AgentProposal
    from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
        MultiAgentOrchestrator,
    )
    p = AgentProposal("gpt", {"recommended_vendor": "", "risk_score": 0.05})
    out = await MultiAgentOrchestrator()._enrich_with_risk("acme", [p])
    assert out[0].raw["risk_source"] == "self_reported"


# ── Negotiation endpoint ─────────────────────────────────────────────────────

def test_negotiate_requires_pro():
    r = _client().post("/agent/sova/commerce/negotiate",
                       json={"purchase_request": "50 laptops"},
                       headers={"X-Tenant-Tier": "community_business"})
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "feature_gated"


def test_negotiate_gated_for_starter():
    r = _client().post("/agent/sova/commerce/negotiate",
                       json={"purchase_request": "50 laptops"})
    assert r.status_code == 403


def test_negotiate_never_settles(monkeypatch):
    r = _client().post("/agent/sova/commerce/negotiate",
                       json={"purchase_request": "50 laptops", "budget_usd": 50000},
                       headers={"X-Tenant-Tier": "pro"})
    assert r.status_code == 200
    body = r.json()
    assert body["settled"] is False
    assert "nothing was purchased" in body["note"]
    assert "auction_id" in body


def test_negotiate_ignores_body_tenant_id(monkeypatch):
    """tenant_id is bound from the API key — a body field must not redirect it."""
    seen: dict = {}

    async def _fake_auction(self, tenant_id, purchase_request, budget_usd=None):
        seen["tenant_id"] = tenant_id
        return "auction-1"

    monkeypatch.setattr(
        "warden.business_community.agentic_commerce.multi_agent.orchestrator."
        "MultiAgentOrchestrator.run_auction", _fake_auction)
    monkeypatch.setattr(
        "warden.business_community.agentic_commerce.multi_agent.orchestrator."
        "MultiAgentOrchestrator.get_auction", lambda self, a, t: {"proposals": []})

    r = _client().post("/agent/sova/commerce/negotiate",
                       json={"purchase_request": "x", "tenant_id": "victim-tenant"},
                       headers={"X-Tenant-Tier": "pro"})
    assert r.status_code == 200
    assert seen["tenant_id"] != "victim-tenant"
