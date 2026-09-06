"""
warden/tests/test_agent_commerce_agent.py
──────────────────────────────────────────
PR-8: CommerceAgent sub-agent + /agent/sova/commerce/negotiate co-pilot.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    os.environ["COMMERCE_DB_PATH"] = str(tmp_path_factory.mktemp("cc") / "c.db")
    from warden.main import app
    with TestClient(app) as c:
        yield c


def test_commerce_subagent_defined():
    from warden.agent.master import _AGENT_PROMPTS, _AGENT_TOOLS, SubAgent
    assert SubAgent.COMMERCE in _AGENT_TOOLS
    assert SubAgent.COMMERCE in _AGENT_PROMPTS
    tools = _AGENT_TOOLS[SubAgent.COMMERCE]
    assert "reconcile_orders" in tools
    assert "revoke_mandate" in tools          # approval-gated
    assert "approve_purchase_intent" in tools


def test_commerce_subagent_mutating_tools_are_gated():
    from warden.agent import tools as t
    from warden.agent.master import _AGENT_TOOLS, SubAgent
    gated = {n for n in _AGENT_TOOLS[SubAgent.COMMERCE] if n in t.OPERATOR_TOOLS}
    assert gated == {"revoke_mandate", "approve_purchase_intent"}
    handlers = t.handlers_for(operator=True, auto_approve=False)
    assert handlers["revoke_mandate"].__name__ == "gated_revoke_mandate"


def test_negotiate_needs_pro(client):
    r = client.post("/agent/sova/commerce/negotiate",
                    json={"request": "buy 1TB object storage under $40"},
                    headers={"X-Tenant-Tier": "community_business"})
    assert r.status_code == 403


def test_negotiate_runs_without_api_keys(client, monkeypatch):
    # No LLM keys → connectors return no proposals; endpoint still ranks + returns.
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    r = client.post("/agent/sova/commerce/negotiate",
                    json={"request": "buy 1TB object storage under $40", "budget_usd": 40},
                    headers={"X-Tenant-Tier": "pro"})
    assert r.status_code == 200
    body = r.json()
    assert body["settlement"] == "not_performed"
    assert "auction_id" in body and len(body["auction_id"]) > 8
    assert "ranked" in body
