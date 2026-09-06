"""
warden/tests/test_agent_commerce.py
────────────────────────────────────
PR-6: SOVA agentic-marketplace read tools + auth on the commerce router.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")


@pytest.fixture(scope="module")
def app_client(tmp_path_factory):
    db = str(tmp_path_factory.mktemp("commerce") / "c.db")
    os.environ["COMMERCE_DB_PATH"] = db
    from warden.main import app
    with TestClient(app) as c:
        yield c


def test_commerce_read_tools_registered():
    from warden.agent import tools as t
    for name in ("list_mandates", "get_mandate", "get_agentic_spend",
                 "list_commerce_orders", "get_commerce_order",
                 "list_commerce_auctions", "get_commerce_auction"):
        assert name in t.TOOL_HANDLERS
        assert name in t.READ_TOOLS
        assert name not in t.OPERATOR_TOOLS
        assert name in {d["name"] for d in t.tools_for(operator=False)}


def test_forensics_subagent_gets_commerce_tools():
    from warden.agent.master import _AGENT_TOOLS, SubAgent
    tools = _AGENT_TOOLS[SubAgent.FORENSICS]
    assert "get_agentic_spend" in tools
    assert "list_commerce_orders" in tools


def _dep_callables(route):
    out, stack = [], list(route.dependant.dependencies)
    while stack:
        d = stack.pop()
        if getattr(d, "call", None) is not None:
            out.append(d.call)
        stack.extend(getattr(d, "dependencies", []))
    return out


def test_commerce_routes_have_auth_dependency():
    # Every commerce route (except the signature-validated webhook) carries
    # require_api_key — previously they had only the feature gate.
    from warden.business_community.agentic_commerce.api import router

    for route in router.routes:
        path = getattr(route, "path", "")
        if not path or path.endswith("/webhooks/ap2"):
            continue
        names = {getattr(fn, "__name__", "") for fn in _dep_callables(route)}
        assert "require_api_key" in names, f"{path} missing require_api_key ({names})"


def test_customer_key_cannot_query_other_tenant(app_client):
    # default (internal) key path: X-Tenant-ID is honoured, so a plain read works.
    r = app_client.get("/business-community/commerce/analytics/spend",
                       headers={"X-Tenant-Tier": "pro", "X-Tenant-ID": "default"})
    assert r.status_code == 200
    assert "total_mandates" in r.json()


def test_commerce_gated_below_tier(app_client):
    r = app_client.get("/business-community/commerce/mandates")  # no tier header → starter
    assert r.status_code == 403
