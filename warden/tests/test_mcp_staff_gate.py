"""
warden/tests/test_mcp_staff_gate.py

The paid MCP tools are the one path to the Digital Staff handlers that a stranger
can reach, and until this change it was the one path with no gate at all:
`warden/mcp/gateway.py` ran `STAFF_TOOL_HANDLERS[tool_name](**arguments)`
directly. No authorization boundary, no velocity guard, no GSAM quarantine, no
SAC screen — the hole Phase 7 closed for MasterAgent (CLAUDE.md, "One gate for
every agentic tool call"), found again by CodeRabbit on #439 and deferred then
because it needed a boundary decision for callers nobody had registered.

The decision: each caller becomes a principal `mcp:<agent_id>` whose boundary is
exactly the set this gateway already offers. No legitimate call is newly
refused, and every gate STAFF-01/02 requires now runs.

These tests execute the gateway rather than reading it. The last one reads the
source, because the regression it guards is a line of code coming back.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("X402_GATE_ENABLED", "false")

from fastapi.testclient import TestClient  # noqa: E402

_TOOL = "screen_sanctions_list"
_ARGS = {"subject_name": "Acme Corp", "list_name": "OFAC_SDN"}
# X402_GATE_ENABLED=false makes _check_payment return "dev" for every caller.
_PRINCIPAL = "mcp:dev"


def _call(client: TestClient) -> dict:
    r = client.post("/mcp/", json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": _TOOL, "arguments": _ARGS},
    })
    assert r.status_code == 200
    return r.json()["result"]


@pytest.fixture()
def client():
    from warden.main import app
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def handler_spy(monkeypatch):
    from warden.staff import tools as staff_tools

    calls: list[dict] = []

    async def spy(**kwargs):
        calls.append(kwargs)
        return {"hit": False}

    monkeypatch.setitem(staff_tools.STAFF_TOOL_HANDLERS, _TOOL, spy)
    return calls


@pytest.fixture()
def clean_boundary():
    from warden.staff.boundaries import get_registry

    reg = get_registry()
    reg._local.pop(_PRINCIPAL, None)
    yield reg
    reg._local.pop(_PRINCIPAL, None)


def test_a_paid_call_runs_as_a_namespaced_principal(client, handler_spy, clean_boundary, monkeypatch):
    seen: list[str] = []
    from warden.mcp import gateway

    real = gateway.staff_dispatch

    async def recording(agent_id, tool_name, tool_input, *a, **k):
        seen.append(agent_id)
        return await real(agent_id, tool_name, tool_input, *a, **k)

    monkeypatch.setattr(gateway, "staff_dispatch", recording)
    result = _call(client)

    assert result["isError"] is False
    assert seen == [_PRINCIPAL], "the call did not pass through staff_dispatch"
    assert handler_spy, "the tool never ran"


def test_the_boundary_is_exactly_what_the_gateway_offers(client, handler_spy, clean_boundary):
    from warden.mcp.pricing import MCP_EXPOSED_TOOLS
    from warden.staff.boundaries import AgentRole

    _call(client)
    b = clean_boundary.get(_PRINCIPAL)
    assert b is not None, "no boundary was created for the caller"
    assert b.role == AgentRole.MCP_CLIENT
    assert b.allowed_tools == MCP_EXPOSED_TOOLS
    assert b.refund_cap_usd == 0


def test_a_quarantined_caller_is_refused_and_the_tool_never_runs(client, handler_spy, clean_boundary, monkeypatch):
    import warden.gsam.quarantine as q

    monkeypatch.setattr(q, "is_quarantined", lambda agent_id, redis=None: agent_id == _PRINCIPAL)
    result = _call(client)

    assert result["isError"] is True
    assert "agent_quarantined" in result["content"][0]["text"]
    assert handler_spy == [], "a quarantined caller reached the handler"


def test_a_suspended_caller_is_refused_and_the_tool_never_runs(client, handler_spy, clean_boundary):
    import dataclasses

    _call(client)                                   # creates the boundary
    handler_spy.clear()
    b = clean_boundary.get(_PRINCIPAL)
    clean_boundary.put(dataclasses.replace(b, suspended=True))

    result = _call(client)
    assert result["isError"] is True
    assert "boundary" in result["content"][0]["text"].lower()
    assert handler_spy == [], "a suspended caller reached the handler"


def test_the_gateway_never_indexes_the_staff_handlers_directly():
    src = (Path(__file__).resolve().parents[1] / "mcp" / "gateway.py").read_text(encoding="utf-8")
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"STAFF_TOOL_HANDLERS\s*\[", code), (
        "gateway.py dispatches a staff tool by indexing STAFF_TOOL_HANDLERS — "
        "that skips boundary, velocity, quarantine and SAC; use staff_dispatch()"
    )
