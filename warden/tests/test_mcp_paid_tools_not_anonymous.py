"""
warden/tests/test_mcp_paid_tools_not_anonymous.py

The payment gate (`X402_GATE_ENABLED`) is a posture flag and is off in
production. Off used to mean every caller passed as `dev`: the twelve priced
staff tools were listed to, and executed for, anyone on the internet, free.
A harmless `get_ticket` call against production confirmed it (audit S-1).

Off now means the paid tools are an operator surface. These tests run the
gateway with authentication ON, which the rest of the suite does not, because
the defect was only visible to a caller without a key.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("REDIS_URL", "memory://")

from fastapi.testclient import TestClient  # noqa: E402

from warden.mcp.pricing import MCP_EXPOSED_TOOLS  # noqa: E402
from warden.mcp.product_tools import FREE_TOOLS  # noqa: E402

_KEY = "test-operator-key-0123456789"


def _rpc(method: str, params: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": 7, "method": method, "params": params or {}}


@pytest.fixture()
def client(monkeypatch):
    """A gateway that requires an API key, payment gate off: the production posture."""
    from warden import auth_guard
    from warden.main import app

    monkeypatch.setattr(auth_guard, "_VALID_KEY", _KEY)
    monkeypatch.setattr(auth_guard, "_KEYS_PATH", "")
    monkeypatch.setenv("X402_GATE_ENABLED", "false")
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def handler_spy(monkeypatch):
    from warden.staff import tools as staff_tools

    calls: list[str] = []
    for name in MCP_EXPOSED_TOOLS:
        async def _spy(_name=name, **_kwargs):
            calls.append(_name)
            return {"ok": True}

        monkeypatch.setitem(staff_tools.STAFF_TOOL_HANDLERS, name, _spy)
    return calls


def _names(response) -> set[str]:
    return {t["name"] for t in response.json()["result"]["tools"]}


def test_a_stranger_is_not_offered_the_paid_tools(client):
    assert _names(client.post("/mcp/", json=_rpc("tools/list"))) == set(FREE_TOOLS)


@pytest.mark.parametrize("tool", sorted(MCP_EXPOSED_TOOLS))
def test_a_stranger_cannot_run_a_paid_tool(client, handler_spy, tool):
    r = client.post("/mcp/", json=_rpc("tools/call", {"name": tool, "arguments": {}}))
    body = r.json()
    assert "result" not in body
    assert body["error"]["code"] == -32601
    assert body["id"] == 7
    assert handler_spy == []


def test_a_wrong_key_is_a_stranger(client, handler_spy):
    r = client.post(
        "/mcp/",
        json=_rpc("tools/call", {"name": "get_ticket", "arguments": {"ticket_id": "T-1"}}),
        headers={"X-API-Key": "not-the-key"},
    )
    assert "error" in r.json()
    assert handler_spy == []


def test_the_refusal_does_not_say_the_tool_exists(client):
    """A stranger learns nothing that a made-up tool name would not also tell them."""
    real = client.post("/mcp/", json=_rpc("tools/call", {"name": "get_ticket", "arguments": {}}))
    fake = client.post("/mcp/", json=_rpc("tools/call", {"name": "no_such_tool", "arguments": {}}))
    assert real.json()["error"]["code"] == fake.json()["error"]["code"]
    assert real.json()["error"]["message"].replace("get_ticket", "X") == (
        fake.json()["error"]["message"].replace("no_such_tool", "X")
    )


def test_an_operator_key_still_reaches_the_paid_tools(client, handler_spy):
    headers = {"X-API-Key": _KEY}
    assert _names(client.post("/mcp/", json=_rpc("tools/list"), headers=headers)) == (
        set(FREE_TOOLS) | set(MCP_EXPOSED_TOOLS)
    )
    r = client.post(
        "/mcp/",
        json=_rpc("tools/call", {"name": "get_ticket", "arguments": {"ticket_id": "T-1"}}),
        headers=headers,
    )
    assert r.json()["result"]["isError"] is False
    assert handler_spy == ["get_ticket"]


def test_free_tools_stay_open_to_a_stranger(client):
    r = client.post("/mcp/", json=_rpc("tools/call", {"name": "list_pricing", "arguments": {}}))
    assert r.json()["result"]["isError"] is False


def test_discovery_counts_only_what_a_stranger_can_call(client):
    assert client.get("/mcp/").json()["tools_count"] == len(FREE_TOOLS)
