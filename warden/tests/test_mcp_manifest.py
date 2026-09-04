"""
warden/tests/test_mcp_manifest.py — the MCP manifest describes the real server.

A readiness audit (2026-09-02) reported "MCP mentioned on site but no standard
manifest endpoint found". `/.well-known/mcp.json` did exist on the gateway; it
was simply unreachable from the site host, and what it said was wrong in three
ways an automated client cannot recover from:

  * it advertised protocol "2025-11-05" — not a revision that has ever existed,
    so a client matching it against its own list found nothing;
  * it never named a transport;
  * it listed only the paid staff tools, so a client connecting in order to use
    a security gateway found no tool that filters anything.

The descriptor is generated, so it cannot drift from the tool tables. What it
*can* drift from is the gateway's own behaviour — the version it negotiates, the
tools it will actually run, whether a tool is free. These tests hold the two
together.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.api.discovery import router as discovery_router
from warden.discovery.well_known import build_mcp_descriptor
from warden.mcp.gateway import SUPPORTED_PROTOCOL_VERSIONS, negotiate_version
from warden.mcp.gateway import router as mcp_router
from warden.mcp.pricing import MCP_EXPOSED_TOOLS
from warden.mcp.product_tools import (
    FREE_TOOLS,
    PRODUCT_TOOL_HANDLERS,
    PRODUCT_TOOL_SCHEMAS,
)

#: Every MCP revision that has ever been published. A version string outside
#: this set is a typo, and a typo here is invisible until a client gives up.
REAL_MCP_REVISIONS = frozenset(
    {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"}
)


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(mcp_router)
    app.include_router(discovery_router)
    return TestClient(app, raise_server_exceptions=False)


def _rpc(method: str, params: dict | None = None, rid: int = 1) -> dict:
    body: dict = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    return body


# ── Versions ─────────────────────────────────────────────────────────────────


class TestProtocolVersions:
    def test_every_advertised_version_is_a_real_revision(self):
        unknown = set(SUPPORTED_PROTOCOL_VERSIONS) - REAL_MCP_REVISIONS
        assert not unknown, f"advertising revisions that do not exist: {sorted(unknown)}"

    def test_the_newest_is_listed_first(self):
        assert list(SUPPORTED_PROTOCOL_VERSIONS) == sorted(
            SUPPORTED_PROTOCOL_VERSIONS, reverse=True
        )

    def test_a_revision_we_do_not_implement_is_not_claimed(self):
        """
        2026-07-28 replaced the initialize handshake with per-request `_meta`
        negotiation and a mandatory `server/discover`. This endpoint implements
        neither, so it must not appear in the supported list.
        """
        assert "2026-07-28" not in SUPPORTED_PROTOCOL_VERSIONS

    def test_a_supported_request_is_echoed(self):
        for version in SUPPORTED_PROTOCOL_VERSIONS:
            assert negotiate_version(version) == version

    def test_an_unknown_request_gets_the_newest_supported(self):
        assert negotiate_version("1999-01-01") == SUPPORTED_PROTOCOL_VERSIONS[0]
        assert negotiate_version(None) == SUPPORTED_PROTOCOL_VERSIONS[0]

    def test_the_manifest_and_the_endpoint_name_the_same_version(self, client):
        doc = build_mcp_descriptor()
        assert doc["schema_version"] == SUPPORTED_PROTOCOL_VERSIONS[0]
        assert doc["protocol"] == f"MCP/{SUPPORTED_PROTOCOL_VERSIONS[0]}"
        assert doc["protocol_versions"] == list(SUPPORTED_PROTOCOL_VERSIONS)
        assert client.get("/mcp/").json()["protocol"] == doc["schema_version"]

    def test_every_response_carries_the_version_header(self, client):
        response = client.post("/mcp/", json=_rpc("ping"))
        assert response.headers["MCP-Protocol-Version"] in SUPPORTED_PROTOCOL_VERSIONS


# ── The descriptor ───────────────────────────────────────────────────────────


class TestDescriptor:
    def test_it_names_its_transport(self):
        """Without this a client does not know how to speak to the endpoint."""
        assert build_mcp_descriptor()["transport"] == "streamable-http"

    def test_the_url_is_the_endpoint_that_answers(self, client):
        assert build_mcp_descriptor()["url"].endswith("/mcp/")

    def test_it_lists_every_callable_tool(self):
        listed = {t["name"] for t in build_mcp_descriptor()["tools"]}
        assert listed == set(MCP_EXPOSED_TOOLS) | set(FREE_TOOLS)

    def test_the_free_tools_are_priced_at_zero_and_named_as_free(self):
        doc = build_mcp_descriptor()
        prices = {t["name"]: t["price_usd"] for t in doc["tools"]}
        for name in FREE_TOOLS:
            assert prices[name] == "0"
        assert set(doc["payment"]["free_tools"]) == set(FREE_TOOLS)

    def test_no_paid_tool_is_priced_at_zero(self):
        """A $0 price on a gated tool reads as free and is not."""
        doc = build_mcp_descriptor()
        for tool in doc["tools"]:
            if tool["name"] in FREE_TOOLS:
                continue
            assert float(tool["price_usd"]) > 0, f"{tool['name']} advertises $0 but is gated"

    def test_it_points_at_documentation_a_human_can_read(self):
        assert build_mcp_descriptor()["documentation"].endswith("/mcp")

    def test_it_is_served_at_the_well_known_path(self, client):
        response = client.get("/.well-known/mcp.json")
        assert response.status_code == 200
        assert response.json()["url"] == build_mcp_descriptor()["url"]


# ── The product tools ────────────────────────────────────────────────────────


class TestProductTools:
    def test_every_free_tool_has_a_schema_and_a_handler(self):
        schemas = {t["name"] for t in PRODUCT_TOOL_SCHEMAS}
        assert schemas == set(FREE_TOOLS) == set(PRODUCT_TOOL_HANDLERS)

    def test_no_free_tool_collides_with_a_paid_one(self):
        """A name in both sets would decide its own price by branch order."""
        assert not (set(FREE_TOOLS) & set(MCP_EXPOSED_TOOLS))

    def test_the_product_tools_come_first_in_tools_list(self, client):
        """An agent that truncates the list must still see what this product does."""
        names = [t["name"] for t in client.post("/mcp/", json=_rpc("tools/list")).json()["result"]["tools"]]
        assert names[: len(FREE_TOOLS)] == [t["name"] for t in PRODUCT_TOOL_SCHEMAS]
        assert "filter_text" in names

    def test_every_tool_schema_is_a_valid_json_schema_object(self, client):
        for tool in client.post("/mcp/", json=_rpc("tools/list")).json()["result"]["tools"]:
            assert tool["inputSchema"]["type"] == "object"
            assert isinstance(tool["inputSchema"].get("properties", {}), dict)
            assert tool["description"], f"{tool['name']} has no description"

    def test_a_free_tool_runs_without_payment(self, client, monkeypatch):
        monkeypatch.setenv("X402_GATE_ENABLED", "true")
        response = client.post(
            "/mcp/", json=_rpc("tools/call", {"name": "list_pricing", "arguments": {}})
        )
        assert response.status_code == 200, "the payment gate charged for a free tool"
        assert response.json()["result"]["isError"] is False

    def test_filter_text_refuses_without_the_callers_own_key(self, client):
        """
        It spends the caller's quota, so it must not fall back to the gateway's
        internal key — that would let an anonymous client filter on someone
        else's allowance.
        """
        import json

        response = client.post(
            "/mcp/",
            json=_rpc("tools/call", {"name": "filter_text", "arguments": {"content": "hi"}}),
        )
        result = response.json()["result"]
        assert result["isError"] is True
        assert json.loads(result["content"][0]["text"])["error"] == "authentication_required"

    def test_filter_text_rejects_an_empty_argument_before_any_network_call(self, client):
        import json

        response = client.post(
            "/mcp/",
            headers={"X-API-Key": "irrelevant"},
            json=_rpc("tools/call", {"name": "filter_text", "arguments": {"content": ""}}),
        )
        result = response.json()["result"]
        assert json.loads(result["content"][0]["text"])["error"] == "invalid_arguments"

    def test_an_unknown_tool_is_still_not_found(self, client):
        response = client.post(
            "/mcp/", json=_rpc("tools/call", {"name": "rm_rf", "arguments": {}})
        )
        assert response.json()["error"]["code"] == -32601

    def test_the_pricing_tool_reads_the_canonical_table(self):
        import asyncio

        from warden.billing.pricing import TIER_PRICE_USD_MONTH

        result = asyncio.run(PRODUCT_TOOL_HANDLERS["list_pricing"](None, {}))
        published = {p["id"]: p["price_usd_month"] for p in result["plans"]}
        for tier, price in TIER_PRICE_USD_MONTH.items():
            if tier == "trial":
                continue
            assert published[tier] == round(price, 2), f"{tier} is published off-table"

    def test_an_unlimited_plan_is_not_published_as_zero_requests(self):
        """`None` means unlimited; a client reading 0 would refuse to send anything."""
        import asyncio

        result = asyncio.run(PRODUCT_TOOL_HANDLERS["list_pricing"](None, {}))
        unlimited = [p for p in result["plans"] if p["unlimited_requests"]]
        assert unlimited, "no unlimited plan published"
        assert all(p["requests_per_month"] is None for p in unlimited)
