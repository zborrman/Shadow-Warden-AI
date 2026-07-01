"""Tests for the paid MCP gateway (warden/mcp/gateway.py)."""
from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("LOGS_PATH", "/tmp/warden_test_mcp_logs.json")
os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/warden_test_mcp_dynamic.json")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("MODEL_CACHE_DIR", "/tmp/warden_test_models")
os.environ.setdefault("X402_GATE_ENABLED", "false")   # gate off → all calls pass

from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    from warden.main import app
    return TestClient(app, raise_server_exceptions=False)


def rpc(method: str, params: dict | None = None, req_id: int = 1) -> dict:
    body: dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        body["params"] = params
    return body


class TestMcpDiscovery:
    def test_get_info(self, client: TestClient) -> None:
        r = client.get("/mcp/")
        assert r.status_code == 200
        data = r.json()
        assert data["protocol"] == "2024-11-05"
        assert data["tools_count"] > 0
        assert "billing" in data

    def test_initialize(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-agent", "version": "1.0"},
        }))
        assert r.status_code == 200
        body = r.json()
        assert body["result"]["protocolVersion"] == "2024-11-05"
        assert "tools" in body["result"]["capabilities"]
        assert body["result"]["serverInfo"]["name"] == "shadow-warden-staff-tools"

    def test_ping(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("ping"))
        assert r.status_code == 200
        assert r.json()["result"] == {}

    def test_tools_list(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("tools/list"))
        assert r.status_code == 200
        tools = r.json()["result"]["tools"]
        names = {t["name"] for t in tools}
        assert "screen_sanctions_list" in names
        assert "score_kyc_profile" in names
        assert "generate_seo_content" in names
        assert "resolve_ticket_kb" in names
        # Sensitive tools must NOT be exposed
        assert "issue_refund" not in names
        assert "get_billing_status" not in names

    def test_tools_list_includes_pricing_in_description(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("tools/list"))
        tools = {t["name"]: t for t in r.json()["result"]["tools"]}
        desc = tools["screen_sanctions_list"]["description"]
        assert "$0.05" in desc or "/call" in desc

    def test_tools_list_schema_shape(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("tools/list"))
        tools = r.json()["result"]["tools"]
        for t in tools:
            assert "name" in t
            assert "description" in t
            assert "inputSchema" in t

    def test_notifications_initialized(self, client: TestClient) -> None:
        r = client.post("/mcp/", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert r.status_code == 202

    def test_unknown_method(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("bogus/method"))
        assert r.status_code == 200
        assert r.json()["error"]["code"] == -32601

    def test_invalid_json(self, client: TestClient) -> None:
        r = client.post("/mcp/", content=b"not-json", headers={"Content-Type": "application/json"})
        assert r.status_code == 200
        assert r.json()["error"]["code"] == -32700


class TestMcpToolCall:
    def test_screen_sanctions_clean(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("tools/call", {
            "name": "screen_sanctions_list",
            "arguments": {"subject_name": "Acme Corp", "list_name": "OFAC_SDN"},
        }))
        assert r.status_code == 200
        body = r.json()
        assert "result" in body
        content = body["result"]["content"][0]["text"]
        data = json.loads(content)
        assert "hit" in data
        assert data["hit"] is False

    def test_score_kyc_low_risk(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("tools/call", {
            "name": "score_kyc_profile",
            "arguments": {
                "entity_name": "Clean Entity GmbH",
                "country": "de",
                "entity_type": "company",
                "pep": False,
                "adverse_media": False,
                "transaction_volume_usd": 500.0,
            },
        }))
        assert r.status_code == 200
        data = json.loads(r.json()["result"]["content"][0]["text"])
        assert data["risk_level"] == "LOW"
        assert data["risk_score"] < 25

    def test_score_kyc_high_risk_country(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("tools/call", {
            "name": "score_kyc_profile",
            "arguments": {"entity_name": "XYZ Ltd", "country": "ir", "pep": True},
        }))
        assert r.status_code == 200
        data = json.loads(r.json()["result"]["content"][0]["text"])
        assert data["risk_level"] == "HIGH"

    def test_unknown_tool(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("tools/call", {
            "name": "does_not_exist",
            "arguments": {},
        }))
        assert r.status_code == 200
        assert r.json()["error"]["code"] == -32601

    def test_issue_refund_blocked(self, client: TestClient) -> None:
        """issue_refund is not in MCP_EXPOSED_TOOLS — must be rejected."""
        r = client.post("/mcp/", json=rpc("tools/call", {
            "name": "issue_refund",
            "arguments": {"tenant_id": "t1", "amount_usd": 50.0},
        }))
        assert r.status_code == 200
        assert r.json()["error"]["code"] == -32601

    def test_kb_lookup(self, client: TestClient) -> None:
        r = client.post("/mcp/", json=rpc("tools/call", {
            "name": "resolve_ticket_kb",
            "arguments": {"category": "billing", "tenant_id": "default"},
        }))
        assert r.status_code == 200
        body = r.json()
        assert "result" in body
        assert body["result"]["isError"] is False


class TestMcpPricing:
    def test_pricing_catalog(self) -> None:
        from decimal import Decimal

        from warden.mcp.pricing import MCP_EXPOSED_TOOLS, TOOL_PRICES_USD, price_for

        assert price_for("screen_sanctions_list") == Decimal("0.05")
        assert price_for("score_kyc_profile") == Decimal("0.03")
        assert price_for("generate_sar") == Decimal("0.10")
        assert price_for("resolve_ticket_kb") == Decimal("0.001")
        assert "issue_refund" not in MCP_EXPOSED_TOOLS
        assert "get_billing_status" not in MCP_EXPOSED_TOOLS
        # All exposed tools have prices
        for tool in MCP_EXPOSED_TOOLS:
            assert tool in TOOL_PRICES_USD, f"{tool} missing from TOOL_PRICES_USD"

    def test_default_price_for_unknown(self) -> None:
        from warden.mcp.pricing import DEFAULT_PRICE_USD, price_for
        assert price_for("nonexistent_tool") == DEFAULT_PRICE_USD
