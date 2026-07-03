"""Tests for agent-discovery well-known endpoints."""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.api.discovery import router


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")
    monkeypatch.setenv("WARDEN_API_KEY", "")
    monkeypatch.setenv("LOGS_PATH", "/tmp/warden_test_disc_logs.json")
    monkeypatch.setenv("DYNAMIC_RULES_PATH", "/tmp/warden_test_disc_rules.json")
    monkeypatch.setenv("REDIS_URL", "memory://")
    monkeypatch.setenv("MODEL_CACHE_DIR", "/tmp/warden_test_models")


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestWellKnownBuilders:
    def test_ai_market_shape(self):
        from warden.discovery.well_known import build_ai_market  # noqa: PLC0415
        doc = build_ai_market()
        assert doc["version"] == "1.0"
        assert "gateway" in doc
        assert "capabilities" in doc
        assert "did:shadow" in doc["capabilities"]
        assert "payment_methods" in doc
        methods = [m["type"] for m in doc["payment_methods"]]
        assert "x402" in methods
        assert "l402" in methods

    def test_ai_market_tenant_id(self):
        from warden.discovery.well_known import build_ai_market  # noqa: PLC0415
        doc = build_ai_market(tenant_id="acme")
        assert doc["tenant_id"] == "acme"

    def test_mcp_descriptor_shape(self):
        from warden.discovery.well_known import build_mcp_descriptor  # noqa: PLC0415
        doc = build_mcp_descriptor()
        assert "schema_version" in doc
        assert "tools" in doc
        assert isinstance(doc["tools"], list)
        assert "auth" in doc
        assert "payment" in doc


class TestDiscoveryRouter:
    def test_ai_market_endpoint(self, client):
        resp = client.get("/.well-known/ai-market.json")
        assert resp.status_code == 200
        assert resp.json()["version"] == "1.0"

    def test_mcp_well_known_endpoint(self, client):
        resp = client.get("/.well-known/mcp.json")
        assert resp.status_code == 200
        assert "tools" in resp.json()

    def test_mcp_pricing_endpoint(self, client):
        resp = client.get("/mcp/pricing")
        assert resp.status_code == 200
        data = resp.json()
        assert "default_price_usd" in data
        assert "tools" in data
