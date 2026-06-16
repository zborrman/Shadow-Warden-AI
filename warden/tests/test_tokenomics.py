"""Tests for Agent Tokenomics / WAT ERC-20 (MKT-11)."""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("WAT_SIMULATE", "true")

from warden.tokenomics.agent_token import AgentToken, get_agent_token
from warden.tokenomics.outcome_pricing import OutcomePricingService

# ── AgentToken (simulation mode) ─────────────────────────────────────────────

class TestAgentToken:

    def setup_method(self):
        os.environ["WAT_SIMULATE"] = "true"

    def test_singleton(self):
        a = get_agent_token()
        b = get_agent_token()
        assert a is b

    def test_mint_increases_balance(self):
        tok = AgentToken()
        tok.mint("agent-tok-1", 100.0)
        bal = tok.balance_of("agent-tok-1")
        assert bal >= 100.0

    def test_balance_zero_for_unknown(self):
        tok = AgentToken()
        assert tok.balance_of("agent-nonexistent-xyz") == 0.0

    def test_transfer_moves_tokens(self):
        tok = AgentToken()
        tok.mint("agent-tok-src", 50.0)
        tok.transfer("agent-tok-src", "agent-tok-dst", 20.0)
        assert tok.balance_of("agent-tok-dst") >= 20.0
        assert tok.balance_of("agent-tok-src") <= 30.0

    def test_transfer_insufficient_funds_raises(self):
        tok = AgentToken()
        with pytest.raises(ValueError, match="[Ii]nsufficient|balance"):
            tok.transfer("agent-empty-xyz", "agent-tok-dst", 999999.0)

    def test_mint_returns_tx_hash(self):
        tok = AgentToken()
        result = tok.mint("agent-tok-2", 10.0)
        assert "tx_hash" in result or result is not None


# ── OutcomePricingService ──────────────────────────────────────────────────────

class TestOutcomePricingService:

    def setup_method(self):
        self.svc = OutcomePricingService(db_path=":memory:")

    def test_create_listing(self):
        lid = self.svc.create_listing(
            base_price_usd=100.0,
            kpi_definition="F1 >= 0.9",
            target_value=0.9,
        )
        assert lid is not None
        listing = self.svc.get_listing(lid)
        assert listing["base_price_usd"] == 100.0

    def test_settle_proportional(self):
        lid = self.svc.create_listing(base_price_usd=100.0, kpi_definition="accuracy", target_value=1.0)
        result = self.svc.settle_outcome(lid, "buyer-agent-1", achieved_value=0.8)
        assert result["settled_price_usd"] == pytest.approx(80.0, rel=0.01)

    def test_settle_capped_at_base(self):
        lid = self.svc.create_listing(base_price_usd=50.0, kpi_definition="recall", target_value=0.5)
        result = self.svc.settle_outcome(lid, "buyer-agent-2", achieved_value=1.0)
        assert result["settled_price_usd"] == pytest.approx(50.0, rel=0.01)

    def test_list_listings(self):
        self.svc.create_listing(base_price_usd=10.0, kpi_definition="kpi", target_value=0.5)
        listings = self.svc.list_listings()
        assert len(listings) >= 1


# ── AgentToken — Redis simulation paths ──────────────────────────────────────

class TestAgentTokenRedis:
    """Cover the Redis-backed simulation paths by mocking _redis()."""

    def _mock_redis(self):
        r = MagicMock()
        store: dict = {}

        def incrbyfloat(key, amount):
            store[key] = store.get(key, 0.0) + amount
            return store[key]

        def get(key):
            v = store.get(key)
            return str(v) if v is not None else None

        def expire(key, ttl):
            pass

        def pipeline():
            pipe = MagicMock()
            pipe_ops = []
            def pipe_incrbyfloat(key, amount):
                pipe_ops.append(("incr", key, amount))
                return pipe
            def pipe_expire(key, ttl):
                return pipe
            def execute():
                for _op, key, amount in pipe_ops:
                    store[key] = store.get(key, 0.0) + amount
            pipe.incrbyfloat.side_effect = pipe_incrbyfloat
            pipe.expire.side_effect = pipe_expire
            pipe.execute.side_effect = execute
            return pipe

        r.get.side_effect = get
        r.incrbyfloat.side_effect = incrbyfloat
        r.expire.side_effect = expire
        r.pipeline.side_effect = pipeline
        return r, store

    def test_sim_balance_uses_redis(self):
        from unittest.mock import patch

        from warden.tokenomics.agent_token import AgentToken
        r, store = self._mock_redis()
        store["wat:balance:agent-r1"] = 42.5
        with patch("warden.tokenomics.agent_token._redis", return_value=r):
            tok = AgentToken()
            bal = tok._sim_balance("agent-r1")
        assert bal == pytest.approx(42.5)

    def test_sim_mint_uses_redis(self):
        from unittest.mock import patch

        from warden.tokenomics.agent_token import AgentToken
        r, store = self._mock_redis()
        with patch("warden.tokenomics.agent_token._redis", return_value=r):
            tok = AgentToken()
            result = tok._sim_mint("agent-r2", 100.0)
        assert result["simulated"] is True
        assert result["amount"] == 100.0

    def test_sim_transfer_uses_redis(self):
        from unittest.mock import patch

        from warden.tokenomics.agent_token import AgentToken
        r, store = self._mock_redis()
        store["wat:balance:agent-r3"] = 50.0
        with patch("warden.tokenomics.agent_token._redis", return_value=r):
            tok = AgentToken()
            result = tok._sim_transfer("agent-r3", "agent-r4", 20.0)
        assert result["simulated"] is True
        assert result["amount"] == 20.0

    def test_sim_transfer_insufficient_raises(self):
        from warden.tokenomics.agent_token import AgentToken
        tok = AgentToken()
        with pytest.raises(ValueError, match="[Ii]nsufficient"):
            tok._sim_transfer("empty-agent", "dst-agent", 9999.0)


# ── Tokenomics API router ─────────────────────────────────────────────────────

class TestTokenomicsApi:
    @pytest.fixture(autouse=True)
    def _client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from warden.tokenomics.api import router
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_mint_no_admin_key_required_when_env_empty(self):
        resp = self.client.post("/tokenomics/mint", json={"agent_id": "api-agent-1", "amount": 10.0})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("simulated") is True or "agent_id" in data

    def test_balance_endpoint(self):
        self.client.post("/tokenomics/mint", json={"agent_id": "api-agent-bal", "amount": 25.0})
        resp = self.client.get("/tokenomics/balance/api-agent-bal")
        assert resp.status_code == 200
        data = resp.json()
        assert "balance_wat" in data
        assert data["agent_id"] == "api-agent-bal"

    def test_create_outcome_listing(self):
        resp = self.client.post("/tokenomics/listings/outcome", json={
            "community_id": "test-comm",
            "seller_agent_id": "seller-1",
            "base_price_usd": 50.0,
            "kpi_definition": {"metric": "accuracy"},
            "target_value": 0.9,
        })
        assert resp.status_code == 201

    def test_list_outcome_listings(self):
        resp = self.client.get("/tokenomics/listings/outcome")
        assert resp.status_code == 200
        assert "listings" in resp.json()

    def test_list_outcome_listings_filtered_by_community(self):
        resp = self.client.get("/tokenomics/listings/outcome?community_id=my-community")
        assert resp.status_code == 200

    def test_settle_outcome_unknown_listing(self):
        resp = self.client.post("/tokenomics/listings/unknown-listing-id/settle", json={
            "buyer_agent_id": "buyer-1",
            "achieved_value": 0.8,
        })
        assert resp.status_code in (400, 404, 500)

    def test_mint_admin_key_enforcement(self):
        import os

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        orig = os.environ.get("ADMIN_KEY")
        os.environ["ADMIN_KEY"] = "secret-admin"
        try:
            import importlib

            import warden.tokenomics.api as tapi
            importlib.reload(tapi)
            app2 = FastAPI()
            app2.include_router(tapi.router)
            c2 = TestClient(app2, raise_server_exceptions=False)
            resp_no_key = c2.post("/tokenomics/mint", json={"agent_id": "x", "amount": 1.0})
            assert resp_no_key.status_code == 403
            resp_with_key = c2.post(
                "/tokenomics/mint",
                json={"agent_id": "x", "amount": 1.0},
                headers={"X-Admin-Key": "secret-admin"},
            )
            assert resp_with_key.status_code == 200
        finally:
            if orig is None:
                os.environ.pop("ADMIN_KEY", None)
            else:
                os.environ["ADMIN_KEY"] = orig
