"""Tests for Agent Tokenomics / WAT ERC-20 (MKT-11)."""
from __future__ import annotations

import os
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
