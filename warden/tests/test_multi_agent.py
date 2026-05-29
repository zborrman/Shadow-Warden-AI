"""
warden/tests/test_multi_agent.py  (Phase 2 — 7 tests)
Multi-agent procurement orchestration with mocked AI responses.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("COMMERCE_DB_PATH", "/tmp/test_ma_commerce.db")


class TestAgentProposal:
    def test_proposal_score_price_dominant(self):
        from warden.business_community.agentic_commerce.multi_agent.connectors import AgentProposal
        p = AgentProposal("test", {
            "recommended_vendor": "cheap.com",
            "estimated_price_usd": 10.0,
            "delivery_days": 1,
            "risk_score": 0.1,
            "rationale": "Cheapest option",
        })
        assert p.score() < 0.5  # low price → low score

    def test_proposal_score_high_risk(self):
        from warden.business_community.agentic_commerce.multi_agent.connectors import AgentProposal
        p = AgentProposal("test", {
            "recommended_vendor": "risky.com",
            "estimated_price_usd": 500.0,
            "delivery_days": 30,
            "risk_score": 0.9,
            "rationale": "Risky",
        })
        assert p.score() > 0.5

    def test_keyword_extraction(self):
        from warden.business_community.agentic_commerce.mcp_bridge import MCPBridge
        kw = MCPBridge._extract_keywords("Buy a cloud server for $200")
        assert "cloud" in kw or "server" in kw


class TestMultiAgentOrchestrator:
    @pytest.fixture(autouse=True)
    def _clean(self, tmp_path):
        db = str(tmp_path / "ma.db")
        os.environ["COMMERCE_DB_PATH"] = db
        yield
        if os.path.exists(db):
            os.remove(db)

    def _orch(self):
        from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
            MultiAgentOrchestrator,
        )
        return MultiAgentOrchestrator()

    def test_select_winner_empty(self):
        orch = self._orch()
        assert orch.select_winner([]) is None

    def test_select_winner_picks_lowest_score(self):
        from warden.business_community.agentic_commerce.multi_agent.connectors import AgentProposal
        p1 = AgentProposal("claude", {"estimated_price_usd": 10, "delivery_days": 1, "risk_score": 0.1, "recommended_vendor": "a.com", "rationale": ""})
        p2 = AgentProposal("gpt",    {"estimated_price_usd": 500, "delivery_days": 30, "risk_score": 0.9, "recommended_vendor": "b.com", "rationale": ""})
        winner = self._orch().select_winner([p1, p2])
        assert winner.agent == "claude"

    @pytest.mark.asyncio
    async def test_run_auction_no_api_keys(self):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.pop("GEMINI_API_KEY", None)
        orch = self._orch()
        auction_id = await orch.run_auction("tenant1", "Buy cloud storage under $50")
        assert len(auction_id) > 8
        result = orch.get_auction(auction_id, "tenant1")
        assert result is not None
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_list_auctions(self):
        orch = self._orch()
        await orch.run_auction("tenant2", "test request")
        auctions = orch.list_auctions("tenant2")
        assert len(auctions) >= 1

    def test_evaluate_proposals_sorts_by_score(self):
        from warden.business_community.agentic_commerce.multi_agent.connectors import AgentProposal
        p1 = AgentProposal("a", {"estimated_price_usd": 1000, "delivery_days": 30, "risk_score": 0.9, "recommended_vendor": "x", "rationale": ""})
        p2 = AgentProposal("b", {"estimated_price_usd": 20,   "delivery_days": 2,  "risk_score": 0.1, "recommended_vendor": "y", "rationale": ""})
        ranked = self._orch().evaluate_proposals([p1, p2])
        assert ranked[0].agent == "b"
