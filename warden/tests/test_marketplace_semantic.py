"""
warden/tests/test_marketplace_semantic.py  (SEM-02)
Marketplace Semantic Layer — 12 tests covering all 10 domain models,
tenant isolation, and AI/LLM intent query.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("M2M_ANALYTICS_DB_PATH", "/tmp/test_marketplace_analytics.db")
os.environ.setdefault("M2M_STORE_DB_PATH",     "/tmp/test_marketplace_analytics.db")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _engine():
    from warden.semantic_layer.engine import SemanticEngine
    return SemanticEngine()


def _query(model_id: str, metrics: list, dimensions: list | None = None, filters: list | None = None):
    from warden.semantic_layer.models import QueryObject
    return QueryObject(
        model_id=model_id,
        metrics=metrics,
        dimensions=dimensions or [],
        filters=filters or [],
    )


def _filter(dimension: str, value: str, operator: str = "="):
    from warden.semantic_layer.models import FilterClause
    return FilterClause(dimension=dimension, operator=operator, value=value)


@pytest.fixture(autouse=True)
def _analytics_db(tmp_path):
    """Each test gets an isolated analytics DB."""
    db = str(tmp_path / "analytics.db")
    os.environ["M2M_ANALYTICS_DB_PATH"] = db
    os.environ["M2M_STORE_DB_PATH"] = db
    from warden.m2m_store.analytics import ensure_analytics_schema
    ensure_analytics_schema()
    yield db
    # cleanup handled by tmp_path


# ── 1. Listings — total count ─────────────────────────────────────────────────

class TestMarketplaceListings:
    def test_total_listings_sql(self):
        engine = _engine()
        q = _query("marketplace_listings", ["total_listings"])
        result = engine.generate(q)
        assert "COUNT(*)" in result.sql
        assert "mp_listings" in result.sql
        assert result.model_id == "marketplace_listings"

    def test_active_listings_metric(self):
        engine = _engine()
        q = _query("marketplace_listings", ["active_listings"])
        result = engine.generate(q)
        assert "status" in result.sql
        assert "active" in result.sql

    def test_total_value_metric(self):
        engine = _engine()
        q = _query("marketplace_listings", ["total_value"])
        result = engine.generate(q)
        assert "SUM(price * quantity)" in result.sql


# ── 2. Trades — with date filter ──────────────────────────────────────────────

class TestMarketplaceTrades:
    def test_trade_volume_with_date_filter(self):
        engine = _engine()
        f = _filter("date", "2026-06-01", ">=")
        q = _query("marketplace_trades", ["trade_volume_usd"], ["date"], [f])
        result = engine.generate(q)
        assert "SUM(amount_usd)" in result.sql
        assert "WHERE" in result.sql
        assert "purchased_at" in result.sql

    def test_unique_buyers_dimension(self):
        engine = _engine()
        q = _query("marketplace_trades", ["unique_buyers", "total_trades"], ["seller_agent_id"])
        result = engine.generate(q)
        assert "COUNT(DISTINCT buyer_agent_id)" in result.sql
        assert "GROUP BY" in result.sql


# ── 3. Escrow — active + disputed ────────────────────────────────────────────

class TestMarketplaceEscrow:
    def test_active_escrows_metric(self):
        engine = _engine()
        q = _query("marketplace_escrow", ["active_escrows"])
        result = engine.generate(q)
        assert "funded" in result.sql
        assert "delivered" in result.sql

    def test_disputed_escrows_metric(self):
        engine = _engine()
        q = _query("marketplace_escrow", ["disputed_escrows"])
        result = engine.generate(q)
        assert "disputed" in result.sql

    def test_escrow_by_chain(self):
        engine = _engine()
        q = _query("marketplace_escrow", ["total_escrows"], ["chain"])
        result = engine.generate(q)
        assert "mp_escrow" in result.sql
        assert "chain" in result.sql


# ── 4. Negotiations — success rate ────────────────────────────────────────────

class TestMarketplaceNegotiations:
    def test_success_rate_metric(self):
        engine = _engine()
        q = _query("marketplace_negotiations", ["success_rate"])
        result = engine.generate(q)
        assert "accepted" in result.sql
        assert "NULLIF" in result.sql

    def test_avg_rounds_metric(self):
        engine = _engine()
        q = _query("marketplace_negotiations", ["avg_rounds", "total_negotiations"])
        result = engine.generate(q)
        assert "AVG(rounds)" in result.sql
        assert "COUNT(*)" in result.sql


# ── 5. Reputation — average score ────────────────────────────────────────────

class TestMarketplaceReputation:
    def test_avg_reputation_metric(self):
        engine = _engine()
        q = _query("marketplace_reputation", ["avg_reputation"])
        result = engine.generate(q)
        assert "AVG(overall_score)" in result.sql
        assert "mp_reputation" in result.sql

    def test_top_agents_metric(self):
        engine = _engine()
        q = _query("marketplace_reputation", ["top_agents"])
        result = engine.generate(q)
        assert "0.8" in result.sql


# ── 6. Governance — passed proposals ─────────────────────────────────────────

class TestMarketplaceGovernance:
    def test_passed_proposals_metric(self):
        engine = _engine()
        q = _query("marketplace_governance", ["passed_proposals", "total_proposals"])
        result = engine.generate(q)
        assert "passed" in result.sql
        assert "mp_proposals" in result.sql

    def test_voter_turnout_metric(self):
        engine = _engine()
        q = _query("marketplace_governance", ["avg_voter_turnout"])
        result = engine.generate(q)
        assert "voter_count" in result.sql
        assert "eligible_voters" in result.sql


# ── 7. Agents — active count ──────────────────────────────────────────────────

class TestMarketplaceAgents:
    def test_active_agents_metric(self):
        engine = _engine()
        q = _query("marketplace_agents", ["active_agents", "total_agents"])
        result = engine.generate(q)
        assert "SUM(CASE WHEN status = 'active'" in result.sql
        assert "mp_agents" in result.sql


# ── 8. Assets — grouped by type ──────────────────────────────────────────────

class TestMarketplaceAssets:
    def test_assets_grouped_by_type(self):
        engine = _engine()
        q = _query("marketplace_assets", ["total_assets"], ["asset_type"])
        result = engine.generate(q)
        assert "mp_assets" in result.sql
        assert "asset_type" in result.sql
        assert "GROUP BY" in result.sql


# ── 9. MAESTRO flags — high threats ──────────────────────────────────────────

class TestMarketplaceMaestroFlags:
    def test_high_threats_metric(self):
        engine = _engine()
        q = _query("marketplace_maestro_flags", ["high_threats", "total_flags"])
        result = engine.generate(q)
        assert "high" in result.sql
        assert "critical" in result.sql
        assert "mp_flags" in result.sql


# ── 10. Cross-chain — grouped by chain ───────────────────────────────────────

class TestMarketplaceCrossChain:
    def test_cross_chain_by_chain(self):
        engine = _engine()
        q = _query("marketplace_cross_chain", ["total_cross_chain", "volume_usd"], ["chain"])
        result = engine.generate(q)
        assert "mp_cross_chain" in result.sql
        assert "chain" in result.sql
        assert "GROUP BY" in result.sql


# ── 11. Tenant isolation via community_id filter ──────────────────────────────

class TestTenantIsolation:
    def test_community_filter_in_sql(self):
        engine = _engine()
        f = _filter("community_id", "community-alpha")
        q = _query("marketplace_listings", ["total_listings"], filters=[f])
        result = engine.generate(q)
        assert "WHERE" in result.sql
        assert "community_id" in result.sql

    def test_different_community_different_filter_param(self):
        """Two community queries produce the same SQL template (parameterised)."""
        from warden.semantic_layer.models import FilterClause, QueryObject
        engine = _engine()
        q_a = QueryObject(
            model_id="marketplace_listings",
            metrics=["total_listings"],
            filters=[FilterClause(dimension="community_id", operator="=", value="alpha")],
        )
        q_b = QueryObject(
            model_id="marketplace_listings",
            metrics=["total_listings"],
            filters=[FilterClause(dimension="community_id", operator="=", value="beta")],
        )
        r_a = engine.generate(q_a)
        r_b = engine.generate(q_b)
        # Both generate parameterised SQL — same template, no value interpolation
        assert r_a.sql == r_b.sql, "SQL template must be identical (values are %s placeholders)"
        # Unfiltered query is different (no WHERE clause)
        q_open = QueryObject(model_id="marketplace_listings", metrics=["total_listings"])
        r_open = engine.generate(q_open)
        assert r_open.sql != r_a.sql, "Filtered SQL must differ from unfiltered SQL"


# ── 12. AI intent — natural language → QueryObject → SQL ─────────────────────

class TestAIIntent:
    def test_model_is_llm_safe(self):
        """Verify marketplace_trades model is safe to expose to LLM context."""
        from warden.semantic_layer.engine import SemanticQueryEngine, get_engine
        engine_q = SemanticQueryEngine()
        model = get_engine().get_model("marketplace_trades")
        ctx = engine_q.get_context_for_llm(model)
        assert ctx["model_id"] == "marketplace_trades"
        assert any(m["name"] == "trade_volume_usd" for m in ctx["metrics"])
        assert any(d["name"] == "seller_agent_id" for d in ctx["dimensions"])
        # Raw SQL must NOT be exposed to LLM context
        assert "SUM(" not in str(ctx["metrics"])

    def test_simulated_llm_query_top_sellers(self):
        """
        Simulate LLM-generated QueryObject for 'show me top sellers this month'.
        This is the QueryObject an LLM would produce after receiving get_context_for_llm().
        """
        from warden.semantic_layer.models import FilterClause, QueryObject
        engine = _engine()
        q = QueryObject(
            model_id="marketplace_trades",
            metrics=["trade_volume_usd", "total_trades"],
            dimensions=["seller_agent_id", "date"],
            filters=[FilterClause(dimension="date", operator=">=", value="2026-06-01")],
            intent="show me top sellers this month",
        )
        result = engine.generate(q)
        assert "trade_volume_usd" in result.sql
        assert "seller_agent_id" in result.sql
        assert "WHERE" in result.sql
        assert result.model_id == "marketplace_trades"
        assert result.model_id  # QueryResult echoes model_id only, not intent

    def test_all_marketplace_models_registered(self):
        """All 10 marketplace semantic models are registered in the engine."""
        engine = _engine()
        model_ids = {m.id for m in engine.list_models()}
        expected = {
            "marketplace_listings",
            "marketplace_trades",
            "marketplace_escrow",
            "marketplace_negotiations",
            "marketplace_reputation",
            "marketplace_governance",
            "marketplace_agents",
            "marketplace_assets",
            "marketplace_maestro_flags",
            "marketplace_cross_chain",
        }
        missing = expected - model_ids
        assert not missing, f"Missing models: {missing}"
