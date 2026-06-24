"""
Tests for the three-layer marketplace database architecture.

  Layer 1 — Redis/SQLite  : fast session cache (Redis already tested in conftest)
  Layer 2 — AgentHandoffMemory : context offloading (this file)
  Layer 3 — vector_search  : semantic listing search (this file)

All tests run without Redis (REDIS_URL="memory://") and without Postgres
(MARKETPLACE_VECTOR_SEARCH=false), so they work in CI with zero extra services.
"""
from __future__ import annotations

import asyncio
import sqlite3

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolation(tmp_path, monkeypatch):
    """Force all SQLite-backed modules to use tmp_path DBs."""
    monkeypatch.setenv("REDIS_URL", "memory://")
    monkeypatch.setenv("HANDOFF_DB_PATH", str(tmp_path / "handoff.db"))
    monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "marketplace.db"))
    monkeypatch.setenv("MARKETPLACE_VECTOR_SEARCH", "false")
    yield


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2: AgentHandoffMemory
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentHandoffMemory:
    """Context-offloading: write compact facts, read them back, build prompt snippet."""

    def _mem(self):
        # Import fresh so env vars are picked up
        from warden.marketplace.memory import AgentHandoffMemory
        return AgentHandoffMemory(redis_url="memory://")

    def test_write_returns_key(self, tmp_path):
        mem = self._mem()
        key = asyncio.run(
            mem.write("sess-001", "negotiation_done", {"agreed_price": 42.0})
        )
        assert "marketplace:handoff:sess-001:negotiation_done" in key

    def test_read_returns_facts(self, tmp_path):
        mem = self._mem()
        facts = {"negotiation_id": "neg-abc", "agreed_price": 42.0, "seller": "did:shadow:x"}
        asyncio.run(
            mem.write("sess-002", "neg_done", facts)
        )
        result = asyncio.run(
            mem.read("sess-002", "neg_done")
        )
        assert result == facts

    def test_read_returns_none_for_missing_key(self, tmp_path):
        mem = self._mem()
        result = asyncio.run(
            mem.read("sess-999", "nonexistent_step")
        )
        assert result is None

    def test_read_returns_none_after_ttl_expires(self, tmp_path):
        mem = self._mem()
        asyncio.run(
            mem.write("sess-003", "step_a", {"k": "v"}, ttl=0)
        )
        # TTL=0 means already expired
        result = asyncio.run(
            mem.read("sess-003", "step_a")
        )
        assert result is None

    def test_overwrite_same_key(self, tmp_path):
        mem = self._mem()
        asyncio.run(
            mem.write("sess-004", "step_x", {"v": 1})
        )
        asyncio.run(
            mem.write("sess-004", "step_x", {"v": 2})
        )
        result = asyncio.run(
            mem.read("sess-004", "step_x")
        )
        assert result == {"v": 2}

    def test_compact_prompt_format(self):
        from warden.marketplace.memory import AgentHandoffMemory
        facts = {"agreed_price": 42.0, "seller_agent": "did:shadow:abc"}
        prompt = AgentHandoffMemory.compact_prompt(facts)
        assert "[HANDOFF FACTS]" in prompt
        assert "[END HANDOFF FACTS]" in prompt
        assert "agreed_price: 42.0" in prompt
        assert "seller_agent: did:shadow:abc" in prompt

    def test_compact_prompt_none_facts(self):
        from warden.marketplace.memory import AgentHandoffMemory
        prompt = AgentHandoffMemory.compact_prompt(None)
        assert "[HANDOFF FACTS]" in prompt
        assert "(none)" in prompt

    def test_estimate_savings(self):
        from warden.marketplace.memory import AgentHandoffMemory
        result = AgentHandoffMemory.estimate_savings(full_history_tokens=1000)
        assert result["saved_tokens"] == 950
        assert result["savings_pct"] == 95.0

    def test_sqlite_persistence_across_instances(self, tmp_path):
        """Facts survive across different AgentHandoffMemory instances (process restart sim)."""
        from warden.marketplace.memory import AgentHandoffMemory
        mem1 = AgentHandoffMemory(redis_url="memory://")
        asyncio.run(
            mem1.write("sess-005", "escrow_step", {"escrow_id": "esc-xyz", "amount": 100.0})
        )
        mem2 = AgentHandoffMemory(redis_url="memory://")
        result = asyncio.run(
            mem2.read("sess-005", "escrow_step")
        )
        assert result == {"escrow_id": "esc-xyz", "amount": 100.0}


# ─────────────────────────────────────────────────────────────────────────────
# Layer 3: vector_search (SQLite keyword fallback — no Postgres needed in CI)
# ─────────────────────────────────────────────────────────────────────────────

def _seed_listings(db_path: str, rows: list[dict]) -> None:
    """Insert minimal listing rows so _sqlite_fallback has data to search."""
    con = sqlite3.connect(db_path)
    con.execute("""
        CREATE TABLE IF NOT EXISTS marketplace_listings (
            listing_id   TEXT PRIMARY KEY,
            title        TEXT,
            description  TEXT,
            asset_type   TEXT,
            price_usd    REAL,
            status       TEXT DEFAULT 'active'
        )
    """)
    for r in rows:
        con.execute(
            "INSERT OR IGNORE INTO marketplace_listings "
            "(listing_id,title,description,asset_type,price_usd) VALUES (?,?,?,?,?)",
            (r["listing_id"], r["title"], r.get("description",""), r["asset_type"], r.get("price_usd", 1.0)),
        )
    con.commit()
    con.close()


class TestVectorSearchSqliteFallback:
    """When MARKETPLACE_VECTOR_SEARCH=false, use SQLite LIKE search."""

    def test_returns_matching_listing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
        _seed_listings(str(tmp_path / "mkt.db"), [
            {"listing_id": "L1", "title": "Fraud detection rule", "asset_type": "rule"},
            {"listing_id": "L2", "title": "Sentiment model", "asset_type": "model"},
        ])
        from warden.marketplace.vector_search import _sqlite_fallback
        results = _sqlite_fallback("fraud", limit=10, asset_type=None)
        listing_ids = [r["listing_id"] for r in results]
        assert "L1" in listing_ids

    def test_asset_type_filter_applied(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
        _seed_listings(str(tmp_path / "mkt.db"), [
            {"listing_id": "L3", "title": "Security rule", "asset_type": "rule"},
            {"listing_id": "L4", "title": "Security model", "asset_type": "model"},
        ])
        from warden.marketplace.vector_search import _sqlite_fallback
        results = _sqlite_fallback("security", limit=10, asset_type="rule")
        asset_types = {r["asset_type"] for r in results}
        assert asset_types == {"rule"}

    def test_empty_query_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
        _seed_listings(str(tmp_path / "mkt.db"), [
            {"listing_id": "L5", "title": "Something", "asset_type": "model"},
        ])
        from warden.marketplace.vector_search import _sqlite_fallback
        results = _sqlite_fallback("", limit=10, asset_type=None)
        assert results == []

    def test_no_match_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
        _seed_listings(str(tmp_path / "mkt.db"), [
            {"listing_id": "L6", "title": "Something else", "asset_type": "rule"},
        ])
        from warden.marketplace.vector_search import _sqlite_fallback
        results = _sqlite_fallback("xyzzy_nonexistent", limit=10, asset_type=None)
        assert results == []

    def test_semantic_search_routes_to_fallback_when_vector_disabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_VECTOR_SEARCH", "false")
        monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
        _seed_listings(str(tmp_path / "mkt.db"), [
            {"listing_id": "L7", "title": "Jailbreak detector", "asset_type": "rule"},
        ])
        from warden.marketplace.vector_search import semantic_search
        results = asyncio.run(
            semantic_search("jailbreak", limit=5)
        )
        assert any(r["listing_id"] == "L7" for r in results)

    def test_similarity_field_present(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
        _seed_listings(str(tmp_path / "mkt.db"), [
            {"listing_id": "L8", "title": "Detection signal", "asset_type": "signals"},
        ])
        from warden.marketplace.vector_search import _sqlite_fallback
        results = _sqlite_fallback("detection", limit=5, asset_type=None)
        assert all("similarity" in r for r in results)

    def test_embed_text_returns_none_when_model_missing(self, monkeypatch):
        monkeypatch.setattr(
            "warden.marketplace.vector_search._get_model", lambda: None
        )
        from warden.marketplace.vector_search import embed_text
        assert embed_text("some query") is None


# ─────────────────────────────────────────────────────────────────────────────
# SOVA tools #70 / #71 / #72
# ─────────────────────────────────────────────────────────────────────────────

class TestHandoffMemoryTools:
    """SOVA tool functions write and read handoff facts correctly."""

    def test_write_tool_returns_key(self, tmp_path):
        from warden.agent.tools import write_handoff_memory
        result = asyncio.run(
            write_handoff_memory(
                session_id="tool-sess-001",
                step="negotiation_done",
                facts={"agreed_price": 55.0, "listing_id": "L-abc"},
            )
        )
        assert "key" in result
        assert result["facts_count"] == 2

    def test_read_tool_returns_facts_and_snippet(self, tmp_path):
        from warden.agent.tools import read_handoff_memory, write_handoff_memory
        asyncio.run(
            write_handoff_memory(
                session_id="tool-sess-002",
                step="escrow_funded",
                facts={"escrow_id": "esc-001", "amount_usd": 99.0},
            )
        )
        result = asyncio.run(
            read_handoff_memory(session_id="tool-sess-002", step="escrow_funded")
        )
        assert result["facts"]["escrow_id"] == "esc-001"
        assert "[HANDOFF FACTS]" in result["prompt_snippet"]

    def test_read_tool_missing_key(self):
        from warden.agent.tools import read_handoff_memory
        result = asyncio.run(
            read_handoff_memory(session_id="does-not-exist", step="ghost_step")
        )
        assert "error" in result

    def test_semantic_search_tool_returns_dict(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_VECTOR_SEARCH", "false")
        monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
        _seed_listings(str(tmp_path / "mkt.db"), [
            {"listing_id": "TL1", "title": "Anomaly detector", "asset_type": "model"},
        ])
        from warden.agent.tools import semantic_listing_search
        result = asyncio.run(
            semantic_listing_search(query="anomaly", limit=5)
        )
        assert "results" in result
        assert "count" in result


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 + Layer 3 integration: BuyerAgent uses semantic search
# ─────────────────────────────────────────────────────────────────────────────

class TestBuyerAgentSemanticSearch:
    """search_assets_semantic() delegates to vector_search.semantic_search."""

    def test_search_assets_semantic_async(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
        monkeypatch.setenv("MARKETPLACE_VECTOR_SEARCH", "false")
        _seed_listings(str(tmp_path / "mkt.db"), [
            {"listing_id": "SA1", "title": "Threat intelligence signals", "asset_type": "signals"},
            {"listing_id": "SA2", "title": "Phishing rule set", "asset_type": "rule"},
        ])
        from warden.marketplace.buyer_agent import BuyerAgent
        buyer = BuyerAgent(agent_id="buyer-test", db_path=str(tmp_path / "mkt.db"))
        results = asyncio.run(
            buyer.search_assets_semantic("threat intelligence")
        )
        ids = [r["listing_id"] for r in results]
        assert "SA1" in ids
