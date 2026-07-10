"""
Tests for M2M Agentic Marketplace integration (Steps 2-3 of the M2M plan):
  - Protocol discovery endpoint shape
  - Action dispatcher routing
  - First-Proposal Bias Guard (under-minimum + at-minimum)
  - Fairness stats structure
  - SELECT-only SQL gate on analytics/query
"""
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_app(tmp_db: str) -> "TestClient":
    os.environ["MARKETPLACE_DB_PATH"] = tmp_db
    os.environ["ALLOW_UNAUTHENTICATED"] = "true"
    os.environ["WARDEN_API_KEY"] = ""

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.marketplace.api import router

    app = FastAPI()
    app.include_router(router, prefix="/marketplace")
    return TestClient(app)


# ── Protocol endpoint ─────────────────────────────────────────────────────────

class TestProtocolEndpoint:
    def test_protocol_returns_200(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.get("/marketplace/protocol")
        assert r.status_code == 200

    def test_protocol_top_level_keys_present(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        data = client.get("/marketplace/protocol").json()
        required = {
            "protocol_version", "market_id", "supported_actions",
            "negotiation", "pricing", "escrow", "governance", "trust",
        }
        assert required <= data.keys(), f"Missing keys: {required - data.keys()}"

    def test_protocol_negotiation_has_min_offers_field(self, tmp_path):
        os.environ["MARKETPLACE_MIN_OFFERS_BEFORE_BUY"] = "3"
        client = _make_app(str(tmp_path / "mkt.db"))
        data = client.get("/marketplace/protocol").json()
        assert data["negotiation"]["min_offers_before_buy"] == 3

    def test_protocol_supported_actions_contains_core_verbs(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        data = client.get("/marketplace/protocol").json()
        actions = data["supported_actions"]
        assert "register_agent" in actions
        assert "purchase" in actions
        assert "start_negotiation" in actions
        assert "raise_dispute" in actions

    def test_protocol_trust_algo_is_pagerank(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        data = client.get("/marketplace/protocol").json()
        assert data["trust"]["algorithm"] == "weighted-pagerank"
        assert data["trust"]["maestro_threat_detection"] is True


# ── Action dispatcher ─────────────────────────────────────────────────────────

class TestActionDispatcher:
    def test_action_invalid_type_returns_422(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/action", json={
            "action_type": "nonexistent_action",
            "payload": {},
        })
        assert r.status_code == 422

    def test_action_valid_type_returns_200_or_dispatched_key(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/action", json={
            "action_type": "buy",
            "payload": {},
        })
        assert r.status_code == 200
        data = r.json()
        assert "dispatched" in data
        assert data["action_type"] == "buy"

    def test_action_negotiate_returns_dispatched_key(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/action", json={
            "action_type": "negotiate",
            "payload": {},
        })
        assert r.status_code == 200
        assert "dispatched" in r.json()


# ── Analytics SQL gate ────────────────────────────────────────────────────────

class TestAnalyticsSqlGate:
    def test_select_query_returns_200(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/analytics/query", json={
            "sql": "SELECT 1 AS ping",
            "params": [],
            "caller_agent_id": "did:shadow:tester",
        })
        assert r.status_code == 200
        data = r.json()
        assert "rows" in data

    def test_select_1_returns_correct_value(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/analytics/query", json={
            "sql": "SELECT 1 AS ping",
            "params": [],
            "caller_agent_id": "did:shadow:tester",
        })
        rows = r.json()["rows"]
        assert rows[0]["ping"] == 1

    def test_ddl_statement_is_rejected(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/analytics/query", json={
            "sql": "DROP TABLE IF EXISTS foo",
            "params": [],
        })
        assert r.status_code == 200
        data = r.json()
        assert "error" in data
        assert data["rows"] == []

    def test_insert_statement_is_rejected(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/analytics/query", json={
            "sql": "INSERT INTO foo VALUES (1)",
            "params": [],
        })
        assert r.status_code == 200
        assert "error" in r.json()


# ── First-Proposal Bias Guard ─────────────────────────────────────────────────

class TestFirstProposalBiasGuard:
    """search_and_buy() must require MIN_OFFERS_BEFORE_BUY candidates."""

    def _make_buyer(self, tmp_db: str):
        from warden.marketplace.buyer_agent import BuyerAgent
        return BuyerAgent(agent_id="test-buyer-001", db_path=tmp_db)

    def test_under_minimum_returns_pending_more_offers(self, tmp_path, monkeypatch):
        os.environ["MARKETPLACE_MIN_OFFERS_BEFORE_BUY"] = "3"
        db = str(tmp_path / "mkt.db")
        buyer = self._make_buyer(db)
        monkeypatch.setattr(
            buyer, "search_assets",
            lambda criteria: [
                {"listing_id": "L1", "price_usd": 10.0, "seller_rep_score": 0.5},
                {"listing_id": "L2", "price_usd": 12.0, "seller_rep_score": 0.4},
            ],
        )
        result = buyer.search_and_buy({"asset_type": "model", "max_price": 50.0})
        assert result["status"] == "pending_more_offers"
        assert result["collected"] == 2
        assert result["required"] == 3

    def test_exactly_minimum_candidates_proceeds(self, tmp_path, monkeypatch):
        os.environ["MARKETPLACE_MIN_OFFERS_BEFORE_BUY"] = "3"
        db = str(tmp_path / "mkt.db")
        buyer = self._make_buyer(db)
        candidates = [
            {"listing_id": "L1", "price_usd": 10.0, "seller_rep_score": 0.5},
            {"listing_id": "L2", "price_usd": 8.0, "seller_rep_score": 0.9},
            {"listing_id": "L3", "price_usd": 9.0, "seller_rep_score": 0.3},
        ]
        monkeypatch.setattr(buyer, "search_assets", lambda criteria: candidates)
        purchased = {}
        def fake_auto_buy(listing_id, max_price, mandate_id="", tenant_id=""):
            purchased["listing_id"] = listing_id
            return {"status": "purchased", "listing_id": listing_id, "price_paid": 8.0}
        monkeypatch.setattr(buyer, "auto_buy", fake_auto_buy)
        result = buyer.search_and_buy({"asset_type": "model", "max_price": 50.0})
        assert result.get("status") == "purchased"
        assert result["candidates_evaluated"] == 3
        assert result["fairness_guard_applied"] is True

    def test_best_utility_selected_not_first_found(self, tmp_path, monkeypatch):
        """Buyer must choose lowest utility-score (price × (1-rep)), not first candidate."""
        os.environ["MARKETPLACE_MIN_OFFERS_BEFORE_BUY"] = "3"
        db = str(tmp_path / "mkt.db")
        buyer = self._make_buyer(db)
        candidates = [
            {"listing_id": "EXPENSIVE", "price_usd": 50.0, "seller_rep_score": 0.1},
            {"listing_id": "BEST",      "price_usd": 10.0, "seller_rep_score": 0.9},
            {"listing_id": "MIDDLE",    "price_usd": 20.0, "seller_rep_score": 0.5},
        ]
        monkeypatch.setattr(buyer, "search_assets", lambda criteria: candidates)
        chosen = {}
        def fake_auto_buy(listing_id, max_price, mandate_id="", tenant_id=""):
            chosen["listing_id"] = listing_id
            return {"status": "purchased", "listing_id": listing_id, "price_paid": 10.0}
        monkeypatch.setattr(buyer, "auto_buy", fake_auto_buy)
        buyer.search_and_buy({"asset_type": "model", "max_price": 100.0})
        assert chosen["listing_id"] == "BEST"


# ── Fairness stats ────────────────────────────────────────────────────────────

class TestFairnessStats:
    def test_fairness_stats_returns_expected_keys(self, tmp_path):
        from warden.marketplace.analytics import fairness_stats
        result = fairness_stats(period_days=7, db_path=str(tmp_path / "mkt.db"))
        expected_keys = {
            "period_days",
            "total_purchases",
            "avg_candidates_evaluated",
            "first_offer_acceptance_rate",
            "min_offers_policy",
        }
        assert expected_keys <= result.keys(), f"Missing: {expected_keys - result.keys()}"

    def test_fairness_stats_period_days_matches_input(self, tmp_path):
        from warden.marketplace.analytics import fairness_stats
        result = fairness_stats(period_days=14, db_path=str(tmp_path / "mkt.db"))
        assert result["period_days"] == 14

    def test_fairness_stats_handles_empty_db_gracefully(self, tmp_path):
        from warden.marketplace.analytics import fairness_stats
        result = fairness_stats(period_days=7, db_path=str(tmp_path / "empty.db"))
        assert result["total_purchases"] == 0


# ── Confused Deputy protection ─────────────────────────────────────────────────

class TestConfusedDeputyGuard:
    """POST /analytics/query must reject cross-agent DID references when caller_agent_id is set."""

    def test_own_agent_id_is_allowed(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/analytics/query", json={
            "sql": "SELECT * FROM marketplace_agents WHERE agent_id = 'did:shadow:abc123'",
            "params": [],
            "caller_agent_id": "did:shadow:abc123",
        })
        assert r.status_code == 200
        data = r.json()
        # Confused Deputy guard passed — error (if any) is a SQLite table error, not a deputy block
        assert "Confused Deputy" not in data.get("error", "")

    def test_foreign_agent_id_literal_is_rejected(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/analytics/query", json={
            "sql": "SELECT * FROM marketplace_agents WHERE agent_id = 'did:shadow:evil-agent'",
            "params": [],
            "caller_agent_id": "did:shadow:legitimate-caller",
        })
        assert r.status_code == 200
        data = r.json()
        assert "error" in data
        assert "Confused Deputy" in data["error"]
        assert data["rows"] == []

    def test_no_caller_id_is_rejected(self, tmp_path):
        # Security fix: an unscoped query (no caller_agent_id / X-Agent-ID) could
        # read every tenant's data, so scoping is now MANDATORY — the request is
        # rejected instead of running open.
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/analytics/query", json={
            "sql": "SELECT 1 AS unscoped",
            "params": [],
            # caller_agent_id omitted
        })
        assert r.status_code == 200
        data = r.json()
        assert "error" in data
        assert data["rows"] == []

    def test_x_agent_id_header_also_enforces_scope(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post(
            "/marketplace/analytics/query",
            json={
                "sql": "SELECT * FROM marketplace_negotiations WHERE buyer_agent_id = 'did:shadow:other'",
                "params": [],
            },
            headers={"X-Agent-ID": "did:shadow:legitimate-caller"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "error" in data
        assert "Confused Deputy" in data["error"]

    def test_scoped_response_includes_scoped_by_field(self, tmp_path):
        client = _make_app(str(tmp_path / "mkt.db"))
        r = client.post("/marketplace/analytics/query", json={
            "sql": "SELECT 1 AS ping",
            "params": [],
            "caller_agent_id": "did:shadow:myagent",
        })
        assert r.status_code == 200
        data = r.json()
        assert data.get("scoped_by") == "did:shadow:myagent"
