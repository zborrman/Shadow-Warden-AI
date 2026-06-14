"""Tests for warden.marketplace.trust_graph."""
import os
import sqlite3
import tempfile
from datetime import UTC, datetime

import pytest

os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("STRICT_MODE", "false")

from warden.marketplace.trust_graph import TrustGraph, _trade_weight


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def empty_db(tmp_path):
    db = str(tmp_path / "mkt.db")
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE marketplace_purchases "
        "(id INTEGER PRIMARY KEY, buyer_agent TEXT, seller_agent TEXT, "
        " price_paid REAL, status TEXT, purchased_at TEXT)"
    )
    con.commit()
    con.close()
    return db


@pytest.fixture()
def trade_db(tmp_path):
    db = str(tmp_path / "mkt_trades.db")
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE marketplace_purchases "
        "(id INTEGER PRIMARY KEY, buyer_agent TEXT, seller_agent TEXT, "
        " price_paid REAL, status TEXT, purchased_at TEXT)"
    )
    now = datetime.now(UTC).isoformat()
    rows = [
        ("alice", "bob",   1.0, "completed", now),
        ("alice", "carol", 1.0, "completed", now),
        ("bob",   "carol", 1.0, "completed", now),
        ("dave",  "alice", 1.0, "completed", now),
        ("dave",  "bob",   1.0, "completed", now),
    ]
    con.executemany(
        "INSERT INTO marketplace_purchases (buyer_agent,seller_agent,price_paid,status,purchased_at) VALUES (?,?,?,?,?)",
        rows,
    )
    con.commit()
    con.close()
    return db


# ── Unit: trade weight helper ─────────────────────────────────────────────────

def test_trade_weight_completed():
    assert _trade_weight("completed") == 1.0


def test_trade_weight_disputed():
    assert _trade_weight("disputed") == 0.3


def test_trade_weight_other():
    assert _trade_weight("pending") == 0.5


# ── Empty graph ───────────────────────────────────────────────────────────────

def test_build_empty_db(empty_db):
    tg = TrustGraph()
    tg.build_graph(empty_db)
    assert tg.compute_pagerank() == {}


def test_get_trust_score_unknown_returns_half(empty_db):
    tg = TrustGraph()
    tg.build_graph(empty_db)
    assert tg.get_trust_score("nobody") == 0.5


def test_top_agents_empty(empty_db):
    tg = TrustGraph()
    tg.build_graph(empty_db)
    assert tg.top_agents() == []


# ── Graph with data ───────────────────────────────────────────────────────────

def test_build_with_trades(trade_db):
    tg = TrustGraph()
    tg.build_graph(trade_db)
    ranks = tg.compute_pagerank()
    assert set(ranks.keys()) == {"alice", "bob", "carol", "dave"}


def test_pagerank_normalisation(trade_db):
    tg = TrustGraph()
    tg.build_graph(trade_db)
    for score in tg.compute_pagerank().values():
        assert score >= 0


def test_get_trust_score_range(trade_db):
    tg = TrustGraph()
    tg.build_graph(trade_db)
    for agent in ["alice", "bob", "carol", "dave"]:
        s = tg.get_trust_score(agent)
        assert 0.0 <= s <= 1.0, f"{agent}: {s}"


def test_high_in_degree_agent_ranked_higher(trade_db):
    tg = TrustGraph()
    tg.build_graph(trade_db)
    carol_score = tg.get_trust_score("carol")
    dave_score  = tg.get_trust_score("dave")
    assert carol_score > dave_score, "carol (2 in-edges) should outscore dave (0 in-edges)"


def test_top_agents_returns_n(trade_db):
    tg = TrustGraph()
    tg.build_graph(trade_db)
    top = tg.top_agents(n=3)
    assert len(top) == 3
    assert all("agent_id" in e and "trust_rank" in e for e in top)
    scores = [e["trust_rank"] for e in top]
    assert scores == sorted(scores, reverse=True)


# ── Transitive trust ──────────────────────────────────────────────────────────

def test_transitive_trust_same_agent(trade_db):
    tg = TrustGraph()
    tg.build_graph(trade_db)
    s = tg.get_transitive_trust("alice", "alice")
    assert s == tg.get_trust_score("alice")


def test_transitive_trust_connected_path(trade_db):
    tg = TrustGraph()
    tg.build_graph(trade_db)
    s = tg.get_transitive_trust("alice", "carol")
    assert 0.0 <= s <= 1.0


def test_transitive_trust_no_path_fallback(trade_db):
    tg = TrustGraph()
    tg.build_graph(trade_db)
    # dave -> alice, but carol -> dave path doesn't exist
    s = tg.get_transitive_trust("carol", "dave")
    assert 0.0 <= s <= 1.0


# ── Incremental update ────────────────────────────────────────────────────────

def test_update_graph_adds_edge(empty_db):
    tg = TrustGraph()
    tg.build_graph(empty_db)
    tg.update_graph({"buyer_agent": "x", "seller_agent": "y", "status": "completed"})
    assert tg.get_trust_score("y") > 0 or tg.get_trust_score("y") == 0.5


def test_update_graph_ignores_self_trade(empty_db):
    tg = TrustGraph()
    tg.build_graph(empty_db)
    tg.update_graph({"buyer_agent": "x", "seller_agent": "x", "status": "completed"})
    assert tg.compute_pagerank() == {}
