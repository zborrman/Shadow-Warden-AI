"""
warden/m2m_store/analytics.py
──────────────────────────────
Flat analytics tables for the M2M Marketplace Semantic Layer (SEM-02).

Creates 10 SQLite tables that back the marketplace_* semantic models:
  mp_listings, mp_trades, mp_escrow, mp_negotiations, mp_reputation,
  mp_proposals, mp_agents, mp_assets, mp_flags, mp_cross_chain

These tables use flat columns (not JSON blobs) so the Semantic Layer
engine can generate valid SQL against them directly.

Public API
──────────
  ensure_analytics_schema()   — idempotent schema bootstrap
  record_listing()            — upsert a listing row
  record_trade()              — insert a completed trade
  record_escrow()             — upsert an escrow contract
  record_negotiation()        — upsert a negotiation session
  upsert_reputation()         — upsert an agent's reputation score
  record_proposal()           — upsert a DAO proposal
  register_agent()            — upsert an agent registration
  register_asset()            — upsert a tokenized asset
  record_flag()               — insert a MAESTRO flag
  record_cross_chain_tx()     — insert a cross-chain transaction
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

from warden.config import data_path
from warden.db.connect import open_db

log = logging.getLogger("warden.m2m_store.analytics")
_db_lock = threading.RLock()


def _get_db_path() -> str:
    return os.getenv("M2M_ANALYTICS_DB_PATH", data_path("warden_m2m_store.db", "M2M_STORE_DB_PATH"))


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    # ensure_analytics_schema() is not registry-managed (it's public API also
    # called standalone with con=None elsewhere) — open_db still runs the
    # m2m_store registry DDL (from inventory.py) once; harmless double-apply
    # since every statement is idempotent (CREATE ... IF NOT EXISTS).
    path = _get_db_path()
    with open_db("m2m_store", path, module_default_path=path) as con:
        ensure_analytics_schema(con)
        yield con


def ensure_analytics_schema(con: sqlite3.Connection | None = None) -> None:
    """Create all 10 analytics tables if they do not exist (idempotent)."""
    close_after = con is None
    if con is None:
        con = sqlite3.connect(_get_db_path(), check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
        CREATE TABLE IF NOT EXISTS mp_listings (
            id              TEXT PRIMARY KEY,
            seller_agent_id TEXT NOT NULL,
            community_id    TEXT NOT NULL DEFAULT '',
            asset_type      TEXT NOT NULL DEFAULT 'general',
            chain           TEXT NOT NULL DEFAULT 'ethereum',
            price           REAL NOT NULL DEFAULT 0.0,
            quantity        INTEGER NOT NULL DEFAULT 1,
            status          TEXT NOT NULL DEFAULT 'active',
            created_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mp_trades (
            id              TEXT PRIMARY KEY,
            buyer_agent_id  TEXT NOT NULL,
            seller_agent_id TEXT NOT NULL,
            listing_id      TEXT NOT NULL DEFAULT '',
            community_id    TEXT NOT NULL DEFAULT '',
            amount_usd      REAL NOT NULL DEFAULT 0.0,
            chain           TEXT NOT NULL DEFAULT 'ethereum',
            purchased_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mp_escrow (
            id              TEXT PRIMARY KEY,
            buyer_agent_id  TEXT NOT NULL,
            seller_agent_id TEXT NOT NULL,
            community_id    TEXT NOT NULL DEFAULT '',
            chain           TEXT NOT NULL DEFAULT 'ethereum',
            amount_usd      REAL NOT NULL DEFAULT 0.0,
            status          TEXT NOT NULL DEFAULT 'funded',
            created_at      TEXT NOT NULL,
            resolved_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS mp_negotiations (
            id              TEXT PRIMARY KEY,
            buyer_agent_id  TEXT NOT NULL,
            seller_agent_id TEXT NOT NULL,
            listing_id      TEXT NOT NULL DEFAULT '',
            rounds          INTEGER NOT NULL DEFAULT 1,
            status          TEXT NOT NULL DEFAULT 'pending',
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mp_reputation (
            id              TEXT PRIMARY KEY,
            agent_id        TEXT NOT NULL,
            community_id    TEXT NOT NULL DEFAULT '',
            overall_score   REAL NOT NULL DEFAULT 0.5,
            calculated_at   TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_mp_reputation_agent
            ON mp_reputation(agent_id, community_id);

        CREATE TABLE IF NOT EXISTS mp_proposals (
            id                TEXT PRIMARY KEY,
            community_id      TEXT NOT NULL DEFAULT '',
            proposal_type     TEXT NOT NULL DEFAULT 'policy',
            voter_count       INTEGER NOT NULL DEFAULT 0,
            eligible_voters   INTEGER NOT NULL DEFAULT 1,
            status            TEXT NOT NULL DEFAULT 'pending',
            created_at        TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mp_agents (
            id              TEXT PRIMARY KEY,
            community_id    TEXT NOT NULL DEFAULT '',
            capabilities    TEXT NOT NULL DEFAULT '',
            status          TEXT NOT NULL DEFAULT 'active',
            registered_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mp_assets (
            id              TEXT PRIMARY KEY,
            community_id    TEXT NOT NULL DEFAULT '',
            asset_type      TEXT NOT NULL DEFAULT 'data',
            owner_agent_id  TEXT NOT NULL DEFAULT '',
            chain           TEXT NOT NULL DEFAULT 'ethereum',
            status          TEXT NOT NULL DEFAULT 'available',
            created_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mp_flags (
            id              TEXT PRIMARY KEY,
            agent_id        TEXT NOT NULL,
            community_id    TEXT NOT NULL DEFAULT '',
            flag_type       TEXT NOT NULL DEFAULT 'anomaly',
            threat_level    TEXT NOT NULL DEFAULT 'low',
            description     TEXT NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mp_cross_chain (
            id              TEXT PRIMARY KEY,
            agent_id        TEXT NOT NULL,
            community_id    TEXT NOT NULL DEFAULT '',
            chain           TEXT NOT NULL DEFAULT 'polygon',
            amount_usd      REAL NOT NULL DEFAULT 0.0,
            status          TEXT NOT NULL DEFAULT 'pending',
            created_at      TEXT NOT NULL
        );
    """)
    if close_after:
        con.commit()
        con.close()


# ── Write helpers ─────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(UTC).isoformat()


def record_listing(
    seller_agent_id: str,
    price: float,
    *,
    listing_id: str = "",
    community_id: str = "",
    asset_type: str = "general",
    chain: str = "ethereum",
    quantity: int = 1,
    status: str = "active",
) -> str:
    lid = listing_id or str(uuid.uuid4())
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO mp_listings"
            "(id, seller_agent_id, community_id, asset_type, chain, price, quantity, status, created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (lid, seller_agent_id, community_id, asset_type, chain, price, quantity, status, _now()),
        )
    return lid


def record_trade(
    buyer_agent_id: str,
    seller_agent_id: str,
    amount_usd: float,
    *,
    trade_id: str = "",
    listing_id: str = "",
    community_id: str = "",
    chain: str = "ethereum",
) -> str:
    tid = trade_id or str(uuid.uuid4())
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO mp_trades"
            "(id, buyer_agent_id, seller_agent_id, listing_id, community_id, amount_usd, chain, purchased_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (tid, buyer_agent_id, seller_agent_id, listing_id, community_id, amount_usd, chain, _now()),
        )
    return tid


def record_escrow(
    buyer_agent_id: str,
    seller_agent_id: str,
    amount_usd: float,
    *,
    escrow_id: str = "",
    community_id: str = "",
    chain: str = "ethereum",
    status: str = "funded",
    resolved_at: str | None = None,
) -> str:
    eid = escrow_id or str(uuid.uuid4())
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO mp_escrow"
            "(id, buyer_agent_id, seller_agent_id, community_id, chain, amount_usd, status, created_at, resolved_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (eid, buyer_agent_id, seller_agent_id, community_id, chain, amount_usd, status, _now(), resolved_at),
        )
    return eid


def record_negotiation(
    buyer_agent_id: str,
    seller_agent_id: str,
    *,
    negotiation_id: str = "",
    listing_id: str = "",
    rounds: int = 1,
    status: str = "pending",
) -> str:
    nid = negotiation_id or str(uuid.uuid4())
    now = _now()
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO mp_negotiations"
            "(id, buyer_agent_id, seller_agent_id, listing_id, rounds, status, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (nid, buyer_agent_id, seller_agent_id, listing_id, rounds, status, now, now),
        )
    return nid


def upsert_reputation(
    agent_id: str,
    overall_score: float,
    *,
    community_id: str = "",
) -> str:
    rid = str(uuid.uuid4())
    with _db_lock, _conn() as con:
        existing = con.execute(
            "SELECT id FROM mp_reputation WHERE agent_id=? AND community_id=?",
            (agent_id, community_id),
        ).fetchone()
        if existing:
            rid = existing["id"]
            con.execute(
                "UPDATE mp_reputation SET overall_score=?, calculated_at=? WHERE id=?",
                (overall_score, _now(), rid),
            )
        else:
            con.execute(
                "INSERT INTO mp_reputation(id, agent_id, community_id, overall_score, calculated_at) "
                "VALUES(?,?,?,?,?)",
                (rid, agent_id, community_id, overall_score, _now()),
            )
    return rid


def record_proposal(
    community_id: str,
    *,
    proposal_id: str = "",
    proposal_type: str = "policy",
    voter_count: int = 0,
    eligible_voters: int = 1,
    status: str = "pending",
) -> str:
    pid = proposal_id or str(uuid.uuid4())
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO mp_proposals"
            "(id, community_id, proposal_type, voter_count, eligible_voters, status, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (pid, community_id, proposal_type, voter_count, eligible_voters, status, _now()),
        )
    return pid


def register_agent(
    agent_id: str,
    *,
    community_id: str = "",
    capabilities: str = "",
    status: str = "active",
) -> str:
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO mp_agents(id, community_id, capabilities, status, registered_at) "
            "VALUES(?,?,?,?,?)",
            (agent_id, community_id, capabilities, status, _now()),
        )
    return agent_id


def register_asset(
    *,
    asset_id: str = "",
    community_id: str = "",
    asset_type: str = "data",
    owner_agent_id: str = "",
    chain: str = "ethereum",
    status: str = "available",
) -> str:
    aid = asset_id or str(uuid.uuid4())
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO mp_assets"
            "(id, community_id, asset_type, owner_agent_id, chain, status, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (aid, community_id, asset_type, owner_agent_id, chain, status, _now()),
        )
    return aid


def record_flag(
    agent_id: str,
    *,
    flag_id: str = "",
    community_id: str = "",
    flag_type: str = "anomaly",
    threat_level: str = "low",
    description: str = "",
) -> str:
    fid = flag_id or str(uuid.uuid4())
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO mp_flags"
            "(id, agent_id, community_id, flag_type, threat_level, description, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (fid, agent_id, community_id, flag_type, threat_level, description, _now()),
        )
    return fid


def record_cross_chain_tx(
    agent_id: str,
    amount_usd: float,
    *,
    tx_id: str = "",
    community_id: str = "",
    chain: str = "polygon",
    status: str = "pending",
) -> str:
    txid = tx_id or str(uuid.uuid4())
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO mp_cross_chain"
            "(id, agent_id, community_id, chain, amount_usd, status, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (txid, agent_id, community_id, chain, amount_usd, status, _now()),
        )
    return txid
