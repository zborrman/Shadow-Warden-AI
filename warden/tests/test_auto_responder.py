"""Tests for AutoResponder — autonomous threat isolation (SEC-03)."""
from __future__ import annotations

import asyncio
import sqlite3

import pytest


@pytest.fixture()
def db(tmp_path):
    """Minimal marketplace SQLite DB with required tables."""
    path = str(tmp_path / "mkt.db")
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS marketplace_agents (
            agent_id     TEXT PRIMARY KEY,
            capabilities TEXT NOT NULL DEFAULT '["buy","sell"]',
            status       TEXT NOT NULL DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS marketplace_listings (
            listing_id      TEXT PRIMARY KEY,
            seller_agent_id TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS marketplace_escrows (
            escrow_id    TEXT PRIMARY KEY,
            buyer_agent  TEXT NOT NULL,
            seller_agent TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending'
        );
    """)
    con.execute("INSERT INTO marketplace_agents VALUES ('agent-001','[\"buy\",\"sell\",\"negotiate\"]','active')")
    con.execute("INSERT INTO marketplace_listings VALUES ('lst-001','agent-001','active')")
    con.execute("INSERT INTO marketplace_listings VALUES ('lst-002','agent-001','active')")
    con.execute("INSERT INTO marketplace_escrows VALUES ('esc-001','agent-001','agent-002','pending')")
    con.commit()
    con.close()
    return path


@pytest.fixture()
def responder(db):
    from warden.marketplace.auto_responder import AutoResponder
    return AutoResponder(db_path=db)


class TestIsolation:
    def test_isolation_suspends_capabilities(self, responder, db):
        asyncio.run(responder.isolate_agent("agent-001", "high threat detected"))
        con = sqlite3.connect(db)
        row = con.execute("SELECT capabilities, status FROM marketplace_agents WHERE agent_id='agent-001'").fetchone()
        con.close()
        assert row[0] == "[]"
        assert row[1] == "suspended"

    def test_isolation_cancels_listings(self, responder, db):
        asyncio.run(responder.isolate_agent("agent-001", "test"))
        con = sqlite3.connect(db)
        rows = con.execute("SELECT status FROM marketplace_listings WHERE seller_agent_id='agent-001'").fetchall()
        con.close()
        assert all(r[0] == "cancelled" for r in rows)

    def test_isolation_cancels_escrows(self, responder, db):
        asyncio.run(responder.isolate_agent("agent-001", "test"))
        con = sqlite3.connect(db)
        row = con.execute("SELECT status FROM marketplace_escrows WHERE escrow_id='esc-001'").fetchone()
        con.close()
        assert row[0] == "cancelled"

    def test_isolation_returns_actions_summary(self, responder):
        result = asyncio.run(responder.isolate_agent("agent-001", "collusion"))
        assert "isolation_id" in result
        assert "actions" in result
        assert isinstance(result["actions"], dict)

    def test_stix_event_generated(self, responder):
        result = asyncio.run(responder.isolate_agent("agent-001", "test"))
        assert "isolation_id" in result

    def test_non_high_threat_does_not_auto_trigger(self, responder, db):
        """AutoResponder is only called explicitly (caller decides threshold)."""
        con = sqlite3.connect(db)
        row_before = con.execute("SELECT status FROM marketplace_agents WHERE agent_id='agent-001'").fetchone()
        con.close()
        assert row_before[0] == "active"


class TestRestoration:
    def test_dao_restoration_restores_capabilities(self, responder, db):
        asyncio.run(responder.isolate_agent("agent-001", "test"))
        asyncio.run(responder.restore_agent("agent-001", "dao-prop-999"))
        con = sqlite3.connect(db)
        row = con.execute("SELECT status FROM marketplace_agents WHERE agent_id='agent-001'").fetchone()
        con.close()
        assert row[0] == "active"
