"""Tests for warden/workers/clearing_outbox_relay.py (FT-4 slice 3, ARQ wrapper)."""
from __future__ import annotations

import sqlite3
import time

import pytest

from warden.marketplace.clearing import ClearingEngine
from warden.workers.clearing_outbox_relay import (
    purge_clearing_outbox,
    relay_clearing_outbox,
)


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "mkt.db")
    con = sqlite3.connect(path)
    con.execute("""
        CREATE TABLE marketplace_negotiations (
            negotiation_id TEXT PRIMARY KEY,
            buyer_agent_id TEXT,
            status TEXT,
            agreed_price REAL
        )
    """)
    con.execute(
        "INSERT INTO marketplace_negotiations VALUES (?,?,?,?)",
        ("neg-winner", "buyer-1", "active", 100.0),
    )
    con.commit()
    con.close()
    return path


class TestRelayClearingOutboxJob:
    @pytest.mark.asyncio
    async def test_default_db_path_is_a_noop_when_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "warden.marketplace.clearing._DB_PATH", str(tmp_path / "empty.db")
        )
        result = await relay_clearing_outbox(ctx={})
        assert result == {"attempted": 0, "relayed": 0, "still_pending": 0}

    @pytest.mark.asyncio
    async def test_relays_pending_row_via_default_path(self, db, monkeypatch):
        monkeypatch.setattr("warden.marketplace.clearing._DB_PATH", db)
        monkeypatch.setattr("warden.marketplace.clearing._PG_DSN", "")
        await ClearingEngine(db_path=db).clear_async("neg-winner", "buyer-1")

        async def _ok_insert(self, payload):
            return None
        monkeypatch.setattr(ClearingEngine, "_pg_insert", _ok_insert)

        result = await relay_clearing_outbox(ctx={})
        assert result == {"attempted": 1, "relayed": 1, "still_pending": 0}


class TestPurgeClearingOutboxJob:
    @pytest.mark.asyncio
    async def test_default_db_path_is_a_noop_when_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "warden.marketplace.clearing._DB_PATH", str(tmp_path / "empty.db")
        )
        result = await purge_clearing_outbox(ctx={})
        assert result == {"purged": 0, "remaining_relayed": 0}

    @pytest.mark.asyncio
    async def test_purges_old_relayed_row_via_default_path(self, db, monkeypatch):
        monkeypatch.setattr("warden.marketplace.clearing._DB_PATH", db)
        monkeypatch.setattr("warden.marketplace.clearing._PG_DSN", "")

        async def _ok_insert(self, payload):
            return None
        monkeypatch.setattr(ClearingEngine, "_pg_insert", _ok_insert)

        engine = ClearingEngine(db_path=db)
        rec = await engine.clear_async("neg-winner", "buyer-1")

        con = sqlite3.connect(db)
        old = time.time() - 40 * 86400
        con.execute(
            "UPDATE marketplace_clearing_outbox SET relayed_at = ? WHERE clearing_id = ?",
            (old, rec.clearing_id),
        )
        con.commit()
        con.close()

        result = await purge_clearing_outbox(ctx={})
        assert result == {"purged": 1, "remaining_relayed": 0}
