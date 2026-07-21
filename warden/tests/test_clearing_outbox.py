"""
FT-4 slice 3 — transactional outbox for ClearingEngine's Postgres relay
(`warden/marketplace/clearing.py`).

Before this slice, `_write_postgres()` was fire-and-forget: a failed attempt
just returned False and the record was gone — nothing recorded that a relay
was ever owed. Now every clearing enqueues a durable
`marketplace_clearing_outbox` row before the relay attempt; a failure leaves
it 'pending' for `relay_pending()` to retry later, instead of losing it.
"""
from __future__ import annotations

import sqlite3
import time

import pytest

from warden.marketplace.clearing import ClearingEngine, purge_relayed_outbox, relay_pending


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


def _outbox_row(db_path: str, clearing_id: str) -> tuple | None:
    con = sqlite3.connect(db_path)
    row = con.execute(
        "SELECT status, attempts, relayed_at FROM marketplace_clearing_outbox "
        "WHERE clearing_id = ?",
        (clearing_id,),
    ).fetchone()
    con.close()
    return row


class TestEnqueueOnClearAsync:
    @pytest.mark.asyncio
    async def test_no_postgres_configured_leaves_pending(self, db, monkeypatch):
        monkeypatch.setattr("warden.marketplace.clearing._PG_DSN", "")
        engine = ClearingEngine(db_path=db)
        rec = await engine.clear_async("neg-winner", "buyer-1")

        assert rec.pg_write_ok is False
        status, attempts, relayed_at = _outbox_row(db, rec.clearing_id)
        assert status == "pending"
        assert attempts == 1
        assert relayed_at is None

    @pytest.mark.asyncio
    async def test_successful_relay_marks_row_relayed(self, db, monkeypatch):
        async def _ok_insert(self, payload):
            return None
        monkeypatch.setattr(ClearingEngine, "_pg_insert", _ok_insert)

        engine = ClearingEngine(db_path=db)
        rec = await engine.clear_async("neg-winner", "buyer-1")

        assert rec.pg_write_ok is True
        status, attempts, relayed_at = _outbox_row(db, rec.clearing_id)
        assert status == "relayed"
        assert relayed_at is not None

    @pytest.mark.asyncio
    async def test_replayed_clear_does_not_duplicate_outbox_row(self, db, monkeypatch):
        monkeypatch.setattr("warden.marketplace.clearing._PG_DSN", "")
        engine = ClearingEngine(db_path=db)
        await engine.clear_async("neg-winner", "buyer-1")
        await engine.clear_async("neg-winner", "buyer-1")   # retry

        con = sqlite3.connect(db)
        n = con.execute(
            "SELECT COUNT(*) FROM marketplace_clearing_outbox WHERE clearing_id=?",
            ("clear-neg-winner",),
        ).fetchone()[0]
        con.close()
        assert n == 1


class TestRelayPending:
    @pytest.mark.asyncio
    async def test_drains_pending_rows(self, db, monkeypatch):
        monkeypatch.setattr("warden.marketplace.clearing._PG_DSN", "")
        engine = ClearingEngine(db_path=db)
        rec = await engine.clear_async("neg-winner", "buyer-1")   # fails to relay, stays pending

        async def _ok_insert(self, payload):
            return None
        monkeypatch.setattr(ClearingEngine, "_pg_insert", _ok_insert)

        summary = await relay_pending(db_path=db)
        assert summary == {"attempted": 1, "relayed": 1, "still_pending": 0}

        status, _, relayed_at = _outbox_row(db, rec.clearing_id)
        assert status == "relayed"
        assert relayed_at is not None

    @pytest.mark.asyncio
    async def test_no_pending_rows_is_a_noop(self, db):
        summary = await relay_pending(db_path=db)
        assert summary == {"attempted": 0, "relayed": 0, "still_pending": 0}

    @pytest.mark.asyncio
    async def test_still_failing_row_stays_pending_and_bumps_attempts(self, db, monkeypatch):
        monkeypatch.setattr("warden.marketplace.clearing._PG_DSN", "")
        engine = ClearingEngine(db_path=db)
        rec = await engine.clear_async("neg-winner", "buyer-1")  # attempts=1, pending

        summary = await relay_pending(db_path=db)  # still no DSN configured -> still fails
        assert summary == {"attempted": 1, "relayed": 0, "still_pending": 1}

        status, attempts, _ = _outbox_row(db, rec.clearing_id)
        assert status == "pending"
        assert attempts == 2

    @pytest.mark.asyncio
    async def test_already_relayed_row_is_idempotent_noop(self, db, monkeypatch):
        calls = {"n": 0}

        async def _counting_insert(self, payload):
            calls["n"] += 1
        monkeypatch.setattr(ClearingEngine, "_pg_insert", _counting_insert)

        engine = ClearingEngine(db_path=db)
        rec = await engine.clear_async("neg-winner", "buyer-1")  # relays immediately
        assert calls["n"] == 1

        again = await engine._relay_outbox_row(rec.clearing_id)
        assert again is True
        assert calls["n"] == 1  # no second Postgres call — already relayed


class TestPurgeRelayedOutbox:
    @pytest.mark.asyncio
    async def test_pending_row_is_never_purged_regardless_of_age(self, db, monkeypatch):
        monkeypatch.setattr("warden.marketplace.clearing._PG_DSN", "")
        engine = ClearingEngine(db_path=db)
        rec = await engine.clear_async("neg-winner", "buyer-1")  # relay fails -> stays pending

        con = sqlite3.connect(db)
        con.execute(
            "UPDATE marketplace_clearing_outbox SET created_at = ? WHERE clearing_id = ?",
            (time.time() - 999 * 86400, rec.clearing_id),
        )
        con.commit()
        con.close()

        result = purge_relayed_outbox(db_path=db, older_than_days=30.0)
        assert result == {"purged": 0, "remaining_relayed": 0}
        status, _, _ = _outbox_row(db, rec.clearing_id)
        assert status == "pending"

    @pytest.mark.asyncio
    async def test_relayed_row_younger_than_window_is_kept(self, db, monkeypatch):
        async def _ok_insert(self, payload):
            return None
        monkeypatch.setattr(ClearingEngine, "_pg_insert", _ok_insert)
        engine = ClearingEngine(db_path=db)
        rec = await engine.clear_async("neg-winner", "buyer-1")  # relays immediately

        result = purge_relayed_outbox(db_path=db, older_than_days=30.0)
        assert result == {"purged": 0, "remaining_relayed": 1}
        status, _, _ = _outbox_row(db, rec.clearing_id)
        assert status == "relayed"

    @pytest.mark.asyncio
    async def test_relayed_row_older_than_window_is_purged(self, db, monkeypatch):
        async def _ok_insert(self, payload):
            return None
        monkeypatch.setattr(ClearingEngine, "_pg_insert", _ok_insert)
        engine = ClearingEngine(db_path=db)
        rec = await engine.clear_async("neg-winner", "buyer-1")

        con = sqlite3.connect(db)
        con.execute(
            "UPDATE marketplace_clearing_outbox SET relayed_at = ? WHERE clearing_id = ?",
            (time.time() - 31 * 86400, rec.clearing_id),
        )
        con.commit()
        con.close()

        result = purge_relayed_outbox(db_path=db, older_than_days=30.0)
        assert result == {"purged": 1, "remaining_relayed": 0}
        assert _outbox_row(db, rec.clearing_id) is None

    def test_fresh_db_with_no_rows_is_a_noop(self, tmp_path):
        result = purge_relayed_outbox(db_path=str(tmp_path / "empty.db"), older_than_days=30.0)
        assert result == {"purged": 0, "remaining_relayed": 0}
