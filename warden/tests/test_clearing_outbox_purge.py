"""
FT-4 remainder — retention/cleanup for the clearing outbox
(`warden/marketplace/clearing.py::purge_relayed_outbox`).

The outbox (FT-4 slice 3) accumulated relayed rows forever with no pruning.
`purge_relayed_outbox()` deletes only status='relayed' rows past a retention
window; a 'pending' row is never purged regardless of age.
"""
from __future__ import annotations

import sqlite3
import time

import pytest

from warden.marketplace.clearing import ClearingEngine, purge_relayed_outbox


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


def _insert_outbox_row(db_path: str, clearing_id: str, status: str, relayed_at: float | None) -> None:
    con = sqlite3.connect(db_path)
    con.execute(
        "INSERT INTO marketplace_clearing_outbox "
        "(clearing_id, payload_json, status, attempts, created_at, relayed_at) "
        "VALUES (?, '{}', ?, 0, ?, ?)",
        (clearing_id, status, time.time(), relayed_at),
    )
    con.commit()
    con.close()


def _outbox_ids(db_path: str) -> set[str]:
    con = sqlite3.connect(db_path)
    rows = con.execute("SELECT clearing_id FROM marketplace_clearing_outbox").fetchall()
    con.close()
    return {r[0] for r in rows}


class TestPurgeRelayedOutbox:
    def test_no_table_yet_is_a_noop(self, tmp_path):
        summary = purge_relayed_outbox(db_path=str(tmp_path / "fresh.db"))
        assert summary == {"purged": 0, "remaining_relayed": 0}

    def test_old_relayed_row_is_purged(self, db):
        ClearingEngine(db_path=db)  # ensures tables exist
        old = time.time() - 40 * 86400
        _insert_outbox_row(db, "clear-old", "relayed", old)

        summary = purge_relayed_outbox(db_path=db, older_than_days=30.0)
        assert summary == {"purged": 1, "remaining_relayed": 0}
        assert "clear-old" not in _outbox_ids(db)

    def test_recent_relayed_row_is_kept(self, db):
        ClearingEngine(db_path=db)
        recent = time.time() - 1 * 86400
        _insert_outbox_row(db, "clear-recent", "relayed", recent)

        summary = purge_relayed_outbox(db_path=db, older_than_days=30.0)
        assert summary == {"purged": 0, "remaining_relayed": 1}
        assert "clear-recent" in _outbox_ids(db)

    def test_old_pending_row_is_never_purged(self, db):
        ClearingEngine(db_path=db)
        old = time.time() - 90 * 86400
        _insert_outbox_row(db, "clear-stale-pending", "pending", None)
        # Backdate created_at directly to simulate an old pending row.
        con = sqlite3.connect(db)
        con.execute(
            "UPDATE marketplace_clearing_outbox SET created_at = ? WHERE clearing_id = ?",
            (old, "clear-stale-pending"),
        )
        con.commit()
        con.close()

        summary = purge_relayed_outbox(db_path=db, older_than_days=30.0)
        assert summary["purged"] == 0
        assert "clear-stale-pending" in _outbox_ids(db)

    @pytest.mark.asyncio
    async def test_real_clearing_flow_then_purge(self, db, monkeypatch):
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

        summary = purge_relayed_outbox(db_path=db, older_than_days=30.0)
        assert summary == {"purged": 1, "remaining_relayed": 0}

    def test_respects_limit(self, db):
        ClearingEngine(db_path=db)
        old = time.time() - 40 * 86400
        for i in range(5):
            _insert_outbox_row(db, f"clear-old-{i}", "relayed", old)

        summary = purge_relayed_outbox(db_path=db, older_than_days=30.0, limit=2)
        assert summary["purged"] == 2
        assert summary["remaining_relayed"] == 3
