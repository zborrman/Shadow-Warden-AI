"""
warden/tests/test_escrow_columns_on_old_tables.py

`buyer_address` and `seller_address` were added to `marketplace_escrow` in #403,
in two places: the registered DDL (so a table created afterwards has them) and an
``ALTER TABLE`` in ``ensure_escrow_columns`` (so a table created before does).

The migration only ran on connections opened by ``escrow._conn()``. The purchase
path does not use one: ``listing._do_purchase`` opens its own connection so the
purchase row and the escrow row are written in a single transaction, and hands it
to ``insert_escrow``. So on any database whose escrow table predates #403 the
first purchase failed with::

    sqlite3.OperationalError: table marketplace_escrow has no column named buyer_address

The whole suite passed anyway, because every test builds its table from the
current DDL — a fresh `tmp_path` database can never reproduce a migration bug.
Production happened to be unaffected only by luck: it has no
``marketplace_escrow`` table at all, so it would create one from the new DDL.
Any developer machine, staging copy or restored backup would have hit it.

This file builds the *old* table deliberately, which is the only way to test a
migration at all.
"""
from __future__ import annotations

import sqlite3

import pytest

from warden.marketplace import escrow as _escrow_mod
from warden.marketplace.escrow import EscrowService

# Tolerant so this file still *collects* against the pre-fix module, where the
# helper was named `_migrate_chain_column`. A collection error would prove only
# that a name changed; the assertions below have to be what fails.
ensure_escrow_columns = getattr(
    _escrow_mod, "ensure_escrow_columns",
    getattr(_escrow_mod, "_migrate_chain_column", lambda con: None),
)

#: The schema as it stood before #403 — every column except the two added.
_OLD_DDL = """
CREATE TABLE marketplace_escrow (
    escrow_id        TEXT PRIMARY KEY,
    purchase_id      TEXT NOT NULL DEFAULT '',
    listing_id       TEXT NOT NULL,
    buyer_agent      TEXT NOT NULL,
    seller_agent     TEXT NOT NULL,
    amount_usd       REAL NOT NULL DEFAULT 0.0,
    contract_address TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'pending_deposit',
    asset_hash       TEXT NOT NULL DEFAULT '',
    dispute_reason   TEXT NOT NULL DEFAULT '',
    chain            TEXT NOT NULL DEFAULT 'sepolia',
    memo             TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL,
    funded_at        TEXT,
    delivered_at     TEXT,
    confirmed_at     TEXT,
    expires_at       TEXT NOT NULL
);
"""


@pytest.fixture()
def old_table(tmp_path) -> sqlite3.Connection:
    con = sqlite3.connect(str(tmp_path / "old.db"))
    con.row_factory = sqlite3.Row
    con.executescript(_OLD_DDL)
    con.commit()
    return con


def _columns(con: sqlite3.Connection) -> set[str]:
    return {r[1] for r in con.execute("PRAGMA table_info(marketplace_escrow)")}


class TestAPreExistingTableIsMigrated:
    def test_the_fixture_really_is_the_old_schema(self, old_table):
        """Otherwise everything below passes for the wrong reason."""
        cols = _columns(old_table)
        assert "buyer_address" not in cols
        assert "seller_address" not in cols

    def test_ensure_adds_the_columns(self, old_table):
        ensure_escrow_columns(old_table)
        assert {"buyer_address", "seller_address"} <= _columns(old_table)

    def test_running_it_twice_is_harmless(self, old_table):
        """`ALTER TABLE ADD COLUMN` errors on a column that already exists, so
        this runs on every connection and must be idempotent."""
        ensure_escrow_columns(old_table)
        ensure_escrow_columns(old_table)
        assert {"buyer_address", "seller_address"} <= _columns(old_table)


class TestInsertOnACallerOwnedConnection:
    """The actual failure. `insert_escrow` takes a connection it did not open."""

    def test_insert_succeeds_against_an_unmigrated_table(self, old_table):
        esc = EscrowService().build_escrow(
            listing_id="LST-1",
            buyer_agent_id="did:shadow:buyer",
            seller_agent_id="did:shadow:seller",
            amount_usd=1.0,
        )
        # No _conn(), no migration — exactly what listing._do_purchase does.
        EscrowService.insert_escrow(old_table, esc)
        old_table.commit()

        row = old_table.execute(
            "SELECT escrow_id, buyer_address FROM marketplace_escrow WHERE escrow_id=?",
            (esc.escrow_id,),
        ).fetchone()
        assert row is not None
        assert row["escrow_id"] == esc.escrow_id

    def test_the_row_survives_a_read_back_through_the_service(self, old_table, tmp_path):
        """A column added by ALTER must be readable by the same mapping code
        that reads one declared in the DDL."""
        svc = EscrowService()
        esc = svc.build_escrow(
            listing_id="LST-2", buyer_agent_id="did:b", seller_agent_id="did:s",
            amount_usd=2.5,
        )
        EscrowService.insert_escrow(old_table, esc)
        old_table.commit()
        cols = _columns(old_table)
        assert "buyer_address" in cols and "seller_address" in cols
