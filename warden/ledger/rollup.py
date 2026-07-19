"""
warden/ledger/rollup.py — materialized account balances (FT-1).

`journal.balance()` sums an account's postings on every call — correct, but O(n)
in history. This rollup keeps a materialized `ledger_balances(account → µUSD)`
table so hot read paths avoid the scan. It is a **cache of the journal, never a
source of truth**: every value is recomputable from postings via `refresh()`,
mirroring the GSAM rollup pattern. (Redis caching of this table is a later
optimisation; SQLite materialisation is the substrate.)

Consistency: `refresh(account)` recomputes from the journal and upserts. `balance()`
returns the materialised value when present (fast, as-of-last-refresh); on a miss
it computes live from the journal and materialises it, so a first read is always
correct. Writers (FT-2) call `refresh()` after each `journal.post()`.
"""
from __future__ import annotations

import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

from warden.db.connect import open_db
from warden.db.ddl_registry import register
from warden.ledger import accounts, journal
from warden.ledger.journal import _DB_PATH
from warden.ledger.money import Money

_lock = threading.RLock()

_BALANCES_DDL = """
    CREATE TABLE IF NOT EXISTS ledger_balances (
        account       TEXT    PRIMARY KEY,
        balance_micros INTEGER NOT NULL,
        updated_at    TEXT    NOT NULL
    );
"""

# Same physical DB as journal.py → same db_key, distinct module name.
register("ledger", "warden.ledger.rollup", _BALANCES_DDL)


@contextmanager
def _conn(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    path = db_path or _DB_PATH
    with open_db("ledger", path, module_default_path=_DB_PATH) as con:
        yield con


def refresh(account: str, *, db_path: str | None = None) -> Money:
    """Recompute *account*'s balance from the journal and materialise it."""
    accounts.validate(account)
    with _lock:
        live = journal.balance(account, db_path=db_path)
        with _conn(db_path) as con:
            con.execute(
                "INSERT INTO ledger_balances(account, balance_micros, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(account) DO UPDATE SET "
                "balance_micros=excluded.balance_micros, updated_at=excluded.updated_at",
                (account, live.micros, datetime.now(UTC).isoformat()),
            )
    return live


def refresh_all(*, db_path: str | None = None) -> int:
    """Rematerialise every account that has postings. Returns the count refreshed."""
    with _conn(db_path) as con:
        rows = con.execute("SELECT DISTINCT account FROM ledger_postings").fetchall()
    for r in rows:
        refresh(r["account"], db_path=db_path)
    return len(rows)


def materialized_balance(account: str, *, db_path: str | None = None) -> Money | None:
    """The materialised value, or None if this account was never refreshed."""
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT balance_micros FROM ledger_balances WHERE account=?", (account,)
        ).fetchone()
    return Money.from_micros(int(row["balance_micros"])) if row else None


def balance(account: str, *, db_path: str | None = None) -> Money:
    """Fast balance: materialised value if present, else compute live and materialise."""
    accounts.validate(account)
    cached = materialized_balance(account, db_path=db_path)
    if cached is not None:
        return cached
    return refresh(account, db_path=db_path)
