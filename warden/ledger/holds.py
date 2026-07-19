"""
warden/ledger/holds.py — two-phase reservations on the ledger (FT-1).

A hold reserves value so a runaway loop cannot double-spend between checks
(the SAC-preflight "wallet run" defence, now expressed in double-entry):

    reserve  source → hold:{id}            (funds leave spendable, sit in the hold)
    capture  hold:{id} → fees + source     (charge the actual, refund the rest)
    void     hold:{id} → source            (nothing charged, full refund)

Every phase is a balanced journal transaction (Σ = 0) with a deterministic
idempotency key, so retries are safe. Lifecycle state (HELD/CAPTURED/VOIDED)
lives in a small `ledger_holds` table in the same `warden_ledger.db`; balances
stay journal-derived. Amounts are integer µUSD via `Money`.
"""
from __future__ import annotations

import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

from warden.db.connect import open_db
from warden.db.ddl_registry import register
from warden.ledger import accounts, journal
from warden.ledger.journal import _DB_PATH, Posting
from warden.ledger.money import Money

_lock = threading.RLock()

HELD = "HELD"
CAPTURED = "CAPTURED"
VOIDED = "VOIDED"

_HOLDS_DDL = """
    CREATE TABLE IF NOT EXISTS ledger_holds (
        hold_id        TEXT    PRIMARY KEY,
        source_account TEXT    NOT NULL,
        amount_micros  INTEGER NOT NULL,
        status         TEXT    NOT NULL,
        reserve_tx     TEXT    NOT NULL,
        complete_tx    TEXT    NOT NULL DEFAULT '',
        created_at     TEXT    NOT NULL,
        resolved_at    TEXT    NOT NULL DEFAULT ''
    );
"""

# Same physical DB as journal.py → same db_key, distinct module name.
register("ledger", "warden.ledger.holds", _HOLDS_DDL)


class HoldError(RuntimeError):
    """Raised on an illegal hold transition or bad amount."""


@dataclass(frozen=True)
class Hold:
    hold_id: str
    source_account: str
    amount: Money
    status: str
    reserve_tx: str
    complete_tx: str
    created_at: str
    resolved_at: str


@contextmanager
def _conn(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    path = db_path or _DB_PATH
    with open_db("ledger", path, module_default_path=_DB_PATH) as con:
        yield con


def _row_to_hold(row: sqlite3.Row) -> Hold:
    return Hold(
        hold_id=row["hold_id"], source_account=row["source_account"],
        amount=Money.from_micros(int(row["amount_micros"])), status=row["status"],
        reserve_tx=row["reserve_tx"], complete_tx=row["complete_tx"],
        created_at=row["created_at"], resolved_at=row["resolved_at"],
    )


def get_hold(hold_id: str, *, db_path: str | None = None) -> Hold | None:
    with _conn(db_path) as con:
        row = con.execute("SELECT * FROM ledger_holds WHERE hold_id=?", (hold_id,)).fetchone()
    return _row_to_hold(row) if row else None


def reserve(hold_id: str, source_account: str, amount: Money, *, db_path: str | None = None) -> Hold:
    """Move *amount* from *source_account* into ``hold:{hold_id}``. Idempotent on hold_id."""
    if not amount.is_positive():
        raise HoldError("reserve amount must be positive")
    accounts.validate(source_account)
    hold_acct = accounts.hold(hold_id)

    with _lock:
        existing = get_hold(hold_id, db_path=db_path)
        if existing is not None:
            return existing
        tx = journal.post(
            f"hold-reserve-{hold_id}", "hold_reserve",
            [Posting(source_account, -amount), Posting(hold_acct, amount)],
            db_path=db_path,
        )
        created = datetime.now(UTC).isoformat()
        with _conn(db_path) as con:
            con.execute(
                "INSERT INTO ledger_holds"
                "(hold_id, source_account, amount_micros, status, reserve_tx, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (hold_id, source_account, amount.micros, HELD, tx.tx_id, created),
            )
    return Hold(hold_id, source_account, amount, HELD, tx.tx_id, "", created, "")


def capture(hold_id: str, fee_account: str, actual: Money, *, db_path: str | None = None) -> Hold:
    """Charge *actual* to *fee_account*, refund the remainder to the source. Idempotent."""
    accounts.validate(fee_account)
    with _lock:
        h = get_hold(hold_id, db_path=db_path)
        if h is None:
            raise HoldError(f"unknown hold: {hold_id}")
        if h.status == CAPTURED:
            return h
        if h.status == VOIDED:
            raise HoldError(f"hold {hold_id} already voided")
        if actual.is_negative() or actual > h.amount:
            raise HoldError(f"capture {actual.micros} µUSD outside held {h.amount.micros}")

        hold_acct = accounts.hold(hold_id)
        refund = h.amount - actual
        postings = [Posting(hold_acct, -h.amount)]
        if actual.is_positive():
            postings.append(Posting(fee_account, actual))
        if refund.is_positive():
            postings.append(Posting(h.source_account, refund))
        # actual==0 → [hold -amt, source +amt]; actual==amt → [hold -amt, fee +amt]
        tx = journal.post(f"hold-capture-{hold_id}", "hold_capture", postings, db_path=db_path)
        resolved = datetime.now(UTC).isoformat()
        with _conn(db_path) as con:
            con.execute(
                "UPDATE ledger_holds SET status=?, complete_tx=?, resolved_at=? WHERE hold_id=?",
                (CAPTURED, tx.tx_id, resolved, hold_id),
            )
    return Hold(hold_id, h.source_account, h.amount, CAPTURED, h.reserve_tx, tx.tx_id, h.created_at, resolved)


def void(hold_id: str, *, db_path: str | None = None) -> Hold:
    """Release the hold with no charge — full refund to the source. Idempotent."""
    with _lock:
        h = get_hold(hold_id, db_path=db_path)
        if h is None:
            raise HoldError(f"unknown hold: {hold_id}")
        if h.status == VOIDED:
            return h
        if h.status == CAPTURED:
            raise HoldError(f"hold {hold_id} already captured")

        hold_acct = accounts.hold(hold_id)
        tx = journal.post(
            f"hold-void-{hold_id}", "hold_void",
            [Posting(hold_acct, -h.amount), Posting(h.source_account, h.amount)],
            db_path=db_path,
        )
        resolved = datetime.now(UTC).isoformat()
        with _conn(db_path) as con:
            con.execute(
                "UPDATE ledger_holds SET status=?, complete_tx=?, resolved_at=? WHERE hold_id=?",
                (VOIDED, tx.tx_id, resolved, hold_id),
            )
    return Hold(hold_id, h.source_account, h.amount, VOIDED, h.reserve_tx, tx.tx_id, h.created_at, resolved)
