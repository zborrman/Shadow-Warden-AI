"""
warden/payments/x402_balance.py
Shared x402 pre-funded balance primitive (FT-6 slice 3/3).

warden/voice/x402.py (payment-channel micropayments) and
warden/marketplace/x402_gate.py (HTTP-gate search fee) each maintained their
own copy of an identically-shaped `x402_balances` table (agent_id PRIMARY
KEY, balance_usd, updated_at) and the same three SQL statements against it,
in two separate physical SQLite files. The DDL registry requires a
per-physical-file `db_key` (see `warden/db/ddl_registry.py`), so the tables
themselves stay in their own files — voice and marketplace are different
products with different funding flows, not one shared wallet. What was
actually duplicated is the SQL, not the data, so this module owns the table's
DDL fragment plus the read/write logic; each caller keeps its own
`open_db(db_key, db_path)` connection and passes it in, so a caller that
composes another write (e.g. voice's `x402_transactions` insert) in the same
transaction still gets that for free.

Two deduct semantics are preserved exactly as each caller already had them
before this consolidation — this module does not change either one:
  deduct_strict — reject (return False, no mutation) if balance < amount.
                  Used by voice's payment-channel `deduct()`.
  deduct_floor  — always subtracts, clamped at 0, never rejects. Used by
                  marketplace's fail-open gate, which already checked
                  sufficiency separately via `_has_sufficient_balance()`
                  before this runs.
"""
from __future__ import annotations

import sqlite3
import time

X402_BALANCES_DDL = """
    CREATE TABLE IF NOT EXISTS x402_balances (
        agent_id    TEXT PRIMARY KEY,
        balance_usd REAL NOT NULL DEFAULT 0.0,
        updated_at  TEXT NOT NULL
    );
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def get_balance(con: sqlite3.Connection, agent_id: str) -> float:
    row = con.execute(
        "SELECT balance_usd FROM x402_balances WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    return float(row[0]) if row else 0.0


def credit_balance(con: sqlite3.Connection, agent_id: str, amount_usd: float) -> None:
    """Upsert: add amount_usd to the agent's balance, creating the row if absent."""
    con.execute(
        "INSERT INTO x402_balances (agent_id, balance_usd, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(agent_id) DO UPDATE SET "
        "balance_usd = balance_usd + excluded.balance_usd, updated_at = excluded.updated_at",
        (agent_id, amount_usd, _now()),
    )


def deduct_strict(con: sqlite3.Connection, agent_id: str, amount_usd: float) -> bool:
    """Reject (no mutation, return False) if balance < amount_usd."""
    row = con.execute(
        "SELECT balance_usd FROM x402_balances WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    balance = float(row[0]) if row else 0.0
    if balance < amount_usd:
        return False
    con.execute(
        "UPDATE x402_balances SET balance_usd = ?, updated_at = ? WHERE agent_id = ?",
        (balance - amount_usd, _now(), agent_id),
    )
    return True


def deduct_floor(con: sqlite3.Connection, agent_id: str, amount_usd: float) -> None:
    """Always subtract, clamped at 0. Never rejects — caller already gated sufficiency."""
    con.execute(
        "UPDATE x402_balances SET balance_usd = MAX(0, balance_usd - ?), updated_at = ? "
        "WHERE agent_id = ?",
        (amount_usd, _now(), agent_id),
    )
