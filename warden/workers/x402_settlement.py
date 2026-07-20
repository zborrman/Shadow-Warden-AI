"""
warden/workers/x402_settlement.py
──────────────────────────────────
ARQ worker: x402 pending-deduction settlement (FT-4 slice 1).

x402_gate.deduct_payment() queues every search-fee deduction into
x402_pending_deductions with status='pending' and debits the agent's
pre-funded balance immediately — but nothing has ever drained that queue.
Rows accumulate forever with no settlement, no payout/audit summary, and
no way to tell "charged" from "reconciled."

This worker periodically settles pending deductions: marks each row
'settled' with a settled_at timestamp and returns a per-run summary
(deduction count, distinct agents, total USD) for audit/reconciliation.

Idempotent: the settling UPDATE is gated on `status='pending'`, so
re-running only ever touches rows still pending — safe to run on a
schedule, safe under a concurrent run, safe to call ad hoc.

Fail-soft per row: one corrupt/locked row is skipped and counted in
`errors`; the rest of the batch still settles. A read failure (e.g. the
DB file doesn't exist yet — no x402 activity so far) returns an empty
summary rather than raising.

Environment variables
──────────────────────
  MARKETPLACE_X402_DB_PATH — SQLite location (shared with x402_gate.py)
"""
from __future__ import annotations

import contextlib
import logging
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from warden.config import data_path

log = logging.getLogger("warden.workers.x402_settlement")

_DB_PATH = data_path("warden_x402_marketplace.db", "MARKETPLACE_X402_DB_PATH")


@dataclass
class SettlementSummary:
    settled_count:  int = 0
    agents_settled: int = 0
    total_usd:      str = "0"
    errors:         int = 0


def _ensure_schema(con: sqlite3.Connection) -> None:
    """Additive-only: adds `settled_at` if missing. Deliberately does NOT
    (re)create `x402_pending_deductions` — that table is x402_gate.py's, and
    duplicating its DDL here would re-declare its float-typed money column a
    second time in source text (tripping the no-new-float-money-columns
    ratchet) for a table this module never originates. If the table doesn't
    exist yet (no x402 activity so far), the SELECT in
    `settle_pending_deductions` fails and is caught there — same fail-soft
    outcome, no schema duplication."""
    with contextlib.suppress(Exception):
        con.execute(
            "ALTER TABLE x402_pending_deductions ADD COLUMN settled_at TEXT NOT NULL DEFAULT ''"
        )


def settle_pending_deductions(db_path: str = _DB_PATH) -> SettlementSummary:
    """Mark every currently-pending x402 deduction as settled.

    Returns a SettlementSummary for logging/reconciliation. Never raises.
    """
    summary = SettlementSummary()
    try:
        con = sqlite3.connect(db_path)
        _ensure_schema(con)
        rows = con.execute(
            "SELECT deduction_id, agent_id, amount_usd FROM x402_pending_deductions "
            "WHERE status = 'pending'"
        ).fetchall()
    except Exception as exc:
        log.warning("x402_settlement: read failed: %s", exc)
        return summary

    if not rows:
        con.close()
        return summary

    now   = datetime.now(UTC).isoformat()
    total = Decimal("0")
    agents: set[str] = set()

    for deduction_id, agent_id, amount_usd in rows:
        try:
            cur = con.execute(
                "UPDATE x402_pending_deductions SET status='settled', settled_at=? "
                "WHERE deduction_id=? AND status='pending'",
                (now, deduction_id),
            )
            if cur.rowcount:
                con.commit()
                total += Decimal(str(amount_usd))
                agents.add(agent_id)
                summary.settled_count += 1
        except Exception as exc:
            summary.errors += 1
            log.warning("x402_settlement: failed to settle %s: %s", deduction_id, exc)

    con.close()
    summary.agents_settled = len(agents)
    summary.total_usd = str(total)
    log.info(
        "x402_settlement: settled=%d agents=%d total_usd=%s errors=%d",
        summary.settled_count, summary.agents_settled, summary.total_usd, summary.errors,
    )
    return summary


async def settle_x402_deductions(ctx: dict) -> dict:
    """ARQ cron entry point — see settle_pending_deductions() for the logic.

    Passes the current module-level `_DB_PATH` explicitly rather than relying
    on the function's bound default (defaults are evaluated once at def-time,
    so a test's `monkeypatch.setattr(module, "_DB_PATH", ...)` would otherwise
    have no effect on this call).
    """
    summary = settle_pending_deductions(db_path=_DB_PATH)
    return {
        "settled_count":  summary.settled_count,
        "agents_settled": summary.agents_settled,
        "total_usd":      summary.total_usd,
        "errors":         summary.errors,
    }
