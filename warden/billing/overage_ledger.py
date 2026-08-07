"""
warden/billing/overage_ledger.py
─────────────────────────────────
Idempotent record of what each tenant owes for going over a plan allowance.

Why this exists
───────────────
BL-19 computed an overage every month, logged it, posted a Slack summary — and
stopped. Actual collection was "delegated to `POST /billing/overage/record`,
called with an admin key in production", an endpoint nothing ever called. The
number was real; the invoice was not. Until the loop closes, overage revenue is
a spreadsheet entry, not money.

What this module guarantees
───────────────────────────
* **Idempotent per (tenant, period).** The primary key is the pair, so a cron
  that runs twice — or a retry after a partial failure — cannot double-charge.
  Re-running returns the stored row instead of raising.
* **Enforcement is opt-in.** `OVERAGE_CHARGE_ENFORCED` (default false) decides
  whether a computed charge is actually presented to the payment provider. Off,
  every charge is recorded with status ``computed`` — the same audit trail, no
  money moved. This mirrors `AUTHORIZE_PAYMENT_ENFORCED`: flipping billing on is
  a posture decision an operator makes deliberately, never a side effect of a
  deploy.
* **A failed charge is recorded as failed**, not silently dropped. `status` is
  the operator's queue: ``computed`` → not yet presented, ``charged`` → accepted
  by the provider, ``failed`` → needs a human, ``skipped`` → nothing owed.

Storage: `billing_overage_charges` in the shared billing DB.
"""
from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.billing.overage_ledger")

_DB_PATH: str = data_path("warden_billing_overage.db", "OVERAGE_LEDGER_DB_PATH")

STATUS_SKIPPED  = "skipped"
STATUS_COMPUTED = "computed"
STATUS_CHARGED  = "charged"
STATUS_FAILED   = "failed"

_DDL = """
    CREATE TABLE IF NOT EXISTS billing_overage_charges (
        tenant_id          TEXT    NOT NULL,
        period             TEXT    NOT NULL,          -- YYYY-MM
        plan               TEXT    NOT NULL,
        overage_requests   INTEGER NOT NULL DEFAULT 0,
        overage_turns      INTEGER NOT NULL DEFAULT 0,
        request_charge_usd REAL    NOT NULL DEFAULT 0.0,
        turn_charge_usd    REAL    NOT NULL DEFAULT 0.0,
        total_usd          REAL    NOT NULL DEFAULT 0.0,
        status             TEXT    NOT NULL,
        provider_ref       TEXT    NOT NULL DEFAULT '',
        detail             TEXT    NOT NULL DEFAULT '',
        created_at         TEXT    NOT NULL,
        PRIMARY KEY (tenant_id, period)
    );
    CREATE INDEX IF NOT EXISTS idx_overage_period
        ON billing_overage_charges(period, status);
"""

register("billing_overage", "warden.billing.overage_ledger", _DDL)


def charge_enforced() -> bool:
    """Read per call — an operator flips this without a code change."""
    return os.getenv("OVERAGE_CHARGE_ENFORCED", "false").lower() == "true"


def current_period() -> str:
    return datetime.now(UTC).strftime("%Y-%m")


@contextmanager
def _conn(path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    with open_db(
        "billing_overage", path, turso_name="billing", module_default_path=_DB_PATH
    ) as con:
        yield con


def get_charge(tenant_id: str, period: str, db_path: str = _DB_PATH) -> dict | None:
    """Return the stored charge for a (tenant, period), or None."""
    try:
        with _conn(db_path) as con:
            row = con.execute(
                "SELECT * FROM billing_overage_charges WHERE tenant_id = ? AND period = ?",
                (tenant_id, period),
            ).fetchone()
        return dict(row) if row else None
    except Exception as exc:
        log.warning("overage_ledger: read failed for %s/%s: %s", tenant_id, period, exc)
        return None


def list_period(period: str, db_path: str = _DB_PATH) -> list[dict]:
    """Every charge recorded for a billing period, newest total first."""
    try:
        with _conn(db_path) as con:
            rows = con.execute(
                "SELECT * FROM billing_overage_charges WHERE period = ? "
                "ORDER BY total_usd DESC",
                (period,),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as exc:
        log.warning("overage_ledger: period read failed for %s: %s", period, exc)
        return []


def settle(
    overage: dict[str, Any],
    period: str | None = None,
    db_path: str = _DB_PATH,
) -> dict:
    """
    Record — and, when enforcement is on, present — one tenant's overage.

    `overage` is a row from `billing.router._calculate_overage()`. Returns the
    stored record with an added ``idempotent`` flag telling the caller whether
    this call created it or found it already there.
    """
    tenant_id = str(overage.get("tenant_id") or "")
    if not tenant_id:
        raise ValueError("settle() requires a tenant_id")
    period = period or current_period()

    existing = get_charge(tenant_id, period, db_path)
    if existing is not None:
        return {**existing, "idempotent": True}

    total = float(overage.get("charge_usd") or 0.0)
    if total <= 0.0:
        status, ref, detail = STATUS_SKIPPED, "", "nothing owed"
    elif not charge_enforced():
        status, ref, detail = STATUS_COMPUTED, "", "OVERAGE_CHARGE_ENFORCED=false"
    else:
        status, ref, detail = _present_charge(tenant_id, total, period)

    record = {
        "tenant_id":          tenant_id,
        "period":             period,
        "plan":               str(overage.get("plan") or "unknown"),
        "overage_requests":   int(overage.get("overage_requests") or 0),
        "overage_turns":      int(overage.get("overage_turns") or 0),
        "request_charge_usd": float(overage.get("request_charge_usd") or 0.0),
        "turn_charge_usd":    float(overage.get("turn_charge_usd") or 0.0),
        "total_usd":          round(total, 4),
        "status":             status,
        "provider_ref":       ref,
        "detail":             detail,
        "created_at":         datetime.now(UTC).isoformat(),
    }

    try:
        with _conn(db_path) as con:
            con.execute(
                "INSERT OR IGNORE INTO billing_overage_charges "
                "(tenant_id,period,plan,overage_requests,overage_turns,"
                " request_charge_usd,turn_charge_usd,total_usd,status,"
                " provider_ref,detail,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record["tenant_id"], record["period"], record["plan"],
                    record["overage_requests"], record["overage_turns"],
                    record["request_charge_usd"], record["turn_charge_usd"],
                    record["total_usd"], record["status"],
                    record["provider_ref"], record["detail"], record["created_at"],
                ),
            )
    except Exception as exc:
        # The charge was presented (or deliberately not); losing the write must
        # not crash the monthly run, but it MUST be loud — an unrecorded charge
        # is the one that gets presented twice next month.
        log.error(
            "overage_ledger: WRITE FAILED tenant=%s period=%s status=%s total=%.4f: %s",
            tenant_id, period, status, total, exc,
        )
        return {**record, "idempotent": False, "persisted": False}

    _append_audit(record)
    return {**record, "idempotent": False, "persisted": True}


def _present_charge(tenant_id: str, total_usd: float, period: str) -> tuple[str, str, str]:
    """
    Hand the charge to whatever collects money, returning (status, ref, detail).

    Order: an explicit overage webhook (resellers and custom portals own their
    own billing) → Lemon Squeezy. With neither configured the charge cannot be
    presented, and that is recorded as `failed` rather than quietly as charged.
    """
    from warden.billing.overage import OVERAGE_WEBHOOK_URL, _fire_overage_webhook

    if OVERAGE_WEBHOOK_URL:
        try:
            _fire_overage_webhook(tenant_id, "requests", 0.0,
                                  int(round(total_usd * 100)), "lemonsqueezy")
            return STATUS_CHARGED, "webhook", "presented via OVERAGE_WEBHOOK_URL"
        except Exception as exc:
            log.warning("overage_ledger: webhook charge failed for %s: %s", tenant_id, exc)
            return STATUS_FAILED, "", f"webhook error: {type(exc).__name__}"

    if os.getenv("LEMONSQUEEZY_API_KEY", ""):
        # Lemon Squeezy has no one-time-charge API on a live subscription; the
        # supported path is a metered usage record, which lemon_billing owns.
        try:
            from warden.lemon_billing import get_meter_aggregator
            get_meter_aggregator().record(tenant_id, total_usd)
            return STATUS_CHARGED, "lemonsqueezy_meter", "recorded as metered usage"
        except Exception as exc:
            log.warning("overage_ledger: LS meter failed for %s: %s", tenant_id, exc)
            return STATUS_FAILED, "", f"lemonsqueezy error: {type(exc).__name__}"

    return STATUS_FAILED, "", "no billing provider configured"


def _append_audit(record: dict) -> None:
    """
    Mirror the charge into the tamper-evident billing chain.

    A bypass here leaves a charge outside the audit chain, so it is counted
    rather than swallowed — but it never blocks the settlement itself.
    """
    try:
        from warden.billing.audit_chain import append_billing_event
        append_billing_event(
            tenant_id=record["tenant_id"],
            event_type="overage_charge",
            amount_usd=record["total_usd"],
            tool_name=f"{record['period']}:{record['status']}",
        )
    except Exception as exc:
        from warden.observability import Reason, record_failopen
        record_failopen("billing_overage_audit", Reason.BACKEND_ERROR, exc)
