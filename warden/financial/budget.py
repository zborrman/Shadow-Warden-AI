"""
warden/financial/budget.py  (BL-24)
──────────────────────────────────────
AI Budget Dashboard — per-department budget caps and approval workflows.

Uses the same SQLite DB as cost_allocation.py (COST_ALLOC_DB_PATH).

Tiers: Community Business+ (budget_dashboard_enabled)
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

from warden.config import data_path

log = logging.getLogger("warden.financial.budget")

_DB_PATH = data_path("warden_costs.db", "COST_ALLOC_DB_PATH")
_db_lock = threading.RLock()

_PERIOD_TYPES   = {"monthly", "quarterly", "annual"}
_APPROVAL_STATUSES = {"pending", "approved", "rejected"}


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS budget_caps (
            cap_id      TEXT PRIMARY KEY,
            tenant_id   TEXT NOT NULL,
            department  TEXT NOT NULL DEFAULT 'default',
            period_type TEXT NOT NULL DEFAULT 'monthly',
            cap_usd     REAL NOT NULL,
            alert_pct   REAL NOT NULL DEFAULT 0.80,
            status      TEXT NOT NULL DEFAULT 'active',
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bc_tenant_dept ON budget_caps(tenant_id, department);

        CREATE TABLE IF NOT EXISTS budget_approvals (
            approval_id  TEXT PRIMARY KEY,
            tenant_id    TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            department   TEXT NOT NULL,
            amount_usd   REAL NOT NULL,
            reason       TEXT NOT NULL DEFAULT '',
            status       TEXT NOT NULL DEFAULT 'pending',
            reviewed_by  TEXT,
            reviewed_at  TEXT,
            created_at   TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ba_tenant  ON budget_approvals(tenant_id, status);
        CREATE INDEX IF NOT EXISTS idx_ba_dept    ON budget_approvals(tenant_id, department);
    """)
    con.commit()


def set_budget_cap(
    tenant_id: str,
    cap_usd: float,
    department: str = "default",
    period_type: str = "monthly",
    alert_pct: float = 0.80,
    db_path: str = _DB_PATH,
) -> str:
    period_type = period_type if period_type in _PERIOD_TYPES else "monthly"
    alert_pct   = max(0.0, min(1.0, alert_pct))
    now         = datetime.now(UTC).isoformat()
    cap_id      = str(uuid.uuid4())

    with _db_lock, _conn(db_path) as con:
        existing = con.execute(
            "SELECT cap_id FROM budget_caps WHERE tenant_id=? AND department=? AND period_type=? AND status='active'",
            (tenant_id, department, period_type),
        ).fetchone()
        if existing:
            con.execute(
                "UPDATE budget_caps SET cap_usd=?, alert_pct=?, updated_at=? WHERE cap_id=?",
                (round(cap_usd, 2), alert_pct, now, existing["cap_id"]),
            )
            return existing["cap_id"]
        con.execute(
            """INSERT INTO budget_caps
               (cap_id, tenant_id, department, period_type, cap_usd, alert_pct, status, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (cap_id, tenant_id, department, period_type, round(cap_usd, 2), alert_pct, "active", now, now),
        )
    return cap_id


def check_budget(
    tenant_id: str,
    department: str,
    current_spend: float,
    period_type: str = "monthly",
    db_path: str = _DB_PATH,
) -> dict:
    """Return budget status for a department."""
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT * FROM budget_caps WHERE tenant_id=? AND department=? AND period_type=? AND status='active'",
            (tenant_id, department, period_type),
        ).fetchone()

    if not row:
        return {"status": "no_cap", "department": department, "current_spend": round(current_spend, 2)}

    cap       = row["cap_usd"]
    alert_pct = row["alert_pct"]
    pct_used  = current_spend / cap if cap > 0 else 1.0
    remaining = max(0.0, cap - current_spend)

    if pct_used >= 1.0:
        status = "over_budget"
    elif pct_used >= alert_pct:
        status = "alert"
    else:
        status = "ok"

    return {
        "status":        status,
        "department":    department,
        "cap_usd":       cap,
        "current_spend": round(current_spend, 2),
        "remaining":     round(remaining, 2),
        "pct_used":      round(pct_used, 3),
        "alert_pct":     alert_pct,
    }


def get_realtime_status(
    tenant_id: str,
    db_path: str = _DB_PATH,
) -> dict:
    """All departments' live spend vs cap for current month."""
    period_month = datetime.now(UTC).strftime("%Y-%m")
    with _conn(db_path) as con:
        caps = con.execute(
            "SELECT * FROM budget_caps WHERE tenant_id=? AND status='active'",
            (tenant_id,),
        ).fetchall()
        if caps:
            con.execute("""CREATE TABLE IF NOT EXISTS cost_allocations (
                alloc_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
                vendor_id TEXT NOT NULL DEFAULT '', department TEXT NOT NULL DEFAULT 'default',
                project TEXT NOT NULL DEFAULT '', cost_type TEXT NOT NULL DEFAULT 'api_usage',
                amount_usd REAL NOT NULL DEFAULT 0.0, currency TEXT NOT NULL DEFAULT 'USD',
                period_month TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
                recorded_at TEXT NOT NULL
            )""")
            spends = con.execute(
                """SELECT department, COALESCE(SUM(amount_usd),0) as spend
                   FROM cost_allocations WHERE tenant_id=? AND period_month=?
                   GROUP BY department""",
                (tenant_id, period_month),
            ).fetchall()
        else:
            spends = []

    spend_map = {r["department"]: r["spend"] for r in spends}
    departments = []
    for cap in caps:
        dept    = cap["department"]
        spend   = spend_map.get(dept, 0.0)
        status  = check_budget(tenant_id, dept, spend, cap["period_type"], db_path=db_path)
        departments.append(status)

    return {
        "tenant_id":    tenant_id,
        "period_month": period_month,
        "departments":  departments,
        "total_caps":   len(caps),
    }


# ── Approval workflow ─────────────────────────────────────────────────────────

def request_approval(
    tenant_id: str,
    requested_by: str,
    department: str,
    amount_usd: float,
    reason: str = "",
    db_path: str = _DB_PATH,
) -> str:
    now         = datetime.now(UTC).isoformat()
    approval_id = str(uuid.uuid4())
    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT INTO budget_approvals
               (approval_id, tenant_id, requested_by, department, amount_usd, reason, status, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (approval_id, tenant_id, requested_by, department, round(amount_usd, 2), reason, "pending", now),
        )
    log.info("budget: approval requested %s dept=%s amount=%.2f", approval_id, department, amount_usd)
    return approval_id


def resolve_approval(
    approval_id: str,
    reviewed_by: str,
    approve: bool,
    db_path: str = _DB_PATH,
) -> bool:
    status = "approved" if approve else "rejected"
    now    = datetime.now(UTC).isoformat()
    with _db_lock, _conn(db_path) as con:
        cur = con.execute(
            "UPDATE budget_approvals SET status=?, reviewed_by=?, reviewed_at=? WHERE approval_id=? AND status='pending'",
            (status, reviewed_by, now, approval_id),
        )
    return cur.rowcount > 0


def list_approvals(
    tenant_id: str,
    status: str | None = None,
    db_path: str = _DB_PATH,
) -> list[dict]:
    sql    = "SELECT * FROM budget_approvals WHERE tenant_id = ?"
    params: list = [tenant_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql   += " ORDER BY created_at DESC LIMIT 100"
    with _conn(db_path) as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]
