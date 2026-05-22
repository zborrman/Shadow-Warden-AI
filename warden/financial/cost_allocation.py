"""
warden/financial/cost_allocation.py  (BL-23)
─────────────────────────────────────────────
AI Cost Allocation — track per-department/vendor AI spend.

Records are inserted manually or imported from logs.json.
Supports monthly summary, department breakdown, vendor spend queries.

Tiers: Community Business+ (cost_allocation_enabled)
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

log = logging.getLogger("warden.financial.cost_allocation")

_DB_PATH = os.getenv("COST_ALLOC_DB_PATH", "/tmp/warden_costs.db")
_db_lock = threading.RLock()

_COST_TYPES = {"api_usage", "audit", "compliance", "incident", "training", "other"}


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
        CREATE TABLE IF NOT EXISTS cost_allocations (
            alloc_id     TEXT PRIMARY KEY,
            tenant_id    TEXT NOT NULL,
            vendor_id    TEXT NOT NULL DEFAULT '',
            department   TEXT NOT NULL DEFAULT 'default',
            project      TEXT NOT NULL DEFAULT '',
            cost_type    TEXT NOT NULL DEFAULT 'api_usage',
            amount_usd   REAL NOT NULL DEFAULT 0.0,
            currency     TEXT NOT NULL DEFAULT 'USD',
            period_month TEXT NOT NULL,
            notes        TEXT NOT NULL DEFAULT '',
            recorded_at  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ca_tenant_month ON cost_allocations(tenant_id, period_month);
        CREATE INDEX IF NOT EXISTS idx_ca_dept         ON cost_allocations(tenant_id, department);
        CREATE INDEX IF NOT EXISTS idx_ca_vendor       ON cost_allocations(vendor_id);
        CREATE INDEX IF NOT EXISTS idx_ca_type         ON cost_allocations(tenant_id, cost_type);
    """)
    con.commit()


def record_cost(
    tenant_id: str,
    amount_usd: float,
    vendor_id: str = "",
    department: str = "default",
    project: str = "",
    cost_type: str = "api_usage",
    currency: str = "USD",
    notes: str = "",
    period_month: str | None = None,
    db_path: str = _DB_PATH,
) -> str:
    cost_type    = cost_type if cost_type in _COST_TYPES else "other"
    period_month = period_month or datetime.now(UTC).strftime("%Y-%m")
    now          = datetime.now(UTC).isoformat()
    alloc_id     = str(uuid.uuid4())

    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT INTO cost_allocations
               (alloc_id, tenant_id, vendor_id, department, project, cost_type,
                amount_usd, currency, period_month, notes, recorded_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (alloc_id, tenant_id, vendor_id, department, project, cost_type,
             round(amount_usd, 6), currency, period_month, notes, now),
        )
    return alloc_id


def get_monthly_summary(
    tenant_id: str,
    period_month: str | None = None,
    db_path: str = _DB_PATH,
) -> dict:
    period_month = period_month or datetime.now(UTC).strftime("%Y-%m")
    with _conn(db_path) as con:
        total = con.execute(
            "SELECT COALESCE(SUM(amount_usd),0) FROM cost_allocations WHERE tenant_id = ? AND period_month = ?",
            (tenant_id, period_month),
        ).fetchone()[0]
        by_dept = con.execute(
            """SELECT department, COALESCE(SUM(amount_usd),0) as spend
               FROM cost_allocations WHERE tenant_id = ? AND period_month = ?
               GROUP BY department ORDER BY spend DESC""",
            (tenant_id, period_month),
        ).fetchall()
        by_vendor = con.execute(
            """SELECT vendor_id, COALESCE(SUM(amount_usd),0) as spend
               FROM cost_allocations WHERE tenant_id = ? AND period_month = ? AND vendor_id != ''
               GROUP BY vendor_id ORDER BY spend DESC""",
            (tenant_id, period_month),
        ).fetchall()
        by_type = con.execute(
            """SELECT cost_type, COALESCE(SUM(amount_usd),0) as spend
               FROM cost_allocations WHERE tenant_id = ? AND period_month = ?
               GROUP BY cost_type ORDER BY spend DESC""",
            (tenant_id, period_month),
        ).fetchall()
    return {
        "period_month": period_month,
        "total_usd":    round(total, 2),
        "by_department": {r["department"]: round(r["spend"], 2) for r in by_dept},
        "by_vendor":     {r["vendor_id"]:  round(r["spend"], 2) for r in by_vendor},
        "by_type":       {r["cost_type"]:  round(r["spend"], 2) for r in by_type},
    }


def get_department_breakdown(
    tenant_id: str,
    months: int = 3,
    db_path: str = _DB_PATH,
) -> list[dict]:
    """Return per-department totals for the last N months."""
    result = []
    now    = datetime.now(UTC)
    for i in range(months):
        # go back i months from current
        year  = now.year
        month = now.month - i
        while month <= 0:
            month += 12
            year  -= 1
        period = f"{year:04d}-{month:02d}"
        s      = get_monthly_summary(tenant_id, period, db_path=db_path)
        result.append(s)
    return result


def get_vendor_spend(
    tenant_id: str,
    vendor_id: str,
    months: int = 3,
    db_path: str = _DB_PATH,
) -> dict:
    """Return monthly spend breakdown for a specific vendor."""
    rows_by_month: dict[str, float] = {}
    now = datetime.now(UTC)
    for i in range(months):
        year  = now.year
        month = now.month - i
        while month <= 0:
            month += 12
            year  -= 1
        period = f"{year:04d}-{month:02d}"
        with _conn(db_path) as con:
            total = con.execute(
                "SELECT COALESCE(SUM(amount_usd),0) FROM cost_allocations WHERE tenant_id=? AND vendor_id=? AND period_month=?",
                (tenant_id, vendor_id, period),
            ).fetchone()[0]
        rows_by_month[period] = round(total, 2)
    return {"vendor_id": vendor_id, "monthly": rows_by_month, "total": round(sum(rows_by_month.values()), 2)}


def import_from_logs(
    tenant_id: str,
    logs_path: str | None = None,
    db_path: str = _DB_PATH,
) -> int:
    """Parse logs.json and record one api_usage entry per HIGH/BLOCK event (cost $0.002 each)."""
    path = logs_path or os.getenv("LOGS_PATH", "/warden/data/logs.json")
    count = 0
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("verdict") in ("HIGH", "BLOCK"):
                        record_cost(
                            tenant_id=tenant_id,
                            amount_usd=0.002,
                            cost_type="api_usage",
                            notes=f"auto-import:{entry.get('request_id','')}",
                            db_path=db_path,
                        )
                        count += 1
                except Exception:
                    pass
    except FileNotFoundError:
        log.debug("cost_allocation: logs file not found: %s", path)
    return count
