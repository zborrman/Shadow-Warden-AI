"""
warden/billing/ — billing and quota enforcement helpers.

This package contains:
  - BillingStore, BILLING_AGG_INTERVAL (migrated from legacy billing.py)
  - quotas.py — per-tunnel bandwidth quota enforcement

All legacy imports (``from warden.billing import BillingStore, BILLING_AGG_INTERVAL``)
continue to work as before.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger("warden.billing")

# ── Config ────────────────────────────────────────────────────────────────────

BILLING_DB_PATH = Path(
    os.getenv("BILLING_DB_PATH", "/warden/data/billing.db")
)

LOGS_PATH = Path(
    os.getenv("LOGS_PATH", "/warden/data/logs.json")
)

BILLING_AGG_INTERVAL = int(os.getenv("BILLING_AGG_INTERVAL", "60"))   # seconds


# ── BillingStore ──────────────────────────────────────────────────────────────

class BillingStore:
    """
    Aggregates per-request cost data from logs.json into daily SQLite totals
    and enforces per-tenant monthly USD quotas.

    Typical usage (warden/main.py)::

        _billing = BillingStore()

        # In _run_filter_pipeline — quota gate (raises HTTP 402 if over cap)
        if _billing.is_quota_exceeded(tenant_id):
            raise HTTPException(402, "Monthly cost quota exceeded.")

        # Background loop (asyncio task in lifespan)
        await asyncio.sleep(BILLING_AGG_INTERVAL)
        _billing.aggregate_from_logs()

        # POST /billing/{tenant_id}/quota
        _billing.set_quota(tenant_id, quota_usd=10.0)

        # GET /billing/{tenant_id}
        usage = _billing.get_usage(tenant_id, from_date="2026-01-01", to_date="2026-03-31")
    """

    def __init__(self, db_path: Path | None = None, logs_path: Path | None = None) -> None:
        self._path      = db_path   or BILLING_DB_PATH
        self._logs_path = logs_path or LOGS_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = self._open()
        self._init_schema()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS billing_daily (
                    date      TEXT    NOT NULL,
                    tenant_id TEXT    NOT NULL,
                    requests  INTEGER NOT NULL DEFAULT 0,
                    blocked   INTEGER NOT NULL DEFAULT 0,
                    cost_usd  REAL    NOT NULL DEFAULT 0.0,
                    tokens    INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (date, tenant_id)
                );
                CREATE INDEX IF NOT EXISTS idx_bd_tenant
                    ON billing_daily(tenant_id);

                CREATE TABLE IF NOT EXISTS tenant_quotas (
                    tenant_id  TEXT PRIMARY KEY,
                    quota_usd  REAL NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agg_watermark (
                    id      INTEGER PRIMARY KEY,
                    last_ts TEXT    NOT NULL DEFAULT ''
                );
                INSERT OR IGNORE INTO agg_watermark (id, last_ts) VALUES (1, '');
            """)
            self._conn.commit()

    # ── Aggregation ───────────────────────────────────────────────────────────

    def aggregate_from_logs(self, logs_path: Path | None = None) -> int:
        """
        Read new NDJSON lines from logs.json after the stored watermark and
        upsert aggregated totals into ``billing_daily``.

        Returns the number of new log entries processed.
        """
        path = logs_path or self._logs_path
        if not path.exists():
            return 0

        watermark = self._conn.execute(
            "SELECT last_ts FROM agg_watermark WHERE id=1"
        ).fetchone()[0]

        processed = 0
        new_watermark = watermark
        # accumulate (date, tenant_id) → (requests, blocked, cost, tokens)
        buckets: dict[tuple[str, str], list[int | float]] = {}

        try:
            with path.open("r", encoding="utf-8") as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    ts = entry.get("ts", "")
                    if not ts or ts <= watermark:
                        continue   # already aggregated

                    if ts > new_watermark:
                        new_watermark = ts

                    date       = ts[:10]  # YYYY-MM-DD
                    tenant_id  = entry.get("tenant_id", "default")
                    allowed    = entry.get("allowed", True)
                    cost       = float(entry.get("attack_cost_usd", 0.0))
                    tokens     = int(entry.get("payload_tokens", 0))

                    key = (date, tenant_id)
                    if key not in buckets:
                        buckets[key] = [0, 0, 0.0, 0]
                    buckets[key][0] += 1                          # requests
                    buckets[key][1] += 0 if allowed else 1        # blocked
                    buckets[key][2] += cost                       # cost_usd
                    buckets[key][3] += tokens                     # tokens
                    processed += 1

        except OSError as exc:
            log.warning("BillingStore: could not read logs — %s", exc)
            return 0

        if not buckets:
            return 0

        with self._lock:
            for (date, tenant_id), (reqs, blocked, cost, toks) in buckets.items():
                self._conn.execute(
                    """
                    INSERT INTO billing_daily (date, tenant_id, requests, blocked, cost_usd, tokens)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(date, tenant_id) DO UPDATE SET
                        requests = requests + excluded.requests,
                        blocked  = blocked  + excluded.blocked,
                        cost_usd = cost_usd + excluded.cost_usd,
                        tokens   = tokens   + excluded.tokens
                    """,
                    (date, tenant_id, reqs, blocked, round(cost, 8), toks),
                )
            self._conn.execute(
                "UPDATE agg_watermark SET last_ts=? WHERE id=1",
                (new_watermark,),
            )
            self._conn.commit()

        log.debug("BillingStore: aggregated %d new log entries.", processed)
        return processed

    # ── Quota management ──────────────────────────────────────────────────────

    def set_quota(self, tenant_id: str, quota_usd: float) -> None:
        """Set or replace the monthly USD cost cap for a tenant."""
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO tenant_quotas (tenant_id, quota_usd, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    quota_usd  = excluded.quota_usd,
                    updated_at = excluded.updated_at
                """,
                (tenant_id, quota_usd, now),
            )
            self._conn.commit()
        log.info("BillingStore: set quota tenant=%s quota_usd=%.4f", tenant_id, quota_usd)

    def get_quota(self, tenant_id: str) -> float | None:
        """Return the monthly quota for a tenant, or None if uncapped."""
        row = self._conn.execute(
            "SELECT quota_usd FROM tenant_quotas WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        return float(row[0]) if row else None

    def is_quota_exceeded(self, tenant_id: str) -> bool:
        """
        Return True if the tenant has exceeded their monthly USD cap.
        Returns False when no quota is set (uncapped) or when under the cap.
        Fast path: single SQL query.
        """
        quota = self.get_quota(tenant_id)
        if quota is None:
            return False
        year_month = datetime.now(UTC).strftime("%Y-%m")
        row = self._conn.execute(
            """
            SELECT COALESCE(SUM(cost_usd), 0.0)
            FROM billing_daily
            WHERE tenant_id=? AND date LIKE ?
            """,
            (tenant_id, f"{year_month}-%"),
        ).fetchone()
        used = float(row[0]) if row else 0.0
        return used >= quota

    # ── Query ─────────────────────────────────────────────────────────────────

    def get_usage(
        self,
        tenant_id: str,
        from_date: str | None = None,
        to_date:   str | None = None,
    ) -> dict:
        """
        Return aggregated usage for a tenant over a date range.

        Parameters ``from_date`` and ``to_date`` are inclusive ISO-8601 dates
        (``YYYY-MM-DD``).  Omit both for all-time totals.
        """
        clauses = ["tenant_id=?"]
        params: list = [tenant_id]
        if from_date:
            clauses.append("date >= ?")
            params.append(from_date)
        if to_date:
            clauses.append("date <= ?")
            params.append(to_date)
        where = " AND ".join(clauses)
        row = self._conn.execute(
            f"""
            SELECT COALESCE(SUM(requests),0), COALESCE(SUM(blocked),0),
                   COALESCE(SUM(cost_usd),0.0), COALESCE(SUM(tokens),0)
            FROM billing_daily WHERE {where}
            """,
            params,
        ).fetchone()
        requests  = int(row[0])
        blocked   = int(row[1])
        cost_usd  = round(float(row[2]), 6)
        tokens    = int(row[3])
        quota     = self.get_quota(tenant_id)

        # Current-month total for quota_remaining calculation
        year_month = datetime.now(UTC).strftime("%Y-%m")
        month_row = self._conn.execute(
            "SELECT COALESCE(SUM(cost_usd),0.0) FROM billing_daily "
            "WHERE tenant_id=? AND date LIKE ?",
            (tenant_id, f"{year_month}-%"),
        ).fetchone()
        month_cost = round(float(month_row[0]), 6)
        quota_remaining = round(quota - month_cost, 6) if quota is not None else None

        return {
            "tenant_id":        tenant_id,
            "from_date":        from_date,
            "to_date":          to_date,
            "requests":         requests,
            "blocked":          blocked,
            "cost_usd":         cost_usd,
            "tokens":           tokens,
            "quota_usd":        quota,
            "quota_remaining":  quota_remaining,
            "month_cost_usd":   month_cost,
        }

    def get_daily_breakdown(
        self,
        tenant_id: str,
        from_date: str | None = None,
        to_date:   str | None = None,
        limit:     int        = 90,
    ) -> list[dict]:
        """Return one row per day for the tenant, newest first."""
        clauses = ["tenant_id=?"]
        params: list = [tenant_id]
        if from_date:
            clauses.append("date >= ?")
            params.append(from_date)
        if to_date:
            clauses.append("date <= ?")
            params.append(to_date)
        params.append(limit)
        rows = self._conn.execute(
            f"""
            SELECT date, requests, blocked, cost_usd, tokens
            FROM billing_daily
            WHERE {" AND ".join(clauses)}
            ORDER BY date DESC LIMIT ?
            """,
            params,
        ).fetchall()
        return [
            {
                "date":     row[0],
                "requests": row[1],
                "blocked":  row[2],
                "cost_usd": round(row[3], 6),
                "tokens":   row[4],
            }
            for row in rows
        ]

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        self._conn.close()


__all__ = ["BillingStore", "BILLING_AGG_INTERVAL", "BILLING_DB_PATH", "LOGS_PATH"]
