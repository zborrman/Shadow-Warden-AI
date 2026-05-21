"""
warden/business_intelligence/repository.py  (CM-39)
─────────────────────────────────────────────────────
SQLite cache for generated BI reports — avoids re-computing expensive
aggregations on every API call.  TTL = 15 minutes per cache entry.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

log = logging.getLogger("warden.business_intelligence.repository")

_DB_PATH = os.getenv("BI_DB_PATH", "/tmp/warden_bi.db")
_db_lock = threading.RLock()
_CACHE_TTL_MINUTES = 15


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    with _db_lock:
        con = sqlite3.connect(_DB_PATH)
        con.execute("PRAGMA journal_mode=WAL")
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()


def _ensure_schema() -> None:
    with _conn() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS intelligence_cache (
                cache_key   TEXT PRIMARY KEY,
                tenant_id   TEXT NOT NULL,
                report_type TEXT NOT NULL DEFAULT 'unknown',
                payload     TEXT NOT NULL DEFAULT '{}',
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL
            )
        """)
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_ic_tenant ON intelligence_cache(tenant_id)"
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_ic_expires ON intelligence_cache(expires_at)"
        )


_ensure_schema()


def cache_get(cache_key: str) -> dict | None:
    now = datetime.now(UTC).isoformat()
    with _conn() as con:
        row = con.execute(
            "SELECT payload FROM intelligence_cache WHERE cache_key=? AND expires_at>?",
            (cache_key, now),
        ).fetchone()
    if row:
        try:
            return json.loads(row["payload"])
        except Exception:
            return None
    return None


def cache_set(cache_key: str, tenant_id: str, report_type: str, payload: dict) -> None:
    now = datetime.now(UTC)
    expires = (now + timedelta(minutes=_CACHE_TTL_MINUTES)).isoformat()
    with _conn() as con:
        con.execute(
            """INSERT OR REPLACE INTO intelligence_cache
               (cache_key, tenant_id, report_type, payload, created_at, expires_at)
               VALUES (?,?,?,?,?,?)""",
            (cache_key, tenant_id, report_type, json.dumps(payload), now.isoformat(), expires),
        )


def cache_invalidate(tenant_id: str) -> int:
    with _conn() as con:
        cur = con.execute(
            "DELETE FROM intelligence_cache WHERE tenant_id=?", (tenant_id,)
        )
        return cur.rowcount


def cache_purge_expired() -> int:
    now = datetime.now(UTC).isoformat()
    with _conn() as con:
        cur = con.execute("DELETE FROM intelligence_cache WHERE expires_at<=?", (now,))
        return cur.rowcount


def cache_stats(tenant_id: str) -> dict:
    now = datetime.now(UTC).isoformat()
    with _conn() as con:
        total = con.execute(
            "SELECT COUNT(*) FROM intelligence_cache WHERE tenant_id=?", (tenant_id,)
        ).fetchone()[0]
        live = con.execute(
            "SELECT COUNT(*) FROM intelligence_cache WHERE tenant_id=? AND expires_at>?",
            (tenant_id, now),
        ).fetchone()[0]
    return {"total_entries": total, "live_entries": live, "ttl_minutes": _CACHE_TTL_MINUTES}
