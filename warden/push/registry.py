"""
warden/push/registry.py
────────────────────────
SQLite-backed device token registry for Mobile SOC push notifications.

Table: push_device_tokens
  token_id        TEXT PRIMARY KEY (UUID)
  tenant_id       TEXT NOT NULL
  device_token    TEXT NOT NULL UNIQUE
  platform        TEXT NOT NULL   -- ios | android
  registered_at   TEXT NOT NULL

Max 50 device tokens per tenant — oldest evicted on overflow.
DB path: PUSH_DB_PATH env var (default /tmp/warden_push.db).
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Generator

log = logging.getLogger("warden.push.registry")

_DB_PATH = os.getenv("PUSH_DB_PATH", "/tmp/warden_push.db")
_MAX_DEVICES_PER_TENANT = 50
_db_lock = threading.RLock()


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
    con.execute("""
        CREATE TABLE IF NOT EXISTS push_device_tokens (
            token_id      TEXT PRIMARY KEY,
            tenant_id     TEXT NOT NULL,
            device_token  TEXT NOT NULL UNIQUE,
            platform      TEXT NOT NULL DEFAULT 'android',
            registered_at TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_push_tenant ON push_device_tokens(tenant_id)")


def register_device(
    tenant_id:    str,
    device_token: str,
    platform:     str = "android",
) -> dict:
    """Register a device token for a tenant. Evicts oldest if limit exceeded."""
    with _db_lock, _conn() as con:
        # Upsert — update registered_at on re-registration
        existing = con.execute(
            "SELECT token_id FROM push_device_tokens WHERE device_token = ?",
            (device_token,),
        ).fetchone()
        now = datetime.now(UTC).isoformat()
        if existing:
            con.execute(
                "UPDATE push_device_tokens SET tenant_id=?, platform=?, registered_at=? WHERE device_token=?",
                (tenant_id, platform, now, device_token),
            )
            return {"token_id": existing["token_id"], "status": "updated"}

        # Check tenant limit — evict oldest if at capacity
        count = con.execute(
            "SELECT COUNT(*) FROM push_device_tokens WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()[0]
        if count >= _MAX_DEVICES_PER_TENANT:
            oldest = con.execute(
                "SELECT token_id FROM push_device_tokens WHERE tenant_id=? ORDER BY registered_at ASC LIMIT 1",
                (tenant_id,),
            ).fetchone()
            if oldest:
                con.execute("DELETE FROM push_device_tokens WHERE token_id=?", (oldest["token_id"],))
                log.debug("push registry: evicted oldest token for tenant %s", tenant_id)

        token_id = str(uuid.uuid4())
        con.execute(
            "INSERT INTO push_device_tokens VALUES (?,?,?,?,?)",
            (token_id, tenant_id, device_token, platform, now),
        )
        return {"token_id": token_id, "status": "registered"}


def unregister_device(device_token: str) -> bool:
    """Remove a device token. Returns True if found and removed."""
    with _db_lock, _conn() as con:
        cur = con.execute(
            "DELETE FROM push_device_tokens WHERE device_token=?", (device_token,)
        )
        return cur.rowcount > 0


def get_tokens_for_tenant(tenant_id: str) -> list[str]:
    """Return all active FCM/APNs device tokens for a tenant."""
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT device_token FROM push_device_tokens WHERE tenant_id=?",
            (tenant_id,),
        ).fetchall()
    return [r["device_token"] for r in rows]


def list_devices(tenant_id: str) -> list[dict]:
    """Return device list (without full token) for the Settings UI."""
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT token_id, platform, registered_at, "
            "SUBSTR(device_token, 1, 12) || '…' AS token_preview "
            "FROM push_device_tokens WHERE tenant_id=? ORDER BY registered_at DESC",
            (tenant_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def device_count(tenant_id: str) -> int:
    with _db_lock, _conn() as con:
        return con.execute(
            "SELECT COUNT(*) FROM push_device_tokens WHERE tenant_id=?", (tenant_id,)
        ).fetchone()[0]
