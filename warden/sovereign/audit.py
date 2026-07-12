"""
warden/sovereign/audit.py
──────────────────────────
Sovereign routing decision audit trail.

Every call to warden.sovereign.router.route() is persisted here so that
compliance teams can reconstruct the full routing history for any entity
transfer.  Records are immutable once written (INSERT OR IGNORE).

DB: SEP_DB_PATH (shared with sep.py / data_pod.py).
Table: sep_routing_audit

Columns
───────
  id            TEXT PK  — UUID v4
  tenant_id     TEXT     — requesting tenant
  entity_ueciid TEXT     — SEP entity (nullable — not all routes are for SEP transfers)
  tunnel_id     TEXT     — selected tunnel (NULL when DIRECT or BLOCK)
  jurisdiction  TEXT     — selected jurisdiction code
  action        TEXT     — TUNNEL | DIRECT | BLOCK
  compliant     INTEGER  — 1 / 0
  reason        TEXT     — plain-English explanation
  frameworks    TEXT     — JSON array of compliance framework names
  latency_ms    REAL     — expected additional latency (NULL when unknown)
  recorded_at   TEXT     — ISO-8601 UTC timestamp
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import UTC, datetime

from warden.config import data_path

log = logging.getLogger("warden.sovereign.audit")

_DB_PATH = data_path("warden_sep.db", "SEP_DB_PATH")
_lock    = threading.RLock()


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS sep_routing_audit (
            id            TEXT PRIMARY KEY,
            tenant_id     TEXT NOT NULL,
            entity_ueciid TEXT,
            tunnel_id     TEXT,
            jurisdiction  TEXT NOT NULL,
            action        TEXT NOT NULL,
            compliant     INTEGER NOT NULL DEFAULT 0,
            reason        TEXT NOT NULL,
            frameworks    TEXT NOT NULL DEFAULT '[]',
            latency_ms    REAL,
            recorded_at   TEXT NOT NULL
        )
    """)
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_sra_tenant ON sep_routing_audit(tenant_id)"
    )
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_sra_action ON sep_routing_audit(action)"
    )
    con.commit()
    return con


def log_routing_decision(
    tenant_id:     str,
    route_decision,                   # RouteDecision dataclass from router.py
    entity_ueciid: str | None = None,
) -> str:
    """
    Persist a RouteDecision to the audit trail.

    Returns the generated record id (UUID v4).
    Fails silently — audit failures must never block the routing path.
    """
    record_id = str(uuid.uuid4())
    now       = datetime.now(UTC).isoformat()
    try:
        with _lock:
            con = _conn()
            con.execute(
                """
                INSERT OR IGNORE INTO sep_routing_audit
                  (id, tenant_id, entity_ueciid, tunnel_id, jurisdiction,
                   action, compliant, reason, frameworks, latency_ms, recorded_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    record_id,
                    tenant_id,
                    entity_ueciid,
                    getattr(route_decision, "tunnel_id",     None),
                    getattr(route_decision, "jurisdiction",  "UNKNOWN"),
                    getattr(route_decision, "action",        "UNKNOWN"),
                    1 if getattr(route_decision, "compliant", False) else 0,
                    getattr(route_decision, "reason",        ""),
                    json.dumps(getattr(route_decision, "frameworks", [])),
                    getattr(route_decision, "latency_hint_ms", None),
                    now,
                ),
            )
            con.commit()
            con.close()
    except Exception as exc:
        log.debug("sovereign audit: write failed: %s", exc)
    return record_id


def list_decisions(
    tenant_id: str | None = None,
    action:    str | None = None,
    limit:     int        = 200,
) -> list[dict]:
    """
    Query routing audit records.  Returns newest-first.
    """
    try:
        with _lock:
            con = _conn()
            where_parts: list[str] = []
            params: list = []
            if tenant_id:
                where_parts.append("tenant_id = ?")
                params.append(tenant_id)
            if action:
                where_parts.append("action = ?")
                params.append(action)
            where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
            rows = con.execute(
                f"SELECT * FROM sep_routing_audit {where} ORDER BY recorded_at DESC LIMIT ?",
                params + [limit],
            ).fetchall()
            cols = [d[0] for d in con.execute("PRAGMA table_info(sep_routing_audit)").fetchall()]
            con.close()
            result = []
            for row in rows:
                d = dict(zip(cols, row, strict=False))
                d["frameworks"] = json.loads(d.get("frameworks") or "[]")
                d["compliant"]  = bool(d.get("compliant"))
                result.append(d)
            return result
    except Exception as exc:
        log.debug("sovereign audit: list failed: %s", exc)
        return []
