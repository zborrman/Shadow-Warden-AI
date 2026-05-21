"""
warden/communities/incident_register.py  (CM-35)
──────────────────────────────────────────────────
AI Incident Register — log AI-related incidents with automatic STIX 2.1
audit chain linkage.

Each incident written by `log_incident()` is appended to the community's
STIX chain as a Note bundle, giving a tamper-evident audit trail.

Tiers: Individual+ (incident_register_enabled)
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Generator

log = logging.getLogger("warden.communities.incident_register")

_DB_PATH = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
_db_lock = threading.RLock()

_SEVERITIES  = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_CATEGORIES  = {"JAILBREAK", "PII_LEAK", "HALLUCINATION", "ABUSE", "COMPLIANCE", "OTHER"}
_STATUSES    = {"open", "investigating", "resolved", "closed"}


@dataclass
class IncidentRecord:
    incident_id:      str
    tenant_id:        str
    community_id:     str
    title:            str
    severity:         str
    category:         str
    description:      str
    affected_system:  str
    vendor_id:        str
    request_id:       str
    status:           str
    resolved_at:      str | None
    stix_chain_id:    str
    created_at:       str
    updated_at:       str

    def to_dict(self) -> dict:
        return {
            "incident_id":      self.incident_id,
            "tenant_id":        self.tenant_id,
            "community_id":     self.community_id,
            "title":            self.title,
            "severity":         self.severity,
            "category":         self.category,
            "description":      self.description,
            "affected_system":  self.affected_system,
            "vendor_id":        self.vendor_id,
            "request_id":       self.request_id,
            "status":           self.status,
            "resolved_at":      self.resolved_at,
            "stix_chain_id":    self.stix_chain_id,
            "created_at":       self.created_at,
            "updated_at":       self.updated_at,
        }


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
        CREATE TABLE IF NOT EXISTS ai_incidents (
            incident_id      TEXT PRIMARY KEY,
            tenant_id        TEXT NOT NULL,
            community_id     TEXT NOT NULL DEFAULT '',
            title            TEXT NOT NULL,
            severity         TEXT NOT NULL DEFAULT 'MEDIUM',
            category         TEXT NOT NULL DEFAULT 'OTHER',
            description      TEXT NOT NULL DEFAULT '',
            affected_system  TEXT NOT NULL DEFAULT '',
            vendor_id        TEXT NOT NULL DEFAULT '',
            request_id       TEXT NOT NULL DEFAULT '',
            status           TEXT NOT NULL DEFAULT 'open',
            resolved_at      TEXT,
            stix_chain_id    TEXT NOT NULL DEFAULT '',
            created_at       TEXT NOT NULL,
            updated_at       TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_inc_tenant   ON ai_incidents(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_inc_severity ON ai_incidents(severity, status);
        CREATE INDEX IF NOT EXISTS idx_inc_status   ON ai_incidents(tenant_id, status);
    """)
    con.commit()


def log_incident(
    tenant_id: str,
    title: str,
    severity: str = "MEDIUM",
    category: str = "OTHER",
    description: str = "",
    community_id: str = "",
    affected_system: str = "",
    vendor_id: str = "",
    request_id: str = "",
    db_path: str = _DB_PATH,
) -> str:
    """Create an incident record and append to the STIX audit chain."""
    severity = severity.upper() if severity.upper() in _SEVERITIES else "MEDIUM"
    category = category.upper() if category.upper() in _CATEGORIES else "OTHER"
    now         = datetime.now(UTC).isoformat()
    incident_id = str(uuid.uuid4())

    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT INTO ai_incidents
               (incident_id, tenant_id, community_id, title, severity, category,
                description, affected_system, vendor_id, request_id,
                status, resolved_at, stix_chain_id, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (incident_id, tenant_id, community_id, title, severity, category,
             description, affected_system, vendor_id, request_id,
             "open", None, "", now, now),
        )

    # Append to STIX audit chain (non-blocking, fail-open)
    stix_id = _append_to_stix(incident_id, community_id or tenant_id, title, severity, category, db_path)
    if stix_id:
        with _db_lock, _conn(db_path) as con:
            con.execute(
                "UPDATE ai_incidents SET stix_chain_id = ? WHERE incident_id = ?",
                (stix_id, incident_id),
            )

    log.info("incident_register: logged %s severity=%s tenant=%s", incident_id, severity, tenant_id)
    return incident_id


def _append_to_stix(
    incident_id: str,
    community_id: str,
    title: str,
    severity: str,
    category: str,
    db_path: str,
) -> str:
    """Append incident as STIX Note bundle directly into sep_stix_chain. Returns chain_id or ''."""
    try:
        import hashlib  # noqa: PLC0415

        now      = datetime.now(UTC).isoformat()
        chain_id = str(uuid.uuid4())

        bundle = {
            "type":         "bundle",
            "id":           f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": [{
                "type":         "note",
                "spec_version": "2.1",
                "id":           f"note--{uuid.uuid4()}",
                "created":      now,
                "modified":     now,
                "abstract":     f"AI Incident: {title}",
                "content":      json.dumps({
                    "incident_id": incident_id,
                    "severity":    severity,
                    "category":    category,
                }),
                "object_refs": [],
                "x-warden-incident": {"incident_id": incident_id, "severity": severity},
            }],
        }
        canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
        b_hash    = hashlib.sha256(canonical.encode()).hexdigest()

        con = sqlite3.connect(db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("""
            CREATE TABLE IF NOT EXISTS sep_stix_chain (
                chain_id     TEXT PRIMARY KEY,
                community_id TEXT NOT NULL,
                transfer_id  TEXT NOT NULL UNIQUE,
                bundle_json  TEXT NOT NULL,
                bundle_hash  TEXT NOT NULL,
                prev_hash    TEXT NOT NULL,
                seq          INTEGER NOT NULL,
                created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )
        """)
        row = con.execute(
            "SELECT bundle_hash, seq FROM sep_stix_chain WHERE community_id=? ORDER BY seq DESC LIMIT 1",
            (community_id,),
        ).fetchone()
        prev_hash = row["bundle_hash"] if row else "0" * 64
        seq       = (row["seq"] + 1) if row else 0

        con.execute(
            """INSERT OR IGNORE INTO sep_stix_chain
               (chain_id, community_id, transfer_id, bundle_json, bundle_hash, prev_hash, seq, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (chain_id, community_id, incident_id, canonical, b_hash, prev_hash, seq, now),
        )
        con.commit()
        con.close()
        return chain_id
    except Exception as exc:
        log.warning("incident_register: STIX append failed for %s — %s", incident_id, exc)
        return ""


def auto_log_from_filter_event(
    tenant_id: str,
    event_dict: dict,
    db_path: str = _DB_PATH,
) -> str | None:
    """Convenience: create incident from a HIGH/BLOCK filter event dict."""
    verdict  = event_dict.get("verdict", "")
    if verdict not in ("HIGH", "BLOCK"):
        return None
    category = _infer_category(event_dict)
    title    = f"Auto-detected: {category.replace('_', ' ').title()} — {verdict}"
    return log_incident(
        tenant_id=tenant_id,
        title=title,
        severity="HIGH" if verdict == "BLOCK" else "MEDIUM",
        category=category,
        description=f"Automatically logged from filter event {event_dict.get('request_id', '')}",
        request_id=event_dict.get("request_id", ""),
        vendor_id=event_dict.get("vendor_id", ""),
        db_path=db_path,
    )


def _infer_category(event: dict) -> str:
    flags = str(event.get("flags", [])).upper()
    if "JAILBREAK" in flags:   return "JAILBREAK"
    if "PII" in flags:         return "PII_LEAK"
    if "PHISH" in flags:       return "ABUSE"
    if "SECRET" in flags:      return "COMPLIANCE"
    return "OTHER"


def update_status(
    incident_id: str,
    status: str,
    resolved_at: str | None = None,
    db_path: str = _DB_PATH,
) -> bool:
    if status not in _STATUSES:
        return False
    now = datetime.now(UTC).isoformat()
    with _db_lock, _conn(db_path) as con:
        cur = con.execute(
            "UPDATE ai_incidents SET status = ?, resolved_at = ?, updated_at = ? WHERE incident_id = ?",
            (status, resolved_at, now, incident_id),
        )
    return cur.rowcount > 0


def get_incident(incident_id: str, db_path: str = _DB_PATH) -> dict | None:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT * FROM ai_incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
    return dict(row) if row else None


def list_incidents(
    tenant_id: str,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    limit: int = 50,
    db_path: str = _DB_PATH,
) -> list[dict]:
    sql    = "SELECT * FROM ai_incidents WHERE tenant_id = ?"
    params: list = [tenant_id]
    if severity: sql += " AND severity = ?"; params.append(severity.upper())
    if status:   sql += " AND status = ?";   params.append(status)
    if category: sql += " AND category = ?"; params.append(category.upper())
    sql += f" ORDER BY created_at DESC LIMIT {int(limit)}"
    with _conn(db_path) as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_incident_stats(tenant_id: str, db_path: str = _DB_PATH) -> dict:
    with _conn(db_path) as con:
        total  = con.execute("SELECT COUNT(*) FROM ai_incidents WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        open_  = con.execute("SELECT COUNT(*) FROM ai_incidents WHERE tenant_id = ? AND status = 'open'", (tenant_id,)).fetchone()[0]
        high   = con.execute("SELECT COUNT(*) FROM ai_incidents WHERE tenant_id = ? AND severity IN ('HIGH','CRITICAL')", (tenant_id,)).fetchone()[0]
        rows   = con.execute(
            "SELECT category, COUNT(*) as cnt FROM ai_incidents WHERE tenant_id = ? GROUP BY category",
            (tenant_id,),
        ).fetchall()
    by_cat = {r["category"]: r["cnt"] for r in rows}
    return {
        "total":          total,
        "open":           open_,
        "high_critical":  high,
        "by_category":    by_cat,
    }
