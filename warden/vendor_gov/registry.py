"""
warden/vendor_gov/registry.py  (BL-22)
───────────────────────────────────────
AI Vendor Governance Register — SQLite-backed registry of AI vendors and
their Data Processing Agreements (DPAs), with expiry tracking and alerts.

Tiers: Individual+ (vendor_governance_enabled)
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Generator

log = logging.getLogger("warden.vendor_gov.registry")

_DB_PATH  = os.getenv("VENDOR_GOV_DB_PATH", "/tmp/warden_vendor.db")
_db_lock  = threading.RLock()

_PROVIDER_TYPES = {"LLM", "EMBEDDING", "TOOL", "AGENT", "OTHER"}
_RISK_TIERS     = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_VENDOR_STATUSES = {"active", "review", "terminated"}
_DPA_TYPES      = {"GDPR_ART28", "CCPA", "ISO27001", "HIPAA", "CUSTOM"}
_DPA_STATUSES   = {"active", "expired", "draft", "terminated"}


@dataclass
class VendorRecord:
    vendor_id:     str
    tenant_id:     str
    display_name:  str
    website:       str       = ""
    provider_type: str       = "LLM"
    risk_tier:     str       = "MEDIUM"
    status:        str       = "active"
    contact_email: str       = ""
    tags:          dict      = field(default_factory=dict)
    created_at:    str       = ""
    updated_at:    str       = ""

    def to_dict(self) -> dict:
        return {
            "vendor_id":     self.vendor_id,
            "tenant_id":     self.tenant_id,
            "display_name":  self.display_name,
            "website":       self.website,
            "provider_type": self.provider_type,
            "risk_tier":     self.risk_tier,
            "status":        self.status,
            "contact_email": self.contact_email,
            "tags":          self.tags,
            "created_at":    self.created_at,
            "updated_at":    self.updated_at,
        }


@dataclass
class DPARecord:
    dpa_id:       str
    vendor_id:    str
    tenant_id:    str
    dpa_type:     str  = "GDPR_ART28"
    signed_at:    str | None = None
    expires_at:   str | None = None
    doc_ref:      str  = ""
    status:       str  = "active"
    notes:        str  = ""
    created_at:   str  = ""

    def to_dict(self) -> dict:
        return {
            "dpa_id":     self.dpa_id,
            "vendor_id":  self.vendor_id,
            "tenant_id":  self.tenant_id,
            "dpa_type":   self.dpa_type,
            "signed_at":  self.signed_at,
            "expires_at": self.expires_at,
            "doc_ref":    self.doc_ref,
            "status":     self.status,
            "notes":      self.notes,
            "created_at": self.created_at,
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
        CREATE TABLE IF NOT EXISTS ai_vendors (
            vendor_id     TEXT PRIMARY KEY,
            tenant_id     TEXT NOT NULL,
            display_name  TEXT NOT NULL,
            website       TEXT NOT NULL DEFAULT '',
            provider_type TEXT NOT NULL DEFAULT 'LLM',
            risk_tier     TEXT NOT NULL DEFAULT 'MEDIUM',
            status        TEXT NOT NULL DEFAULT 'active',
            contact_email TEXT NOT NULL DEFAULT '',
            tags          TEXT NOT NULL DEFAULT '{}',
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_av_tenant ON ai_vendors(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_av_status  ON ai_vendors(tenant_id, status);

        CREATE TABLE IF NOT EXISTS vendor_dpa_records (
            dpa_id        TEXT PRIMARY KEY,
            vendor_id     TEXT NOT NULL,
            tenant_id     TEXT NOT NULL,
            dpa_type      TEXT NOT NULL DEFAULT 'GDPR_ART28',
            signed_at     TEXT,
            expires_at    TEXT,
            doc_ref       TEXT NOT NULL DEFAULT '',
            status        TEXT NOT NULL DEFAULT 'active',
            notes         TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_dpa_vendor  ON vendor_dpa_records(vendor_id);
        CREATE INDEX IF NOT EXISTS idx_dpa_tenant  ON vendor_dpa_records(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_dpa_expires ON vendor_dpa_records(expires_at);
    """)
    con.commit()


def register_vendor(
    tenant_id: str,
    display_name: str,
    website: str = "",
    provider_type: str = "LLM",
    risk_tier: str = "MEDIUM",
    contact_email: str = "",
    tags: dict | None = None,
    db_path: str = _DB_PATH,
) -> VendorRecord:
    provider_type = provider_type.upper() if provider_type.upper() in _PROVIDER_TYPES else "OTHER"
    risk_tier     = risk_tier.upper() if risk_tier.upper() in _RISK_TIERS else "MEDIUM"
    now           = datetime.now(UTC).isoformat()
    vendor_id     = str(uuid.uuid4())
    tags_json     = json.dumps(tags or {})

    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT INTO ai_vendors
               (vendor_id, tenant_id, display_name, website, provider_type,
                risk_tier, status, contact_email, tags, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (vendor_id, tenant_id, display_name, website, provider_type,
             risk_tier, "active", contact_email, tags_json, now, now),
        )

    log.info("vendor_gov: registered vendor %s (tenant=%s)", vendor_id, tenant_id)
    return VendorRecord(
        vendor_id=vendor_id, tenant_id=tenant_id, display_name=display_name,
        website=website, provider_type=provider_type, risk_tier=risk_tier,
        status="active", contact_email=contact_email, tags=tags or {},
        created_at=now, updated_at=now,
    )


def update_vendor(
    vendor_id: str,
    tenant_id: str,
    *,
    display_name: str | None = None,
    website: str | None = None,
    risk_tier: str | None = None,
    status: str | None = None,
    contact_email: str | None = None,
    tags: dict | None = None,
    db_path: str = _DB_PATH,
) -> bool:
    sets, params = [], []
    if display_name  is not None: sets.append("display_name = ?");  params.append(display_name)
    if website       is not None: sets.append("website = ?");       params.append(website)
    if risk_tier     is not None: sets.append("risk_tier = ?");     params.append(risk_tier.upper())
    if status        is not None: sets.append("status = ?");        params.append(status)
    if contact_email is not None: sets.append("contact_email = ?"); params.append(contact_email)
    if tags          is not None: sets.append("tags = ?");          params.append(json.dumps(tags))
    if not sets:
        return False
    sets.append("updated_at = ?")
    params.extend([datetime.now(UTC).isoformat(), vendor_id, tenant_id])
    with _db_lock, _conn(db_path) as con:
        cur = con.execute(
            f"UPDATE ai_vendors SET {', '.join(sets)} WHERE vendor_id = ? AND tenant_id = ?",
            params,
        )
    return cur.rowcount > 0


def get_vendor(vendor_id: str, tenant_id: str, db_path: str = _DB_PATH) -> VendorRecord | None:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT * FROM ai_vendors WHERE vendor_id = ? AND tenant_id = ?",
            (vendor_id, tenant_id),
        ).fetchone()
    if not row:
        return None
    return _row_to_vendor(row)


def list_vendors(
    tenant_id: str,
    status: str | None = None,
    risk_tier: str | None = None,
    provider_type: str | None = None,
    db_path: str = _DB_PATH,
) -> list[VendorRecord]:
    sql    = "SELECT * FROM ai_vendors WHERE tenant_id = ?"
    params: list = [tenant_id]
    if status:        sql += " AND status = ?";        params.append(status)
    if risk_tier:     sql += " AND risk_tier = ?";     params.append(risk_tier.upper())
    if provider_type: sql += " AND provider_type = ?"; params.append(provider_type.upper())
    sql += " ORDER BY created_at DESC"
    with _conn(db_path) as con:
        rows = con.execute(sql, params).fetchall()
    return [_row_to_vendor(r) for r in rows]


def _row_to_vendor(row: sqlite3.Row) -> VendorRecord:
    return VendorRecord(
        vendor_id=row["vendor_id"], tenant_id=row["tenant_id"],
        display_name=row["display_name"], website=row["website"],
        provider_type=row["provider_type"], risk_tier=row["risk_tier"],
        status=row["status"], contact_email=row["contact_email"],
        tags=json.loads(row["tags"] or "{}"),
        created_at=row["created_at"], updated_at=row["updated_at"],
    )


# ── DPA tracking ──────────────────────────────────────────────────────────────

def add_dpa(
    vendor_id: str,
    tenant_id: str,
    dpa_type: str = "GDPR_ART28",
    signed_at: str | None = None,
    expires_at: str | None = None,
    doc_ref: str = "",
    notes: str = "",
    db_path: str = _DB_PATH,
) -> DPARecord:
    dpa_type = dpa_type.upper() if dpa_type.upper() in _DPA_TYPES else "CUSTOM"
    now      = datetime.now(UTC).isoformat()
    dpa_id   = str(uuid.uuid4())
    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT INTO vendor_dpa_records
               (dpa_id, vendor_id, tenant_id, dpa_type, signed_at, expires_at,
                doc_ref, status, notes, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (dpa_id, vendor_id, tenant_id, dpa_type, signed_at, expires_at,
             doc_ref, "active", notes, now),
        )
    log.info("vendor_gov: DPA %s added for vendor %s", dpa_id, vendor_id)
    return DPARecord(
        dpa_id=dpa_id, vendor_id=vendor_id, tenant_id=tenant_id,
        dpa_type=dpa_type, signed_at=signed_at, expires_at=expires_at,
        doc_ref=doc_ref, status="active", notes=notes, created_at=now,
    )


def list_dpas(vendor_id: str, tenant_id: str, db_path: str = _DB_PATH) -> list[DPARecord]:
    with _conn(db_path) as con:
        rows = con.execute(
            "SELECT * FROM vendor_dpa_records WHERE vendor_id = ? AND tenant_id = ? ORDER BY created_at DESC",
            (vendor_id, tenant_id),
        ).fetchall()
    return [_row_to_dpa(r) for r in rows]


def get_expiring_dpas(
    tenant_id: str,
    within_days: int = 30,
    db_path: str = _DB_PATH,
) -> list[DPARecord]:
    now    = datetime.now(UTC)
    cutoff = (now + timedelta(days=within_days)).isoformat()
    with _conn(db_path) as con:
        rows = con.execute(
            """SELECT * FROM vendor_dpa_records
               WHERE tenant_id = ? AND status = 'active'
                 AND expires_at IS NOT NULL AND expires_at <= ?
               ORDER BY expires_at ASC""",
            (tenant_id, cutoff),
        ).fetchall()
    return [_row_to_dpa(r) for r in rows]


def _row_to_dpa(row: sqlite3.Row) -> DPARecord:
    return DPARecord(
        dpa_id=row["dpa_id"], vendor_id=row["vendor_id"], tenant_id=row["tenant_id"],
        dpa_type=row["dpa_type"], signed_at=row["signed_at"], expires_at=row["expires_at"],
        doc_ref=row["doc_ref"], status=row["status"], notes=row["notes"],
        created_at=row["created_at"],
    )


def get_vendor_stats(tenant_id: str, db_path: str = _DB_PATH) -> dict:
    with _conn(db_path) as con:
        total     = con.execute("SELECT COUNT(*) FROM ai_vendors WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        active    = con.execute("SELECT COUNT(*) FROM ai_vendors WHERE tenant_id = ? AND status = 'active'", (tenant_id,)).fetchone()[0]
        high_risk = con.execute("SELECT COUNT(*) FROM ai_vendors WHERE tenant_id = ? AND risk_tier IN ('HIGH','CRITICAL')", (tenant_id,)).fetchone()[0]
        dpa_count = con.execute("SELECT COUNT(*) FROM vendor_dpa_records WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        expiring  = con.execute(
            "SELECT COUNT(*) FROM vendor_dpa_records WHERE tenant_id = ? AND status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?",
            (tenant_id, (datetime.now(UTC) + timedelta(days=30)).isoformat()),
        ).fetchone()[0]
    return {
        "total_vendors":    total,
        "active_vendors":   active,
        "high_risk_vendors": high_risk,
        "total_dpas":       dpa_count,
        "expiring_dpas_30d": expiring,
    }
