"""
STAFF-02: BDR Agent tools.

crm_search          — query lead pipeline
crm_upsert_lead     — create or update a lead (no contracts, no auto-send)
send_email_draft    — push to draft queue, never sends autonomously
schedule_meeting_slot — add a proposed slot to calendar queue

Storage: Redis keys under staff:bdr:{tenant_id}:*
"""
from __future__ import annotations

import logging
import time

log = logging.getLogger(__name__)

from warden.config import data_path  # noqa: E402

_DB_PATH = data_path("warden_bdr.db", "BDR_DB_PATH")


def _db():
    import sqlite3
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            company TEXT NOT NULL,
            contact TEXT,
            email TEXT,
            status TEXT DEFAULT 'NEW',
            score REAL DEFAULT 0.0,
            notes TEXT,
            created_at INTEGER,
            updated_at INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            to_email TEXT NOT NULL,
            subject TEXT,
            body TEXT,
            lead_id INTEGER,
            status TEXT DEFAULT 'PENDING_REVIEW',
            created_at INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meeting_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            contact TEXT,
            proposed_at TEXT,
            duration_min INTEGER DEFAULT 30,
            status TEXT DEFAULT 'PROPOSED',
            created_at INTEGER
        )
    """)
    conn.commit()
    return conn


async def crm_search(
    tenant_id: str = "default",
    query: str = "",
    status: str | None = None,
    limit: int = 20,
) -> dict:
    conn = _db()
    try:
        sql = "SELECT * FROM leads WHERE tenant_id=?"
        params: list = [tenant_id]
        if query:
            sql += " AND (company LIKE ? OR contact LIKE ? OR email LIKE ?)"
            params += [f"%{query}%", f"%{query}%", f"%{query}%"]
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += f" ORDER BY updated_at DESC LIMIT {min(limit, 100)}"
        rows = conn.execute(sql, params).fetchall()
        return {"leads": [dict(r) for r in rows], "count": len(rows)}
    finally:
        conn.close()


async def crm_upsert_lead(
    tenant_id: str = "default",
    company: str = "",
    contact: str = "",
    email: str = "",
    status: str = "NEW",
    score: float = 0.0,
    notes: str = "",
    lead_id: int | None = None,
) -> dict:
    conn = _db()
    now = int(time.time())
    try:
        if lead_id:
            conn.execute(
                "UPDATE leads SET company=?,contact=?,email=?,status=?,score=?,notes=?,updated_at=? WHERE id=? AND tenant_id=?",
                (company, contact, email, status, score, notes, now, lead_id, tenant_id),
            )
            conn.commit()
            return {"lead_id": lead_id, "action": "updated"}
        cur = conn.execute(
            "INSERT INTO leads (tenant_id,company,contact,email,status,score,notes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (tenant_id, company, contact, email, status, score, notes, now, now),
        )
        conn.commit()
        return {"lead_id": cur.lastrowid, "action": "created"}
    finally:
        conn.close()


async def send_email_draft(
    tenant_id: str = "default",
    to_email: str = "",
    subject: str = "",
    body: str = "",
    lead_id: int | None = None,
) -> dict:
    """Queue a draft for human review — never sends autonomously."""
    conn = _db()
    now = int(time.time())
    try:
        cur = conn.execute(
            "INSERT INTO email_drafts (tenant_id,to_email,subject,body,lead_id,status,created_at) VALUES (?,?,?,?,?,?,?)",
            (tenant_id, to_email, subject, body, lead_id, "PENDING_REVIEW", now),
        )
        conn.commit()
        draft_id = cur.lastrowid
        log.info("BDR: email draft %d queued for human review (to=%s)", draft_id, to_email)
        return {
            "draft_id": draft_id,
            "status": "PENDING_REVIEW",
            "note": "Draft queued for human approval — not sent autonomously.",
        }
    finally:
        conn.close()


async def schedule_meeting_slot(
    tenant_id: str = "default",
    contact: str = "",
    proposed_at: str = "",
    duration_min: int = 30,
) -> dict:
    """Propose a calendar slot — places in queue, human confirms."""
    conn = _db()
    now = int(time.time())
    try:
        cur = conn.execute(
            "INSERT INTO meeting_slots (tenant_id,contact,proposed_at,duration_min,status,created_at) VALUES (?,?,?,?,?,?)",
            (tenant_id, contact, proposed_at, duration_min, "PROPOSED", now),
        )
        conn.commit()
        return {
            "slot_id": cur.lastrowid,
            "status": "PROPOSED",
            "note": "Proposed slot queued for human confirmation.",
        }
    finally:
        conn.close()


BDR_TOOL_HANDLERS = {
    "crm_search": crm_search,
    "crm_upsert_lead": crm_upsert_lead,
    "send_email_draft": send_email_draft,
    "schedule_meeting_slot": schedule_meeting_slot,
}

BDR_TOOLS = [
    {
        "name": "crm_search",
        "description": "Search leads in the CRM pipeline.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "status": {"type": "string", "enum": ["NEW", "QUALIFIED", "CONTACTED", "WON", "LOST"]},
                "limit": {"type": "integer"},
            },
        },
    },
    {
        "name": "crm_upsert_lead",
        "description": "Create or update a lead. No contract authority.",
        "input_schema": {
            "type": "object",
            "properties": {
                "company": {"type": "string"},
                "contact": {"type": "string"},
                "email": {"type": "string"},
                "status": {"type": "string"},
                "score": {"type": "number"},
                "notes": {"type": "string"},
                "lead_id": {"type": "integer"},
            },
            "required": ["company"],
        },
    },
    {
        "name": "send_email_draft",
        "description": "Queue a personalized email draft for human review. Never sends automatically.",
        "input_schema": {
            "type": "object",
            "properties": {
                "to_email": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "lead_id": {"type": "integer"},
            },
            "required": ["to_email", "subject", "body"],
        },
    },
    {
        "name": "schedule_meeting_slot",
        "description": "Propose a meeting time slot. Human must confirm before it is booked.",
        "input_schema": {
            "type": "object",
            "properties": {
                "contact": {"type": "string"},
                "proposed_at": {"type": "string", "description": "ISO 8601 datetime"},
                "duration_min": {"type": "integer"},
            },
            "required": ["contact", "proposed_at"],
        },
    },
]
