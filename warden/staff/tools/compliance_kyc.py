"""
STAFF-05: Compliance / KYC-AML Agent tools.

screen_sanctions_list  — OFAC / EU consolidated list lookup (Rec-1: docs pre-screened)
score_kyc_profile      — composite KYC risk score (rule-based)
generate_sar           — draft Suspicious Activity Report (MEDIUM/HIGH risk only)

Rec-1 (injection guardrail): any document or profile text is sent through /filter
before entering the compliance analysis context. Fail-open: analysis continues on
filter timeout, but incident is logged.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from typing import Any

log = logging.getLogger(__name__)

from warden.config import data_path  # noqa: E402

_DB_PATH = data_path("warden_compliance.db", "COMPLIANCE_DB_PATH")

# Minimal built-in denylist for air-gapped / offline mode.
_BUILTIN_DENYLIST: set[str] = {
    "ofac_test_entity",
    "sanctioned_demo_corp",
}


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS screening_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            subject TEXT,
            list_name TEXT,
            hit INTEGER DEFAULT 0,
            score REAL,
            details TEXT,
            screened_at INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sar_drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            subject TEXT,
            risk_level TEXT,
            narrative TEXT,
            evidence TEXT,
            status TEXT DEFAULT 'DRAFT',
            created_at INTEGER
        )
    """)
    conn.commit()
    return conn


async def _prescreen_text(text: str, tenant_id: str) -> bool:
    """Rec-1: return True if text passes filter (clean), False if blocked. Fail-open = True."""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(
                "http://localhost:8001/filter",
                json={"content": text[:4000], "tenant_id": tenant_id},
            )
            if r.status_code == 200 and r.json().get("blocked"):
                log.warning("COMPLIANCE: content blocked by filter — potential injection in input")
                return False
    except Exception as exc:  # noqa: BLE001
        log.debug("COMPLIANCE: filter prescreen unavailable (fail-open): %s", exc)
    return True


async def screen_sanctions_list(
    tenant_id: str = "default",
    subject_name: str = "",
    aliases: list[str] | None = None,
    list_name: str = "OFAC_SDN",
    additional_context: str = "",
) -> dict:
    """Screen an entity against sanctions lists. Rec-1: additional_context prescreened."""
    if additional_context:
        clean = await _prescreen_text(additional_context, tenant_id)
        if not clean:
            return {
                "error": "Input blocked by injection filter. Sanitize document before submitting.",
                "hit": False,
                "score": 0.0,
            }

    all_names = [subject_name] + (aliases or [])
    hit = any(
        n.lower().strip() in _BUILTIN_DENYLIST
        for n in all_names
    )
    # Fuzzy name similarity to denylist entries
    score = 0.0
    if not hit:
        for candidate in _BUILTIN_DENYLIST:
            for n in all_names:
                overlap = len(set(n.lower().split()) & set(candidate.split("_")))
                if overlap > 0:
                    score = max(score, overlap / max(len(candidate.split("_")), 1))

    details: dict[str, Any] = {
        "list": list_name,
        "matched_entries": [subject_name] if hit else [],
        "fuzzy_score": round(score, 3),
    }

    conn = _db()
    try:
        conn.execute(
            "INSERT INTO screening_log (tenant_id,subject,list_name,hit,score,details,screened_at) VALUES (?,?,?,?,?,?,?)",
            (tenant_id, subject_name, list_name, int(hit), score, json.dumps(details), int(time.time())),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "subject": subject_name,
        "list": list_name,
        "hit": hit,
        "score": score,
        "risk": "HIGH" if hit else ("MEDIUM" if score > 0.3 else "LOW"),
        "details": details,
    }


async def score_kyc_profile(
    tenant_id: str = "default",
    entity_name: str = "",
    country: str = "",
    entity_type: str = "individual",
    pep: bool = False,
    adverse_media: bool = False,
    transaction_volume_usd: float = 0.0,
    document_text: str = "",
) -> dict:
    """Rule-based KYC composite risk score. Rec-1: document_text prescreened."""
    if document_text:
        clean = await _prescreen_text(document_text, tenant_id)
        if not clean:
            return {"error": "Document blocked by injection filter.", "risk_level": "UNKNOWN"}

    # High-risk country list (subset for illustration)
    high_risk_countries = {"ir", "kp", "sy", "cu", "sd", "mm", "ru", "by"}
    medium_risk_countries = {"cn", "ae", "tr", "ng", "pk", "vn"}

    score = 0
    flags: list[str] = []

    if country.lower() in high_risk_countries:
        score += 40
        flags.append(f"high_risk_country:{country}")
    elif country.lower() in medium_risk_countries:
        score += 20
        flags.append(f"medium_risk_country:{country}")

    if pep:
        score += 30
        flags.append("politically_exposed_person")

    if adverse_media:
        score += 25
        flags.append("adverse_media_hit")

    if transaction_volume_usd > 100_000:
        score += 15
        flags.append("high_transaction_volume")
    elif transaction_volume_usd > 10_000:
        score += 5

    if entity_type == "shell_company":
        score += 20
        flags.append("shell_company")

    risk_level = "LOW" if score < 25 else ("MEDIUM" if score < 55 else "HIGH")

    return {
        "entity_name": entity_name,
        "risk_score": min(score, 100),
        "risk_level": risk_level,
        "flags": flags,
        "requires_enhanced_due_diligence": risk_level == "HIGH",
        "escalate_to_human": risk_level in ("MEDIUM", "HIGH"),
    }


async def generate_sar(
    tenant_id: str = "default",
    subject_name: str = "",
    risk_level: str = "HIGH",
    suspicious_activity: str = "",
    transaction_details: str = "",
    evidence_ids: list[str] | None = None,
) -> dict:
    """Draft a SAR. Only for MEDIUM/HIGH risk; L2 autonomy — queued for compliance officer sign-off."""
    if risk_level not in ("MEDIUM", "HIGH"):
        return {
            "error": f"SAR not warranted for {risk_level} risk. Only MEDIUM/HIGH qualify.",
            "drafted": False,
        }

    # Rec-1: pre-screen operator-supplied freetext for prompt injection before it
    # enters the SAR narrative (fail-open on filter timeout, like the sibling tools).
    _freetext = f"{suspicious_activity}\n{transaction_details}".strip()
    if _freetext:
        clean = await _prescreen_text(_freetext, tenant_id)
        if not clean:
            return {
                "error": "Input blocked by injection filter. Sanitize the activity/transaction narrative before submitting.",
                "drafted": False,
            }

    narrative = (
        f"SUSPICIOUS ACTIVITY REPORT — DRAFT\n"
        f"Subject: {subject_name}\n"
        f"Risk Level: {risk_level}\n"
        f"Reported: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n\n"
        f"ACTIVITY DESCRIPTION:\n{suspicious_activity}\n\n"
        f"TRANSACTION DETAILS:\n{transaction_details}\n\n"
        f"Evidence references: {', '.join(evidence_ids or [])}\n\n"
        "STATUS: DRAFT — Requires compliance officer review and signature before filing."
    )

    conn = _db()
    try:
        cur = conn.execute(
            "INSERT INTO sar_drafts (tenant_id,subject,risk_level,narrative,evidence,status,created_at) VALUES (?,?,?,?,?,?,?)",
            (tenant_id, subject_name, risk_level, narrative, json.dumps(evidence_ids or []), "DRAFT", int(time.time())),
        )
        conn.commit()
        return {
            "sar_id": cur.lastrowid,
            "status": "DRAFT",
            "risk_level": risk_level,
            "narrative_preview": narrative[:300] + "...",
            "note": "Draft queued for compliance officer sign-off. Not filed autonomously.",
        }
    finally:
        conn.close()


COMPLIANCE_TOOL_HANDLERS = {
    "screen_sanctions_list": screen_sanctions_list,
    "score_kyc_profile": score_kyc_profile,
    "generate_sar": generate_sar,
}

COMPLIANCE_TOOLS = [
    {
        "name": "screen_sanctions_list",
        "description": "Screen an entity against OFAC/EU sanctions lists. Additional context is pre-screened for injection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "subject_name": {"type": "string"},
                "aliases": {"type": "array", "items": {"type": "string"}},
                "list_name": {"type": "string", "enum": ["OFAC_SDN", "EU_CONSOLIDATED", "UN_LIST"]},
                "additional_context": {"type": "string", "description": "Unstructured document text (will be pre-screened)."},
            },
            "required": ["subject_name"],
        },
    },
    {
        "name": "score_kyc_profile",
        "description": "Compute a KYC composite risk score for an entity.",
        "input_schema": {
            "type": "object",
            "properties": {
                "entity_name": {"type": "string"},
                "country": {"type": "string", "description": "ISO 3166-1 alpha-2 country code"},
                "entity_type": {"type": "string", "enum": ["individual", "company", "shell_company", "trust"]},
                "pep": {"type": "boolean"},
                "adverse_media": {"type": "boolean"},
                "transaction_volume_usd": {"type": "number"},
                "document_text": {"type": "string", "description": "ID document text — prescreened for injection."},
            },
            "required": ["entity_name"],
        },
    },
    {
        "name": "generate_sar",
        "description": "Draft a Suspicious Activity Report for MEDIUM/HIGH risk entities. Queued for compliance officer review.",
        "input_schema": {
            "type": "object",
            "properties": {
                "subject_name": {"type": "string"},
                "risk_level": {"type": "string", "enum": ["MEDIUM", "HIGH"]},
                "suspicious_activity": {"type": "string"},
                "transaction_details": {"type": "string"},
                "evidence_ids": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["subject_name", "suspicious_activity"],
        },
    },
]
