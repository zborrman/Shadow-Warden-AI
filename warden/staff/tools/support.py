"""
STAFF-04: Support Agent tools.

get_ticket          — fetch support ticket by ID
resolve_ticket_kb   — look up resolution from KB, mark ticket resolved
issue_refund        — Rec-3: emit HMAC-signed RefundIntent (boundary enforces cap)
get_billing_status  — read current billing/subscription status

Rec-3 (payment isolation): issue_refund never touches a payment API key.
It calls AuthorizationBoundary.sign_refund_intent() and stores the intent
in the DB for the billing backend to countersign.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import time
from decimal import Decimal

log = logging.getLogger(__name__)

_DB_PATH = os.getenv("SUPPORT_DB_PATH", "/tmp/warden_support.db")

# Minimal knowledge base — production would be a vector DB
_KB: dict[str, str] = {
    "billing": "Check the billing portal at /portal/billing for invoice history.",
    "login": "Clear cookies and try incognito mode. Reset password at /auth/reset.",
    "api_key": "API keys are created in /portal/api-keys. Rotate immediately if compromised.",
    "performance": "Check /platform/metrics for latency. Contact support if P99 > 50ms.",
    "refund": "Refunds under $10 are processed within 24h. Larger amounts require manager approval.",
    "gdpr": "Submit GDPR requests to privacy@shadow-warden-ai.com with subject GDPR-REQUEST.",
}


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            subject TEXT,
            body TEXT,
            status TEXT DEFAULT 'OPEN',
            resolution TEXT,
            created_at INTEGER,
            resolved_at INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS refund_intents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            agent_id TEXT,
            amount_usd TEXT,
            reason TEXT,
            sig TEXT,
            status TEXT DEFAULT 'PENDING_COUNTERSIGN',
            created_at INTEGER
        )
    """)
    conn.commit()
    return conn


async def get_ticket(
    tenant_id: str = "default",
    ticket_id: int | None = None,
    status: str | None = None,
    limit: int = 10,
) -> dict:
    conn = _db()
    try:
        if ticket_id is not None:
            row = conn.execute(
                "SELECT * FROM tickets WHERE id=? AND tenant_id=?", (ticket_id, tenant_id)
            ).fetchone()
            if row is None:
                return {"error": f"Ticket {ticket_id} not found"}
            return {"ticket": dict(row)}

        sql = "SELECT * FROM tickets WHERE tenant_id=?"
        params: list = [tenant_id]
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += f" ORDER BY created_at DESC LIMIT {min(limit, 50)}"
        rows = conn.execute(sql, params).fetchall()
        return {"tickets": [dict(r) for r in rows], "count": len(rows)}
    finally:
        conn.close()


async def resolve_ticket_kb(
    tenant_id: str = "default",
    ticket_id: int = 0,
    category: str = "",
    custom_resolution: str = "",
) -> dict:
    """Look up resolution from KB and mark ticket resolved."""
    kb_answer = _KB.get(category.lower(), "")
    resolution = custom_resolution or kb_answer or "Resolved by support agent."

    conn = _db()
    try:
        row = conn.execute(
            "SELECT * FROM tickets WHERE id=? AND tenant_id=?", (ticket_id, tenant_id)
        ).fetchone()
        if row is None:
            return {"error": f"Ticket {ticket_id} not found"}

        conn.execute(
            "UPDATE tickets SET status='RESOLVED', resolution=?, resolved_at=? WHERE id=? AND tenant_id=?",
            (resolution, int(time.time()), ticket_id, tenant_id),
        )
        conn.commit()
        return {
            "ticket_id": ticket_id,
            "status": "RESOLVED",
            "resolution": resolution,
            "kb_category": category,
            "kb_hit": bool(kb_answer),
        }
    finally:
        conn.close()


_HIGH_RISK_REFUND_COUNTRIES: frozenset[str] = frozenset(
    {"IR", "KP", "SY", "CU", "SD", "MM", "RU", "BY"}
)


async def issue_refund(
    tenant_id: str = "default",
    agent_id: str = "support",
    amount_usd: str = "0.00",
    reason: str = "",
    country: str = "",
) -> dict:
    """
    Rec-3: emit a signed RefundIntent. Does not call any payment API.
    The billing backend countersigns and processes after human review for > $0.

    A2A integration: if country is in HIGH_RISK_REFUND_COUNTRIES, calls
    ComplianceAgent.score_kyc_profile before issuing the intent. If KYC
    returns HIGH risk, escalates to human instead of creating the intent.
    """
    # A2A pre-check: route to ComplianceAgent if high-risk country
    if country.upper() in _HIGH_RISK_REFUND_COUNTRIES:
        try:
            from warden.staff.a2a import get_a2a_router  # noqa: PLC0415
            router = get_a2a_router()
            kyc = await router.route(
                "support", "compliance", "score_kyc_profile",
                {
                    "tenant_id": tenant_id,
                    "entity_name": f"refund_requestor_{tenant_id}",
                    "country": country.upper(),
                    "entity_type": "individual",
                    "pep": False,
                    "adverse_media": False,
                    "transaction_volume_usd": float(amount_usd or "0"),
                },
            )
            if kyc.get("risk_level") == "HIGH":
                log.warning(
                    "SUPPORT: A2A KYC HIGH-RISK — refund blocked tenant=%s country=%s call_id=%s",
                    tenant_id, country, kyc.get("call_id"),
                )
                return {
                    "issued": False,
                    "escalated": True,
                    "escalation_reason": "high_risk_country_kyc_block",
                    "country": country,
                    "kyc_risk_level": kyc.get("risk_level"),
                    "kyc_flags": kyc.get("flags", []),
                    "a2a_call_id": kyc.get("call_id"),
                    "note": "Refund escalated to human review — ComplianceAgent scored HIGH risk.",
                }
        except Exception as exc:  # noqa: BLE001 — A2A fail-open
            log.warning("SUPPORT: A2A KYC call failed (fail-open, proceeding): %s", exc)

    from warden.staff.boundaries import get_registry  # noqa: PLC0415

    reg = get_registry()
    boundary = reg.get(agent_id)
    if boundary is None:
        return {"error": f"No boundary found for agent '{agent_id}'"}

    try:
        intent = boundary.sign_refund_intent(tenant_id, Decimal(amount_usd), reason)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "issued": False}

    conn = _db()
    try:
        cur = conn.execute(
            "INSERT INTO refund_intents (tenant_id,agent_id,amount_usd,reason,sig,status,created_at) VALUES (?,?,?,?,?,?,?)",
            (tenant_id, agent_id, amount_usd, reason, intent["sig"], "PENDING_COUNTERSIGN", int(time.time())),
        )
        conn.commit()
        log.info("SUPPORT: refund intent #%d queued tenant=%s amount=$%s", cur.lastrowid, tenant_id, amount_usd)
        return {
            "intent_id": cur.lastrowid,
            "issued": True,
            "requires_backend_countersign": True,
            "amount_usd": amount_usd,
            "sig": intent["sig"],
            "note": "Intent signed — billing backend will countersign and process.",
        }
    finally:
        conn.close()


async def get_billing_status(
    tenant_id: str = "default",
) -> dict:
    """Read current subscription/billing status from billing API (fail-open stub)."""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(
                f"http://localhost:8001/billing/status?tenant_id={tenant_id}",
                headers={"X-API-Key": os.getenv("WARDEN_API_KEY", "")},
            )
            if r.status_code == 200:
                return r.json()
    except Exception as exc:  # noqa: BLE001
        log.debug("SUPPORT: billing status unavailable: %s", exc)

    return {
        "tenant_id": tenant_id,
        "status": "unknown",
        "note": "Billing API unavailable — check /portal/billing directly.",
    }


SUPPORT_TOOL_HANDLERS = {
    "get_ticket": get_ticket,
    "resolve_ticket_kb": resolve_ticket_kb,
    "issue_refund": issue_refund,
    "get_billing_status": get_billing_status,
}

SUPPORT_TOOLS = [
    {
        "name": "get_ticket",
        "description": "Fetch one or multiple support tickets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "integer"},
                "status": {"type": "string", "enum": ["OPEN", "RESOLVED", "ESCALATED"]},
                "limit": {"type": "integer"},
            },
        },
    },
    {
        "name": "resolve_ticket_kb",
        "description": "Resolve a support ticket using a KB category or custom resolution text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "integer"},
                "category": {"type": "string", "enum": ["billing", "login", "api_key", "performance", "refund", "gdpr", "other"]},
                "custom_resolution": {"type": "string"},
            },
            "required": ["ticket_id"],
        },
    },
    {
        "name": "issue_refund",
        "description": "Issue a signed refund intent (Rec-3: no payment key exposed). Capped at boundary refund_cap_usd.",
        "input_schema": {
            "type": "object",
            "properties": {
                "amount_usd": {"type": "string", "description": "Decimal string, e.g. '5.00'"},
                "reason": {"type": "string"},
            },
            "required": ["amount_usd", "reason"],
        },
    },
    {
        "name": "get_billing_status",
        "description": "Get current subscription and billing status for the tenant.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
]
