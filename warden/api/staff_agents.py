"""
FastAPI router — /staff/agents/*

POST /staff/agents/{agent_id}/query      — run a query through a specific agent
GET  /staff/agents/{agent_id}/drafts     — fetch draft queue (emails, SEO, SARs, etc.)
GET  /staff/agents/bdr/leads             — CRM lead pipeline
GET  /staff/agents/bdr/drafts/email      — email drafts awaiting review
POST /staff/agents/bdr/drafts/email/{id}/approve   — mark email draft as approved
GET  /staff/agents/growth/drafts/seo     — SEO content drafts
GET  /staff/agents/growth/proposals      — budget proposals
GET  /staff/agents/compliance/sars       — SAR drafts
GET  /staff/agents/support/tickets       — support tickets
POST /staff/agents/support/tickets       — create a test ticket (dev only)
GET  /staff/agents/support/refunds       — refund intent queue
GET  /staff/agents/economics/report      — unit economics (cost per action)
GET  /staff/agents/economics/alerts      — margin alerts (avg cost > threshold)
GET  /staff/agents/a2a/audit             — A2A cross-agent call audit log
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from warden.auth_guard import require_api_key

log = logging.getLogger(__name__)

try:
    from warden.billing.feature_gate import require_feature as _require_feature
    _GATE = [_require_feature("master_agent_enabled")]
except Exception:
    _GATE = []

router = APIRouter(
    prefix="/staff/agents",
    tags=["Digital Staff Agents"],
    dependencies=[Depends(require_api_key), *_GATE],
)


# ── Pydantic models ────────────────────────────────────────────────────────────

class AgentQueryRequest(BaseModel):
    query: str
    tenant_id: str = "default"
    session_id: str | None = None


class CreateTicketRequest(BaseModel):
    tenant_id: str = "default"
    subject: str
    body: str


# ── Generic query endpoint ─────────────────────────────────────────────────────

@router.post("/{agent_id}/query")
async def agent_query(agent_id: str, req: AgentQueryRequest) -> dict[str, Any]:
    from warden.staff.agents.base import run_staff_query  # noqa: PLC0415
    result = await run_staff_query(
        agent_id=agent_id,
        query=req.query,
        tenant_id=req.tenant_id,
        session_id=req.session_id,
    )
    if "error" in result and not result.get("response"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ── BDR endpoints ──────────────────────────────────────────────────────────────

def _bdr_db():
    from warden.staff.tools.bdr import _conn  # noqa: PLC0415
    return _conn()


@router.get("/bdr/leads")
async def bdr_leads(tenant_id: str = "default", status: str | None = None, limit: int = 20) -> dict:
    from warden.staff.tools.bdr import crm_search  # noqa: PLC0415
    return await crm_search(tenant_id=tenant_id, status=status, limit=limit)


@router.get("/bdr/drafts/email")
async def bdr_email_drafts(tenant_id: str = "default") -> dict:
    with _bdr_db() as db:
        rows = db.execute(
            "SELECT * FROM email_drafts WHERE tenant_id=? ORDER BY created_at DESC LIMIT 50",
            (tenant_id,)
        ).fetchall()
        return {"drafts": [dict(r) for r in rows], "count": len(rows)}


@router.post("/bdr/drafts/email/{draft_id}/approve")
async def approve_email_draft(draft_id: int, tenant_id: str = "default") -> dict:
    with _bdr_db() as db:
        row = db.execute(
            "SELECT * FROM email_drafts WHERE id=? AND tenant_id=?", (draft_id, tenant_id)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Draft {draft_id} not found")
        db.execute(
            "UPDATE email_drafts SET status='APPROVED' WHERE id=? AND tenant_id=?",
            (draft_id, tenant_id),
        )
        return {"draft_id": draft_id, "status": "APPROVED"}


@router.get("/bdr/meeting-slots")
async def bdr_meeting_slots(tenant_id: str = "default") -> dict:
    with _bdr_db() as db:
        rows = db.execute(
            "SELECT * FROM meeting_slots WHERE tenant_id=? ORDER BY created_at DESC LIMIT 50",
            (tenant_id,)
        ).fetchall()
        return {"slots": [dict(r) for r in rows], "count": len(rows)}


# ── Growth endpoints ───────────────────────────────────────────────────────────

def _growth_db():
    from warden.staff.tools.growth import _conn  # noqa: PLC0415
    return _conn()


@router.get("/growth/drafts/seo")
async def growth_seo_drafts(tenant_id: str = "default") -> dict:
    with _growth_db() as db:
        rows = db.execute(
            "SELECT id, tenant_id, topic, injection_clean, status, created_at FROM seo_drafts WHERE tenant_id=? ORDER BY created_at DESC LIMIT 50",
            (tenant_id,)
        ).fetchall()
        return {"drafts": [dict(r) for r in rows], "count": len(rows)}


@router.get("/growth/proposals")
async def growth_budget_proposals(tenant_id: str = "default") -> dict:
    with _growth_db() as db:
        rows = db.execute(
            "SELECT * FROM budget_proposals WHERE tenant_id=? ORDER BY created_at DESC LIMIT 50",
            (tenant_id,)
        ).fetchall()
        return {"proposals": [dict(r) for r in rows], "count": len(rows)}


@router.post("/growth/proposals/{proposal_id}/approve")
async def approve_budget_proposal(proposal_id: int, tenant_id: str = "default") -> dict:
    with _growth_db() as db:
        row = db.execute(
            "SELECT * FROM budget_proposals WHERE id=? AND tenant_id=?", (proposal_id, tenant_id)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Proposal {proposal_id} not found")
        db.execute(
            "UPDATE budget_proposals SET status='APPROVED' WHERE id=? AND tenant_id=?",
            (proposal_id, tenant_id),
        )
        return {"proposal_id": proposal_id, "status": "APPROVED"}


# ── Compliance endpoints ───────────────────────────────────────────────────────

def _compliance_db():
    from warden.staff.tools.compliance_kyc import _conn  # noqa: PLC0415
    return _conn()


@router.get("/compliance/sars")
async def compliance_sars(tenant_id: str = "default") -> dict:
    with _compliance_db() as db:
        rows = db.execute(
            "SELECT id, tenant_id, subject, risk_level, status, created_at FROM sar_drafts WHERE tenant_id=? ORDER BY created_at DESC LIMIT 50",
            (tenant_id,)
        ).fetchall()
        return {"sars": [dict(r) for r in rows], "count": len(rows)}


@router.post("/compliance/sars/{sar_id}/approve")
async def approve_sar(sar_id: int, tenant_id: str = "default") -> dict:
    with _compliance_db() as db:
        row = db.execute(
            "SELECT * FROM sar_drafts WHERE id=? AND tenant_id=?", (sar_id, tenant_id)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"SAR {sar_id} not found")
        db.execute(
            "UPDATE sar_drafts SET status='FILED' WHERE id=? AND tenant_id=?",
            (sar_id, tenant_id),
        )
        return {"sar_id": sar_id, "status": "FILED"}


@router.get("/compliance/screening-log")
async def compliance_screening_log(tenant_id: str = "default", limit: int = 50) -> dict:
    with _compliance_db() as db:
        rows = db.execute(
            "SELECT * FROM screening_log WHERE tenant_id=? ORDER BY screened_at DESC LIMIT ?",
            (tenant_id, min(limit, 200))
        ).fetchall()
        return {"entries": [dict(r) for r in rows], "count": len(rows)}


# ── Support endpoints ──────────────────────────────────────────────────────────

def _support_db():
    from warden.staff.tools.support import _conn  # noqa: PLC0415
    return _conn()


@router.get("/support/tickets")
async def support_tickets(tenant_id: str = "default", status: str | None = None) -> dict:
    from warden.staff.tools.support import get_ticket  # noqa: PLC0415
    return await get_ticket(tenant_id=tenant_id, status=status)


@router.post("/support/tickets")
async def create_support_ticket(req: CreateTicketRequest) -> dict:
    import time
    with _support_db() as db:
        now = int(time.time())
        cur = db.execute(
            "INSERT INTO tickets (tenant_id,subject,body,status,created_at) VALUES (?,?,?,?,?)",
            (req.tenant_id, req.subject, req.body, "OPEN", now),
        )
        return {"ticket_id": cur.lastrowid, "status": "OPEN"}


@router.get("/support/refunds")
async def support_refund_intents(tenant_id: str = "default") -> dict:
    with _support_db() as db:
        rows = db.execute(
            "SELECT id,tenant_id,agent_id,amount_usd,reason,status,created_at FROM refund_intents WHERE tenant_id=? ORDER BY created_at DESC LIMIT 50",
            (tenant_id,)
        ).fetchall()
        return {"refunds": [dict(r) for r in rows], "count": len(rows)}


@router.post("/support/refunds/{intent_id}/approve")
async def approve_refund_intent(intent_id: int, tenant_id: str = "default") -> dict:
    with _support_db() as db:
        row = db.execute(
            "SELECT * FROM refund_intents WHERE id=? AND tenant_id=?", (intent_id, tenant_id)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Refund intent {intent_id} not found")
        db.execute(
            "UPDATE refund_intents SET status='APPROVED_FOR_PROCESSING' WHERE id=? AND tenant_id=?",
            (intent_id, tenant_id),
        )
        return {"intent_id": intent_id, "status": "APPROVED_FOR_PROCESSING"}


# ── Unit Economics endpoints ───────────────────────────────────────────────────

@router.get("/economics/report")
async def economics_report(tenant_id: str = "default", days: int = 30) -> dict:
    """Per-action token cost breakdown for the last N days."""
    from warden.staff.economics import get_tracker  # noqa: PLC0415
    return get_tracker().get_report(tenant_id, days)


@router.get("/economics/alerts")
async def economics_alerts(tenant_id: str = "default", threshold_usd: float = 0.50) -> dict:
    """Actions where average cost-per-call exceeds threshold_usd."""
    from warden.staff.economics import get_tracker  # noqa: PLC0415
    alerts = get_tracker().get_margin_alerts(tenant_id, threshold_usd)
    return {"tenant_id": tenant_id, "threshold_usd": threshold_usd, "alerts": alerts}


# ── A2A audit endpoint ─────────────────────────────────────────────────────────

@router.get("/a2a/audit")
async def a2a_audit(limit: int = 100) -> dict:
    """Cross-agent (A2A) call audit log — last N entries."""
    from warden.staff.a2a import get_a2a_router  # noqa: PLC0415
    return {"calls": get_a2a_router().get_audit_log(limit)}
