"""
warden/api/agent.py
────────────────────
SOVA + MasterAgent FastAPI router.

Routes
──────
  POST   /agent/sova                  — run a query through SOVA
  DELETE /agent/sova/{session_id}     — clear conversation history
  POST   /agent/sova/task/{job}       — trigger a scheduled task manually
  POST   /agent/master                — run MasterAgent (multi-agent coordination)
  POST   /agent/approve/{token}       — approve or reject a pending high-impact action
  GET    /agent/approve/{token}       — get pending approval details

Auth: standard X-API-Key (same as all other warden routes).
"""
from __future__ import annotations

import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key
from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/agent", tags=["SOVA Agent"])


# ── Request / Response models ─────────────────────────────────────────────────

class SovaRequest(BaseModel):
    query:      str   = Field(..., min_length=1, max_length=4000, description="Your question or command for SOVA")
    session_id: str   = Field("interactive", description="Conversation session ID (for multi-turn memory)")
    tenant_id:  str   = Field("default",     description="Tenant context for tool calls")
    max_tokens: int   = Field(4096, ge=256, le=8192)


class SovaResponse(BaseModel):
    response:          str
    tools_used:        list[str]
    input_tokens:      int
    output_tokens:     int
    cache_read_tokens: int
    latency_ms:        float
    session_id:        str


class TaskResponse(BaseModel):
    job:        str
    status:     str
    latency_ms: float


class MasterRequest(BaseModel):
    task:         str  = Field(..., min_length=1, max_length=8000, description="High-level task for MasterAgent")
    tenant_id:    str  = Field("default", description="Tenant context for all sub-agent tool calls")
    auto_approve: bool = Field(False, description="Skip human-in-the-loop gate (trusted/scheduled callers only)")


class MasterResponse(BaseModel):
    synthesis:       str
    sub_results:     list[dict]
    tools_used:      list[str]
    total_tokens:    int
    latency_ms:      float
    approval_tokens: list[str]
    ts:              str


class ApprovalResponse(BaseModel):
    token:    str
    resolved: bool
    approved: bool | None = None
    detail:   str = ""


AuthDep = Depends(require_api_key)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/sova", response_model=SovaResponse, summary="Query SOVA agent")
async def query_sova(body: SovaRequest, auth: AuthResult = AuthDep) -> SovaResponse:
    """
    Send a natural-language query or command to SOVA.

    SOVA will use its tool suite (27 Shadow Warden API calls) to gather
    data, reason over it, and return an actionable response.

    Supports multi-turn conversations via `session_id`.

    Example queries:
    - "Which communities need key rotation?"
    - "What's our ROI for the default tenant this month?"
    - "Are there any new critical CVEs affecting our dependencies?"
    - "Give me a morning brief"
    - "Check SLA compliance for all monitors"
    """
    from warden.agent.sova import run_query

    result = await run_query(
        query      = body.query,
        session_id = body.session_id,
        tenant_id  = body.tenant_id,
        max_tokens = body.max_tokens,
    )
    return SovaResponse(
        response          = result["response"],
        tools_used        = result["tools_used"],
        input_tokens      = result["input_tokens"],
        output_tokens     = result["output_tokens"],
        cache_read_tokens = result["cache_read_tokens"],
        latency_ms        = result["latency_ms"],
        session_id        = body.session_id,
    )


@router.delete(
    "/sova/{session_id}",
    status_code=204,
    summary="Clear SOVA conversation history",
)
async def clear_session(session_id: str, auth: AuthResult = AuthDep) -> None:
    from warden.agent.memory import clear_history
    clear_history(session_id)


_MANUAL_TASKS = {
    "morning-brief":  "sova_morning_brief",
    "threat-sync":    "sova_threat_sync",
    "rotation-check": "sova_rotation_check",
    "sla-report":     "sova_sla_report",
    "upgrade-scan":   "sova_upgrade_scan",
    "corpus-watchdog": "sova_corpus_watchdog",
    "visual-patrol":  "sova_visual_patrol",
}


@router.post(
    "/sova/task/{job}",
    response_model=TaskResponse,
    summary="Manually trigger a SOVA scheduled task",
)
async def trigger_task(job: str, auth: AuthResult = AuthDep) -> TaskResponse:
    """
    Manually trigger one of SOVA's scheduled tasks without waiting for cron.

    Available jobs:
    - `morning-brief`   — full daily operations brief → Slack
    - `threat-sync`     — refresh CVE + ArXiv, alert on critical findings
    - `rotation-check`  — audit all community key ages, auto-rotate if overdue
    - `sla-report`      — 7-day SLA compliance report → Slack
    - `upgrade-scan`    — identify tenants near quota limit
    - `corpus-watchdog` — check circuit breaker + bypass rate
    """
    if job not in _MANUAL_TASKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown job '{job}'. Available: {list(_MANUAL_TASKS)}",
        )

    from warden.agent import scheduler as _scheduler

    fn_name = _MANUAL_TASKS[job]
    fn = getattr(_scheduler, fn_name, None)
    if fn is None:
        raise HTTPException(status_code=500, detail=f"Job function '{fn_name}' not found")

    t0 = time.perf_counter()
    result = await fn(ctx={})
    latency = round((time.perf_counter() - t0) * 1000, 1)

    return TaskResponse(
        job        = job,
        status     = result.get("status", "ok"),
        latency_ms = latency,
    )


# ── MasterAgent endpoints ─────────────────────────────────────────────────────

@router.post(
    "/master",
    response_model=MasterResponse,
    summary="Run MasterAgent (multi-agent SOC coordination)",
    dependencies=[require_feature("master_agent_enabled")],
)
async def run_master_agent(
    body: MasterRequest,
    auth: AuthResult = AuthDep,
) -> MasterResponse:
    """
    Dispatch a high-level task to MasterAgent.

    MasterAgent decomposes the task, spawns specialist sub-agents in parallel
    (SOVAOperator, ThreatHunter, ForensicsAgent, ComplianceAgent), then
    synthesizes a unified executive report.

    High-impact actions (key rotation, agent revocation, config changes) are
    paused for human approval — `approval_tokens` lists pending tokens.
    Resolve them via `POST /agent/approve/{token}?action=approve|reject`.

    Example tasks:
    - "Full SOC morning brief — health, threats, SLA, and rotation status"
    - "Investigate why tenant acme-corp had 400% request spike at 03:00 UTC"
    - "Check compliance posture for our Q2 SOC 2 audit"
    """
    from warden.agent.master import run_master

    result = await run_master(
        task         = body.task,
        tenant_id    = body.tenant_id,
        auto_approve = body.auto_approve,
    )
    return MasterResponse(
        synthesis       = result.synthesis,
        sub_results     = result.sub_results,
        tools_used      = result.tools_used,
        total_tokens    = result.total_tokens,
        latency_ms      = result.latency_ms,
        approval_tokens = result.approval_tokens,
        ts              = result.ts,
    )


@router.post(
    "/approve/{token}",
    response_model=ApprovalResponse,
    summary="Approve or reject a pending MasterAgent high-impact action",
)
async def approve_action(
    token:  str,
    action: Literal["approve", "reject"] = Query(..., description="approve or reject"),
    auth:   AuthResult = AuthDep,
) -> ApprovalResponse:
    """
    Resolve a human-in-the-loop approval gate.

    The token is issued by MasterAgent when a sub-agent requests a
    high-impact operation (key rotation, agent revocation, etc.).
    Valid for 1 hour from issuance.

    `action=approve` — allows the operation to proceed.
    `action=reject`  — cancels the operation and logs the refusal.
    """
    from warden.agent.master import resolve_approval

    approved = (action == "approve")
    resolved = resolve_approval(token, approved)
    if not resolved:
        raise HTTPException(status_code=404, detail="Approval token not found or expired.")

    return ApprovalResponse(
        token    = token,
        resolved = True,
        approved = approved,
        detail   = f"Action {'approved' if approved else 'rejected'} successfully.",
    )


@router.get(
    "/approve/{token}",
    response_model=ApprovalResponse,
    summary="Check pending approval status",
)
async def get_approval(
    token: str,
    auth:  AuthResult = AuthDep,
) -> ApprovalResponse:
    """Return the current state of a pending approval token."""
    from warden.agent.master import get_pending_approval

    record = get_pending_approval(token)
    if not record:
        raise HTTPException(status_code=404, detail="Approval token not found or already resolved.")

    return ApprovalResponse(
        token    = token,
        resolved = False,
        approved = None,
        detail   = f"Pending approval for agent={record.get('action')}. Context: {record.get('context', '')[:200]}",
    )
