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

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key
from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/agent", tags=["SOVA Agent"])


# ── Request / Response models ─────────────────────────────────────────────────

class SovaRequest(BaseModel):
    query:      str   = Field(..., min_length=1, max_length=4000, description="Your question or command for SOVA")
    session_id: str   = Field("interactive", description="Conversation session ID (for multi-turn memory)")
    max_tokens: int   = Field(4096, ge=256, le=8192)
    operator_mode: bool = Field(
        False,
        description="Expose state-changing tools (config, key rotation, IP block). "
                    "Each such action still returns an approval token — nothing "
                    "mutates until a human resolves it. Requires Pro+.",
    )
    # tenant_id is NOT accepted from the request body — it is bound from the API key.


class SovaResponse(BaseModel):
    response:          str
    tools_used:        list[str]
    input_tokens:      int
    output_tokens:     int
    cache_read_tokens: int
    latency_ms:        float
    session_id:        str
    status:            str = "ok"


class TaskResponse(BaseModel):
    job:        str
    status:     str
    latency_ms: float


class MasterRequest(BaseModel):
    task:         str  = Field(..., min_length=1, max_length=8000, description="High-level task for MasterAgent")
    tenant_id:    str | None = None   # ignored — bound from the API key
    # auto_approve is NOT accepted from the API — state-changing sub-agent tools
    # always return an approval token that a human must resolve.


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


class CommunityLookupRequest(BaseModel):
    query:        str  = Field(..., min_length=1, max_length=500,
                               description="Search query — threat name, CVE ID, attack type, etc.")
    tenant_id:    str  = Field("default", description="Tenant context for tool calls")
    auto_publish: bool = Field(False,
                               description="If True, publish the lookup result to the community feed")
    risk_level:   str  = Field("HIGH", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")


class CommunityLookupResponse(BaseModel):
    query:           str
    total:           int
    results:         list[dict]
    recommendations: list[str]
    source:          str
    published:       bool
    ueciid:          str | None = None
    latency_ms:      float


class ApplyRecommendationResponse(BaseModel):
    ueciid:          str
    rule_id:         str
    examples_added:  int
    approval_token:  str | None = None
    status:          str
    latency_ms:      float


AuthDep = Depends(require_api_key)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/sova",
    response_model=SovaResponse,
    summary="Query SOVA agent",
    dependencies=[require_feature("sova_agent_enabled")],
)
async def query_sova(body: SovaRequest, request: Request, auth: AuthResult = AuthDep) -> SovaResponse:
    """
    Send a natural-language query or command to SOVA.

    SOVA gathers data with its read-only tool suite, reasons over it, and
    returns an actionable response. Set `operator_mode=true` (Pro+) to expose
    state-changing tools — each returns an approval token; nothing mutates
    until a human resolves it via `POST /agent/execute/{token}`.

    `tenant_id` is bound from the API key — it cannot be set from the request.

    Supports multi-turn conversations via `session_id`.
    """
    from warden.agent.sova import run_query

    tenant_id = auth.tenant_id or "default"

    # Per-tenant kill switch (settings service).
    try:
        from warden.settings.service import get_agent_config
        if not get_agent_config(tenant_id).get("sova_enabled", True):
            raise HTTPException(status_code=403, detail="SOVA is disabled for this tenant in settings.")
    except HTTPException:
        raise
    except Exception:
        pass

    if body.operator_mode:
        from warden.billing.feature_gate import FeatureGate, _get_tenant_tier
        g = FeatureGate.for_tier(_get_tenant_tier(request))
        if not g.is_enabled("master_agent_enabled"):
            raise HTTPException(
                status_code=403,
                detail={"error": "feature_gated",
                        "message": "operator_mode requires PRO plan or higher."},
            )

    result = await run_query(
        query         = body.query,
        session_id    = body.session_id,
        tenant_id     = tenant_id,
        max_tokens    = body.max_tokens,
        operator_mode = body.operator_mode,
    )
    return SovaResponse(
        response          = result["response"],
        tools_used        = result["tools_used"],
        input_tokens      = result["input_tokens"],
        output_tokens     = result["output_tokens"],
        cache_read_tokens = result["cache_read_tokens"],
        latency_ms        = result["latency_ms"],
        session_id        = body.session_id,
        status            = result.get("status", "ok"),
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
    "morning-brief":    "sova_morning_brief",
    "threat-sync":      "sova_threat_sync",
    "rotation-check":   "sova_rotation_check",
    "sla-report":       "sova_sla_report",
    "upgrade-scan":     "sova_upgrade_scan",
    "corpus-watchdog":  "sova_corpus_watchdog",
    "visual-patrol":    "sova_visual_patrol",
    "community-lookup": "sova_community_watchdog",
    "commerce-watchdog": "sova_commerce_watchdog",
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
        tenant_id    = auth.tenant_id or "default",
        auto_approve = False,   # never skip the gate for an API caller
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
    from warden.agent import approval as _approval
    from warden.agent.master import resolve_approval

    approved = (action == "approve")
    # New SOVA/sub-agent gate first, then the legacy MasterAgent gate.
    resolved = _approval.resolve(token, approved) or resolve_approval(token, approved)
    if not resolved:
        raise HTTPException(status_code=404, detail="Approval token not found or expired.")

    return ApprovalResponse(
        token    = token,
        resolved = True,
        approved = approved,
        detail   = f"Action {'approved' if approved else 'rejected'} successfully. "
                   + ("Run POST /agent/execute/{token} to perform it." if approved else ""),
    )


@router.post(
    "/execute/{token}",
    summary="Execute a state-changing agent action after human approval",
    dependencies=[Depends(require_api_key)],
)
async def execute_approved_action(token: str, auth: AuthResult = AuthDep) -> dict:
    """
    Perform the tool call bound to an approval *token*.

    The token must already be resolved as `approve` via
    `POST /agent/approve/{token}?action=approve`. The action runs exactly
    once; the token is consumed.
    """
    from warden.agent import approval as _approval
    from warden.agent.tools import TOOL_HANDLERS

    rec = _approval.resolution(token)
    if not rec:
        raise HTTPException(status_code=404, detail="No resolved approval for this token.")
    if rec.get("status") != "approved":
        raise HTTPException(status_code=409, detail=f"Token is {rec.get('status')}, not approved.")
    # Exact tenant match only — a token issued for 'default'/internal flows is
    # not executable by an arbitrary tenant.
    caller = auth.tenant_id or "default"
    if rec.get("tenant_id") != caller:
        raise HTTPException(status_code=403, detail="Token belongs to another tenant.")

    action = rec.get("action", "")
    handler = TOOL_HANDLERS.get(action)
    if handler is None:
        raise HTTPException(status_code=400, detail=f"Unknown action '{action}'.")

    # Atomic single-use claim — concurrent / repeat calls get 409, not a double run.
    if not _approval.try_consume(token):
        raise HTTPException(status_code=409, detail="This approval has already been executed.")

    params = dict(rec.get("params", {}))
    params["tenant_id"] = caller
    try:
        result = await handler(**params)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Execution failed: {exc}") from exc

    return {"token": token, "action": action, "executed": True, "result": result}


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


# ── Community Intelligence endpoint ──────────────────────────────────────────

@router.post(
    "/sova/community/lookup",
    response_model=CommunityLookupResponse,
    summary="Search community threat feed and get mitigation recommendations",
)
async def community_lookup(
    body: CommunityLookupRequest,
    auth: AuthResult = AuthDep,
) -> CommunityLookupResponse:
    """
    Search the SEP community feed for threat signatures and retrieve
    actionable recommendations from the community knowledge base.

    Optionally publishes the lookup as a new community entry so other
    tenants benefit from the intelligence (`auto_publish=true`).

    Example:
    ```json
    { "query": "new jailbreak", "auto_publish": false }
    ```
    """
    from warden.agent.tools import (
        get_community_recommendations,
        publish_to_community,
        search_community_feed,
    )

    t0 = time.perf_counter()

    feed = await search_community_feed(
        query=body.query, limit=10, tenant_id=body.tenant_id
    )
    results = feed.get("results", [])

    recs = await get_community_recommendations(
        incident_type=body.query,
        risk_level=body.risk_level,
        tenant_id=body.tenant_id,
    )

    ueciid: str | None = None
    published = False
    if body.auto_publish:
        pub = await publish_to_community(
            verdict="FLAG",
            rule_id=f"community_lookup:{body.query[:40]}",
            risk_level=body.risk_level,
            evidence_summary=f"Community lookup: {body.query}",
            tenant_id=body.tenant_id,
        )
        published = pub.get("published", False)
        ueciid = pub.get("ueciid")

    return CommunityLookupResponse(
        query=body.query,
        total=len(results),
        results=results,
        recommendations=recs.get("recommendations", []),
        source=recs.get("source", "mitre_fallback"),
        published=published,
        ueciid=ueciid,
        latency_ms=round((time.perf_counter() - t0) * 1000, 1),
    )


# ── Apply community recommendation ────────────────────────────────────────────

@router.post(
    "/sova/community/apply/{ueciid}",
    response_model=ApplyRecommendationResponse,
    summary="Apply a community recommendation to local filter corpus",
)
async def apply_community_recommendation(
    ueciid: str,
    auth:   AuthResult = AuthDep,
) -> ApplyRecommendationResponse:
    """
    Fetch a published community UECIID and synthesise its indicator into the
    local SemanticGuard corpus via EvolutionEngine.add_examples().

    High-impact: the call is wrapped in a human-in-the-loop gate — an approval
    token is returned.  Resolve it via `POST /agent/approve/{token}?action=approve`
    before the examples are actually committed.

    Returns immediately with `status=pending` if approval required, or
    `status=applied` if `auto_approve=true` env is set (admin use only).
    """
    import os as _os  # noqa: PLC0415
    import sqlite3  # noqa: PLC0415

    t0 = time.perf_counter()

    if not ueciid.startswith("SEP-"):
        raise HTTPException(status_code=400, detail="Invalid UECIID format")

    # Fetch the UECIID record
    db_path = _os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM sep_ueciid_index WHERE ueciid=?", (ueciid,)
            ).fetchone()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"SEP DB unavailable: {exc}") from exc

    if not row:
        raise HTTPException(status_code=404, detail=f"UECIID {ueciid} not found")

    display_name = row["display_name"]
    data_class   = row.get("data_class", "GENERAL")
    rule_id      = f"community:{ueciid}"

    # Derive attack example from the indicator display name
    example_text = (
        f"Community-reported threat indicator: {display_name}. "
        f"Data classification: {data_class}. "
        "Treat any prompt containing this indicator as HIGH risk — block or escalate."
    )

    # Issue an approval token before mutating the corpus. FAIL CLOSED: if the
    # approval store is unavailable we refuse — we never apply unattended.
    from warden.agent import approval as _approval  # noqa: PLC0415
    try:
        token = _approval.issue(
            action="apply_community_recommendation",
            context=f"{ueciid}: {display_name[:200]}",
            tenant_id=auth.tenant_id or "default",
            params={"ueciid": ueciid, "example_text": example_text},
        )
    except _approval.ApprovalStoreUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Approval store unavailable — refusing to apply {ueciid} unattended: {exc}",
        ) from exc

    return ApplyRecommendationResponse(
        ueciid         = ueciid,
        rule_id        = rule_id,
        examples_added = 0,
        approval_token = token,
        status         = "pending_approval",
        latency_ms     = round((time.perf_counter() - t0) * 1000, 1),
    )


# ── MISP sync endpoint (admin) ─────────────────────────────────────────────────

@router.post(
    "/misp/sync",
    summary="Trigger MISP threat feed sync",
    dependencies=[Depends(require_api_key)],
)
async def misp_sync(auth: AuthResult = AuthDep) -> dict:
    """
    Pull events from the configured MISP instance and synthesise them into the
    local SemanticGuard corpus via EvolutionEngine.

    Requires `MISP_URL` and `MISP_API_KEY` env vars.
    """
    try:
        from warden.integrations.misp import MISPConnector  # noqa: PLC0415
    except ImportError as exc:
        raise HTTPException(status_code=503, detail=f"MISP integration not available: {exc}") from exc

    try:
        connector = MISPConnector()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result = await connector.sync()
    return result.to_dict()


# ── Procurement co-pilot (PR-8) ──────────────────────────────────────────────

class NegotiateRequest(BaseModel):
    request:    str          = Field(..., min_length=3, max_length=2000,
                                     description="What to buy, in natural language")
    budget_usd: float | None = Field(None, gt=0)


@router.post(
    "/sova/commerce/negotiate",
    summary="Run a guided procurement auction and return a ranked recommendation",
    dependencies=[require_feature("master_agent_enabled")],
)
async def commerce_negotiate(
    body: NegotiateRequest,
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Run a multi-agent procurement auction for *request*, enrich each finalist
    with supplier-risk and community fraud signals, and return a ranked
    recommendation.

    **No settlement is performed.** The response carries the `auction_id`; a
    human completes the purchase through the normal
    `/business-community/commerce` order + approval flow.
    """
    import time as _time  # noqa: PLC0415

    tenant_id = auth.tenant_id or "default"
    t0 = _time.perf_counter()

    from warden.business_community.agentic_commerce.multi_agent.orchestrator import (  # noqa: PLC0415
        MultiAgentOrchestrator,
    )

    orch = MultiAgentOrchestrator()
    auction_id = await orch.run_auction(tenant_id, body.request, budget_usd=body.budget_usd)
    result = orch.get_auction(auction_id, tenant_id) or {}
    proposals = result.get("proposals", [])

    # Enrich finalists with supplier risk + community fraud signal
    enriched: list[dict] = []
    for p in proposals:
        vendor = p.get("recommended_vendor") or p.get("vendor") or ""
        row = {
            "vendor":         vendor,
            "price_usd":      p.get("estimated_price_usd") or p.get("price"),
            "delivery_days":  p.get("delivery_days"),
            "agent_risk":     p.get("risk_score"),
            "rationale":      p.get("rationale", ""),
        }
        if vendor:
            try:
                from warden.communities.supplier_risk import assess_supplier  # noqa: PLC0415
                sr = assess_supplier(tenant_id, vendor)
                if isinstance(sr, dict):
                    row["supplier_risk"] = sr.get("composite_score")
            except Exception:  # noqa: BLE001
                pass
            try:
                from warden.agent.tools import search_community_feed  # noqa: PLC0415
                hits = await search_community_feed(query=vendor, limit=3, tenant_id=tenant_id)
                row["community_fraud_hits"] = hits.get("total", 0)
            except Exception:  # noqa: BLE001
                pass
        enriched.append(row)

    # Rank: lowest combined risk, then price
    def _score(r: dict) -> float:
        ar = float(r.get("agent_risk") or 0)
        sr = float(r.get("supplier_risk") or 0)
        fh = float(r.get("community_fraud_hits") or 0)
        return ar + sr + min(fh, 3) * 0.2

    enriched.sort(key=_score)
    top = enriched[0] if enriched else None

    return {
        "auction_id":    auction_id,
        "tenant_id":     tenant_id,
        "recommendation": top,
        "ranked":        enriched,
        "settlement":    "not_performed",
        "next_step":     "Create an order via POST /business-community/commerce/orders, "
                         "then approve it through the normal flow.",
        "latency_ms":    round((_time.perf_counter() - t0) * 1000, 1),
    }
