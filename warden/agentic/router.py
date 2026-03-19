"""
warden/agentic/router.py
────────────────────────
FastAPI APIRouter for the AP2 Agentic Payment Protocol.

Endpoints
─────────
  GET    /agents                  — list agents for tenant
  POST   /agents                  — register new agent
  GET    /agents/activity         — activity log (MUST be before /{agent_id})
  POST   /agents/revoke-all       — bulk revoke all active agents
  PUT    /agents/{agent_id}       — update agent limits
  DELETE /agents/{agent_id}       — revoke agent
  POST   /mcp/quote               — create invoice hash
  POST   /mcp/mandate/execute     — validate + execute mandate

Mounted in main.py: app.include_router(_agentic_router)
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from warden.agentic.mandate import MandateResult, create_invoice, validate_mandate
from warden.agentic.registry import AgentRegistry, get_registry
from warden.auth_guard import AuthResult, require_api_key

log = logging.getLogger("warden.agentic.router")

router = APIRouter(tags=["Agentic Payment Protocol"])


# ── Request models ────────────────────────────────────────────────────────────

class AgentRegisterRequest(BaseModel):
    name:                 str        = Field(..., min_length=1)
    provider:             str        = Field(default="")
    tenant_id:            str        = Field(default="default")
    max_per_item:         float      = Field(default=0.0, ge=0.0)
    monthly_budget:       float      = Field(default=0.0, ge=0.0)
    allowed_categories:   list[str]  = Field(default_factory=list)
    require_confirmation: bool       = Field(default=False)
    mandate_ttl_seconds:  int        = Field(default=300, ge=30)


class AgentUpdateRequest(BaseModel):
    name:                 str | None       = None
    provider:             str | None       = None
    max_per_item:         float | None     = Field(default=None, ge=0.0)
    monthly_budget:       float | None     = Field(default=None, ge=0.0)
    allowed_categories:   list[str] | None = None
    require_confirmation: bool | None      = None
    mandate_ttl_seconds:  int | None       = Field(default=None, ge=30)


class QuoteRequest(BaseModel):
    sku:      str   = Field(..., min_length=1)
    price:    float = Field(..., gt=0.0)
    agent_id: str   = Field(...)


class MandateExecuteRequest(BaseModel):
    invoice_hash: str   = Field(...)
    sku:          str   = Field(...)
    amount:       float = Field(..., ge=0.0)
    currency:     str   = Field(default="USD")
    agent_id:     str   = Field(...)
    signature:    str   = Field(default="")


# ── Agent management ──────────────────────────────────────────────────────────

@router.get("/agents", summary="List registered agents for a tenant")
async def list_agents(
    tenant_id: str = Query(default="default"),
    _auth: AuthResult = Depends(require_api_key),
) -> list[dict]:
    return get_registry().get_agents(tenant_id)


@router.post("/agents", summary="Register a new AI agent", status_code=201)
async def register_agent(
    body: AgentRegisterRequest,
    _auth: AuthResult = Depends(require_api_key),
) -> dict:
    return get_registry().register_agent(
        tenant_id            = body.tenant_id,
        name                 = body.name,
        provider             = body.provider,
        max_per_item         = body.max_per_item,
        monthly_budget       = body.monthly_budget,
        require_confirmation = body.require_confirmation,
        allowed_categories   = body.allowed_categories,
        mandate_ttl_seconds  = body.mandate_ttl_seconds,
    )


# NOTE: /agents/activity and /agents/revoke-all MUST be declared before
# /agents/{agent_id} to prevent FastAPI treating literal path segments as
# the agent_id path parameter.

@router.get("/agents/activity", summary="Agentic activity audit log for a tenant")
async def get_activity(
    tenant_id: str        = Query(default="default"),
    agent_id:  str | None = Query(default=None),
    limit:     int        = Query(default=100, ge=1, le=1000),
    _auth: AuthResult     = Depends(require_api_key),
) -> list[dict]:
    return get_registry().get_activity(tenant_id, agent_id=agent_id, limit=limit)


@router.post("/agents/revoke-all", summary="Revoke all active agents for a tenant")
async def revoke_all_agents(
    tenant_id: str    = Query(default="default"),
    _auth: AuthResult = Depends(require_api_key),
) -> dict:
    count = get_registry().revoke_all(tenant_id)
    return {"tenant_id": tenant_id, "revoked": count}


@router.put("/agents/{agent_id}", summary="Update agent limits")
async def update_agent(
    agent_id: str,
    body: AgentUpdateRequest,
    _auth: AuthResult = Depends(require_api_key),
) -> dict:
    reg      = get_registry()
    existing = reg.get_agent(agent_id)
    if existing is None:
        raise HTTPException(404, f"Agent {agent_id!r} not found.")
    updated = reg.update_agent(agent_id, **body.model_dump(exclude_none=True))
    return updated  # type: ignore[return-value]


@router.delete("/agents/{agent_id}", summary="Revoke an agent")
async def revoke_agent(
    agent_id: str,
    _auth: AuthResult = Depends(require_api_key),
) -> dict:
    ok = get_registry().revoke_agent(agent_id)
    if not ok:
        raise HTTPException(404, f"Agent {agent_id!r} not found.")
    return {"agent_id": agent_id, "status": "revoked"}


# ── MCP / mandate endpoints ───────────────────────────────────────────────────

@router.post("/mcp/quote", summary="Create a one-time invoice hash for an agent transaction")
async def mcp_quote(
    body: QuoteRequest,
    _auth: AuthResult = Depends(require_api_key),
) -> dict:
    reg   = get_registry()
    agent = reg.get_agent(body.agent_id)
    if agent is None:
        raise HTTPException(404, f"Agent {body.agent_id!r} not found.")
    if agent["status"] != "active":
        raise HTTPException(403, "Agent is not active.")
    return create_invoice(
        sku         = body.sku,
        price       = body.price,
        agent_id    = body.agent_id,
        ttl_seconds = agent.get("mandate_ttl_seconds", 300),
    )


@router.post("/mcp/mandate/execute", summary="Validate and execute an AP2 payment mandate")
async def mcp_mandate_execute(
    body: MandateExecuteRequest,
    _auth: AuthResult = Depends(require_api_key),
) -> dict:
    reg   = get_registry()
    agent = reg.get_agent(body.agent_id)
    if agent is None:
        raise HTTPException(404, f"Agent {body.agent_id!r} not found.")

    # Inject current monthly spend so validate_mandate can check budget
    agent["_monthly_spend"] = reg.get_monthly_spend(body.agent_id)

    result: MandateResult = validate_mandate(body.model_dump(), agent)
    log_status = "approved" if result.valid else "denied"

    reg.log_activity(
        tenant_id      = agent["tenant_id"],
        agent_id       = body.agent_id,
        action         = "mandate_execute",
        sku            = body.sku,
        amount         = body.amount,
        currency       = body.currency,
        status         = log_status,
        reason         = result.reason,
        transaction_id = result.transaction_id,
    )

    if not result.valid:
        raise HTTPException(402, detail=result.reason)

    return {
        "approved":       True,
        "transaction_id": result.transaction_id,
        "agent_id":       body.agent_id,
        "sku":            body.sku,
        "amount":         body.amount,
        "currency":       body.currency,
    }
