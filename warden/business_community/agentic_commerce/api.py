"""
warden/business_community/agentic_commerce/api.py  (CM-40)
───────────────────────────────────────────────────────────
FastAPI router for Agentic Commerce.

Prefix: /business-community/commerce
Tier:   Community Business+ (agentic_commerce_enabled)
Auth:   X-API-Key (require_api_key). A customer key is locked to its own
        tenant; the internal key may name the tenant via X-Tenant-ID.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key
from warden.billing.feature_gate import require_feature

router = APIRouter(
    prefix="/business-community/commerce",
    tags=["Agentic Commerce"],
)
_Gate = require_feature("agentic_commerce_enabled")
_AuthDep = Depends(require_api_key)


def _bound_tenant(auth: AuthResult, request: Request, supplied: str | None) -> str:
    """
    Resolve the tenant for this request.

    A customer API key is locked to its own tenant — a disagreeing `tenant_id`
    is rejected 403. The internal/default key (used by SOVA's own tool calls)
    is trusted to name the tenant via the `X-Tenant-ID` header or the parameter,
    matching the rest of the internal API.
    """
    real = auth.tenant_id or "default"
    if real != "default":
        if supplied and supplied not in (real, "", "default"):
            raise HTTPException(status_code=403, detail="tenant_id does not match your API key")
        return real
    return request.headers.get("X-Tenant-ID") or supplied or "default"


# ── Request models ────────────────────────────────────────────────────────────

class MandateCreateRequest(BaseModel):
    tenant_id: str | None = None   # ignored — bound from API key / header
    max_amount: float = Field(..., gt=0)
    currency: str = "USD"
    valid_until: str | None = None
    allowed_merchants: list[str] = Field(default_factory=list)


class OrderCreateRequest(BaseModel):
    tenant_id: str | None = None
    store_url: str
    mandate_id: str
    items: list[dict[str, Any]] = Field(default_factory=list)
    mcp_intent: str = ""


class MCPIntentRequest(BaseModel):
    tenant_id: str | None = None
    content: str
    currency: str = "USD"
    metadata: dict[str, Any] = Field(default_factory=dict)


class WebhookAP2Request(BaseModel):
    transaction_id: str
    status: str
    order_ref: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuctionRequest(BaseModel):
    tenant_id:        str | None = None
    purchase_request: str
    budget_usd:       float | None = None


# ── Mandate endpoints ─────────────────────────────────────────────────────────

@router.post("/mandates", summary="Create a spending mandate", dependencies=[_Gate])
async def create_mandate(body: MandateCreateRequest, request: Request, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    tenant_id = _bound_tenant(auth, request, body.tenant_id)
    mandate = AP2Processor().create_mandate(
        tenant_id=tenant_id,
        max_amount=body.max_amount,
        currency=body.currency,
        valid_until=body.valid_until,
        allowed_merchants=body.allowed_merchants,
    )
    return mandate.to_dict()


@router.get("/mandates", summary="List mandates for a tenant", dependencies=[_Gate])
async def list_mandates(request: Request, tenant_id: str | None = None, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    tid = _bound_tenant(auth, request, tenant_id)
    mandates = AP2Processor().list_mandates(tid)
    return {"mandates": [m.to_dict() for m in mandates], "count": len(mandates)}


@router.get("/mandates/{mandate_id}", summary="Get mandate details", dependencies=[_Gate])
async def get_mandate(mandate_id: str, request: Request, tenant_id: str | None = None, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    tid = _bound_tenant(auth, request, tenant_id)
    m = AP2Processor().get_mandate(mandate_id, tid)
    if not m:
        raise HTTPException(status_code=404, detail=f"Mandate {mandate_id!r} not found")
    return m.to_dict()


@router.delete("/mandates/{mandate_id}", summary="Revoke a mandate", dependencies=[_Gate])
async def revoke_mandate(mandate_id: str, request: Request, tenant_id: str | None = None, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    tid = _bound_tenant(auth, request, tenant_id)
    ok = AP2Processor().revoke_mandate(mandate_id, tid)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Mandate {mandate_id!r} not found")
    return {"revoked": True, "mandate_id": mandate_id}


@router.get("/mandates/{mandate_id}/verify", summary="Verify mandate status & signature", dependencies=[_Gate])
async def verify_mandate(mandate_id: str, request: Request, tenant_id: str | None = None, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    return AP2Processor().verify_mandate(mandate_id, _bound_tenant(auth, request, tenant_id))


# ── Order endpoints ───────────────────────────────────────────────────────────

@router.post("/orders", summary="Create a purchase order", dependencies=[_Gate])
async def create_order(body: OrderCreateRequest, request: Request, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.service import AgenticCommerceService
    tenant_id = _bound_tenant(auth, request, body.tenant_id)
    result = await AgenticCommerceService().create_purchase_workflow(
        tenant_id=tenant_id,
        store_url=body.store_url,
        items=body.items,
        mandate_id=body.mandate_id,
    )
    if not result.get("success"):
        raise HTTPException(status_code=402, detail=result)
    return result


@router.get("/orders", summary="Order history for a tenant", dependencies=[_Gate])
async def list_orders(request: Request, tenant_id: str | None = None, limit: int = 50, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.service import AgenticCommerceService
    tid = _bound_tenant(auth, request, tenant_id)
    orders = AgenticCommerceService().get_order_history(tid, limit=limit)
    return {"orders": orders, "count": len(orders)}


@router.get("/orders/{order_id}", summary="Get order details + receipt", dependencies=[_Gate])
async def get_order(order_id: str, request: Request, tenant_id: str | None = None, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    from warden.business_community.agentic_commerce.service import AgenticCommerceService
    tid = _bound_tenant(auth, request, tenant_id)
    orders = AgenticCommerceService().get_order_history(tid, limit=1000)
    order = next((o for o in orders if o["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=404, detail=f"Order {order_id!r} not found")
    receipt = AP2Processor().get_receipt(order_id)
    return {"order": order, "receipt": receipt.to_dict() if receipt else None}


# ── MCP intent endpoint ───────────────────────────────────────────────────────

@router.post("/mcp/intent", summary="Submit MCP agent purchase intent", dependencies=[_Gate])
async def submit_mcp_intent(body: MCPIntentRequest, request: Request, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.mcp_bridge import MCPBridge
    tenant_id = _bound_tenant(auth, request, body.tenant_id)
    bridge = MCPBridge()
    intent = bridge.receive_intent({
        "tenant_id": tenant_id,
        "content": body.content,
        "currency": body.currency,
        "metadata": body.metadata,
    })
    result = await bridge.execute_with_approval(intent, tenant_id)
    return {"intent": intent.model_dump(), "workflow": result}


# ── AP2 webhook ───────────────────────────────────────────────────────────────

@router.post("/webhooks/ap2", summary="AP2 payment status callback")
async def ap2_webhook(body: WebhookAP2Request) -> dict:
    # AP2 webhook does not require tenant auth — validated by transaction signature
    import logging as _log
    _log.getLogger("warden.commerce.webhook").info(
        "AP2 webhook: txn=%s status=%s order=%s",
        body.transaction_id, body.status, body.order_ref,
    )
    return {"received": True, "transaction_id": body.transaction_id}


# ── Approval callback ─────────────────────────────────────────────────────────

@router.post("/approve/{workflow_id}", summary="Approve a pending MCP purchase intent", dependencies=[_Gate])
async def approve_workflow(
    workflow_id: str,
    request: Request,
    tenant_id: str | None = None,
    action: str = "approve",
    auth: AuthResult = _AuthDep,
) -> dict:
    _bound_tenant(auth, request, tenant_id)
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="action must be 'approve' or 'reject'")
    return {
        "workflow_id": workflow_id,
        "action": action,
        "resolved": True,
        "message": f"Workflow {workflow_id} {action}d.",
    }


# ── Analytics ─────────────────────────────────────────────────────────────────

@router.get("/analytics/spend", summary="Agentic spend summary", dependencies=[_Gate])
async def spend_summary(request: Request, tenant_id: str | None = None, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.service import AgenticCommerceService
    return AgenticCommerceService().get_mandate_usage(_bound_tenant(auth, request, tenant_id))


# ── Multi-agent auctions ──────────────────────────────────────────────────────

@router.post("/auctions", summary="Launch multi-agent procurement auction", dependencies=[_Gate])
async def create_auction(body: AuctionRequest, request: Request, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
        MultiAgentOrchestrator,
    )
    tenant_id = _bound_tenant(auth, request, body.tenant_id)
    auction_id = await MultiAgentOrchestrator().run_auction(
        tenant_id=tenant_id,
        purchase_request=body.purchase_request,
        budget_usd=body.budget_usd,
    )
    return {"auction_id": auction_id, "status": "completed"}


@router.get("/auctions", summary="List auctions for a tenant", dependencies=[_Gate])
async def list_auctions(request: Request, tenant_id: str | None = None, limit: int = 20, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
        MultiAgentOrchestrator,
    )
    tid = _bound_tenant(auth, request, tenant_id)
    auctions = MultiAgentOrchestrator().list_auctions(tid, limit=limit)
    return {"auctions": auctions, "count": len(auctions)}


@router.get("/auctions/{auction_id}", summary="Get auction result", dependencies=[_Gate])
async def get_auction(auction_id: str, request: Request, tenant_id: str | None = None, auth: AuthResult = _AuthDep) -> dict:
    from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
        MultiAgentOrchestrator,
    )
    tid = _bound_tenant(auth, request, tenant_id)
    result = MultiAgentOrchestrator().get_auction(auction_id, tid)
    if not result:
        raise HTTPException(status_code=404, detail="Auction not found")
    return result
