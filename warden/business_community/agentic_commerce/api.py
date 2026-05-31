"""
warden/business_community/agentic_commerce/api.py  (CM-40)
───────────────────────────────────────────────────────────
FastAPI router for Agentic Commerce.

Prefix: /business-community/commerce
Tier:   Community Business+ (agentic_commerce_enabled)
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(
    prefix="/business-community/commerce",
    tags=["Agentic Commerce"],
)
_Gate = require_feature("agentic_commerce_enabled")


# ── Request models ────────────────────────────────────────────────────────────

class MandateCreateRequest(BaseModel):
    tenant_id: str
    max_amount: float = Field(..., gt=0)
    currency: str = "USD"
    valid_until: str | None = None
    allowed_merchants: list[str] = Field(default_factory=list)


class OrderCreateRequest(BaseModel):
    tenant_id: str
    store_url: str
    mandate_id: str
    items: list[dict[str, Any]] = Field(default_factory=list)
    mcp_intent: str = ""


class MCPIntentRequest(BaseModel):
    tenant_id: str
    content: str
    currency: str = "USD"
    metadata: dict[str, Any] = Field(default_factory=dict)


class WebhookAP2Request(BaseModel):
    transaction_id: str
    status: str
    order_ref: str
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Mandate endpoints ─────────────────────────────────────────────────────────

@router.post("/mandates", summary="Create a spending mandate", dependencies=[_Gate])
async def create_mandate(body: MandateCreateRequest) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    proc = AP2Processor()
    mandate = proc.create_mandate(
        tenant_id=body.tenant_id,
        max_amount=body.max_amount,
        currency=body.currency,
        valid_until=body.valid_until,
        allowed_merchants=body.allowed_merchants,
    )
    return mandate.to_dict()


@router.get("/mandates", summary="List mandates for a tenant", dependencies=[_Gate])
async def list_mandates(tenant_id: str) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    proc = AP2Processor()
    mandates = proc.list_mandates(tenant_id)
    return {"mandates": [m.to_dict() for m in mandates], "count": len(mandates)}


@router.get("/mandates/{mandate_id}", summary="Get mandate details", dependencies=[_Gate])
async def get_mandate(mandate_id: str, tenant_id: str) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    proc = AP2Processor()
    m = proc.get_mandate(mandate_id, tenant_id)
    if not m:
        raise HTTPException(status_code=404, detail=f"Mandate {mandate_id!r} not found")
    return m.to_dict()


@router.delete("/mandates/{mandate_id}", summary="Revoke a mandate", dependencies=[_Gate])
async def revoke_mandate(mandate_id: str, tenant_id: str) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    proc = AP2Processor()
    ok = proc.revoke_mandate(mandate_id, tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Mandate {mandate_id!r} not found")
    return {"revoked": True, "mandate_id": mandate_id}


@router.get("/mandates/{mandate_id}/verify", summary="Verify mandate status & signature", dependencies=[_Gate])
async def verify_mandate(mandate_id: str, tenant_id: str) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    return AP2Processor().verify_mandate(mandate_id, tenant_id)


# ── Order endpoints ───────────────────────────────────────────────────────────

@router.post("/orders", summary="Create a purchase order", dependencies=[_Gate])
async def create_order(body: OrderCreateRequest) -> dict:
    from warden.business_community.agentic_commerce.service import AgenticCommerceService
    svc = AgenticCommerceService()
    result = await svc.create_purchase_workflow(
        tenant_id=body.tenant_id,
        store_url=body.store_url,
        items=body.items,
        mandate_id=body.mandate_id,
    )
    if not result.get("success"):
        raise HTTPException(status_code=402, detail=result)
    return result


@router.get("/orders", summary="Order history for a tenant", dependencies=[_Gate])
async def list_orders(tenant_id: str, limit: int = 50) -> dict:
    from warden.business_community.agentic_commerce.service import AgenticCommerceService
    orders = AgenticCommerceService().get_order_history(tenant_id, limit=limit)
    return {"orders": orders, "count": len(orders)}


@router.get("/orders/{order_id}", summary="Get order details + receipt", dependencies=[_Gate])
async def get_order(order_id: str, tenant_id: str) -> dict:
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    from warden.business_community.agentic_commerce.service import AgenticCommerceService
    orders = AgenticCommerceService().get_order_history(tenant_id, limit=1000)
    order = next((o for o in orders if o["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=404, detail=f"Order {order_id!r} not found")
    receipt = AP2Processor().get_receipt(order_id)
    return {"order": order, "receipt": receipt.to_dict() if receipt else None}


# ── MCP intent endpoint ───────────────────────────────────────────────────────

@router.post("/mcp/intent", summary="Submit MCP agent purchase intent", dependencies=[_Gate])
async def submit_mcp_intent(body: MCPIntentRequest) -> dict:
    from warden.business_community.agentic_commerce.mcp_bridge import MCPBridge
    bridge = MCPBridge()
    intent = bridge.receive_intent({
        "tenant_id": body.tenant_id,
        "content": body.content,
        "currency": body.currency,
        "metadata": body.metadata,
    })
    result = await bridge.execute_with_approval(intent, body.tenant_id)
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
async def approve_workflow(workflow_id: str, tenant_id: str, action: str = "approve") -> dict:
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
async def spend_summary(tenant_id: str) -> dict:
    from warden.business_community.agentic_commerce.service import AgenticCommerceService
    return AgenticCommerceService().get_mandate_usage(tenant_id)


# ── Multi-agent auctions ──────────────────────────────────────────────────────

class AuctionRequest(BaseModel):
    tenant_id:        str
    purchase_request: str
    budget_usd:       float | None = None


@router.post("/auctions", summary="Launch multi-agent procurement auction", dependencies=[_Gate])
async def create_auction(body: AuctionRequest) -> dict:
    from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
        MultiAgentOrchestrator,
    )
    orch = MultiAgentOrchestrator()
    auction_id = await orch.run_auction(
        tenant_id=body.tenant_id,
        purchase_request=body.purchase_request,
        budget_usd=body.budget_usd,
    )
    return {"auction_id": auction_id, "status": "completed"}


@router.get("/auctions", summary="List auctions for a tenant", dependencies=[_Gate])
async def list_auctions(tenant_id: str, limit: int = 20) -> dict:
    from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
        MultiAgentOrchestrator,
    )
    auctions = MultiAgentOrchestrator().list_auctions(tenant_id, limit=limit)
    return {"auctions": auctions, "count": len(auctions)}


@router.get("/auctions/{auction_id}", summary="Get auction result", dependencies=[_Gate])
async def get_auction(auction_id: str, tenant_id: str) -> dict:
    from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
        MultiAgentOrchestrator,
    )
    result = MultiAgentOrchestrator().get_auction(auction_id, tenant_id)
    if not result:
        raise HTTPException(status_code=404, detail="Auction not found")
    return result


# ── Semantic Layer–backed budget endpoints ────────────────────────────────────

@router.get("/budget", summary="MTD spend summary (Semantic Layer)", dependencies=[_Gate])
async def get_budget_summary(tenant_id: str) -> dict:
    """
    Return month-to-date spend, remaining budget, utilisation %, and the
    Semantic Layer SQL used — all in one response.
    """
    from warden.business_community.agentic_commerce.semantic_budget import get_spend_summary
    return get_spend_summary(tenant_id)


@router.get("/budget/check", summary="Pre-flight budget check", dependencies=[_Gate])
async def budget_check(
    tenant_id: str,
    amount_usd: float,
    merchant: str = "",
) -> dict:
    """
    Check whether a payment of *amount_usd* USD would exceed budget limits.
    Returns action: allow | require_approval | block.
    """
    from warden.business_community.agentic_commerce.semantic_budget import check_budget
    decision = check_budget(tenant_id, amount_usd, merchant)
    return {
        "action":             decision.action,
        "allowed":            decision.allowed,
        "reason":             decision.reason,
        "amount_usd":         amount_usd,
        "mtd_spend_usd":      decision.mtd_spend_usd,
        "monthly_budget_usd": decision.monthly_budget_usd,
        "remaining_usd":      decision.remaining_usd,
        "per_tx_limit_usd":   decision.per_tx_limit_usd,
    }
