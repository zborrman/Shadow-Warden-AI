"""
ACP REST API — Agentic Commerce Protocol endpoints.

Prefix:  /acp
Tier:    Community Business+ (agentic_commerce_enabled)
Discovery: GET /.well-known/acp.json (public, no auth)

Endpoints:
  POST   /acp/token              Issue an SPT (merchant call)
  GET    /acp/token/{token_id}   Verify SPT (non-consuming dry-run)
  DELETE /acp/token/{token_id}   Revoke SPT
  POST   /acp/cart               Create cart
  POST   /acp/cart/{cart_id}/items  Add item to cart
  GET    /acp/cart/{cart_id}     Get cart + total
  POST   /acp/cart/{cart_id}/checkout  Checkout (consumes SPT + AP2 payment)
  POST   /acp/refund             Request refund (PENDING_REVIEW)
  GET    /acp/refund/{refund_id} Get refund status
  GET    /acp/refunds            List refunds for tenant
  POST   /acp/refund/{refund_id}/resolve  Human-only approve/reject
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/acp", tags=["acp"])
_Gate = require_feature("agentic_commerce_enabled")

_MERCHANT_ID = os.getenv("ACP_MERCHANT_ID", "shadow-warden-ai")
_BASE_URL    = os.getenv("ACP_BASE_URL", "https://api.shadow-warden-ai.com")


# ── Request / response models ─────────────────────────────────────────────────

class IssueTokenRequest(BaseModel):
    agent_id:    str
    max_amount:  float = Field(..., gt=0)
    currency:    str = "USD"
    scope:       list[str] = Field(default_factory=lambda: ["checkout"])
    ttl_minutes: int = 30
    use_limit:   int = 1


class CreateCartRequest(BaseModel):
    tenant_id:   str
    agent_id:    str
    merchant_id: str = _MERCHANT_ID
    mandate_id:  str
    currency:    str = "USD"


class AddItemRequest(BaseModel):
    product_id:  str
    name:        str
    qty:         int = Field(1, ge=1)
    unit_price:  float = Field(..., gt=0)
    currency:    str = "USD"


class CheckoutRequest(BaseModel):
    spt_id:    str
    agent_id:  str
    tenant_id: str


class RefundRequestBody(BaseModel):
    order_id:    str
    merchant_id: str = _MERCHANT_ID
    agent_id:    str
    tenant_id:   str
    amount:      float = Field(..., gt=0)
    currency:    str = "USD"
    reason:      str = ""


class ResolveRefundRequest(BaseModel):
    action: str   # "approve" | "reject"


# ── Discovery (public, no auth) ───────────────────────────────────────────────

@router.get("/manifest", summary="ACP merchant manifest (public discovery)", include_in_schema=True)
async def acp_manifest() -> dict:
    """ACP discovery manifest — mirrors /.well-known/acp.json."""
    from warden.protocols.acp.models import ACPMerchantManifest
    return ACPMerchantManifest(
        merchant_id=_MERCHANT_ID,
        token_endpoint=f"{_BASE_URL}/acp/token",
        checkout_endpoint=f"{_BASE_URL}/acp/cart/{{cart_id}}/checkout",
        refund_endpoint=f"{_BASE_URL}/acp/refund",
        receipt_endpoint=f"{_BASE_URL}/acp/receipt/{{order_id}}",
    ).model_dump()


# ── SPT endpoints ─────────────────────────────────────────────────────────────

@router.post("/token", summary="Issue a Shared Payment Token (merchant)", dependencies=[_Gate])
async def issue_token(body: IssueTokenRequest) -> dict:
    from warden.protocols.acp.token_vault import issue_spt
    spt = issue_spt(
        merchant_id=_MERCHANT_ID,
        agent_id=body.agent_id,
        max_amount=body.max_amount,
        currency=body.currency,
        scope=body.scope,
        ttl_minutes=body.ttl_minutes,
        use_limit=body.use_limit,
    )
    return spt.model_dump()


@router.get("/token/{token_id}", summary="Verify SPT (dry-run, non-consuming)", dependencies=[_Gate])
async def verify_token(token_id: str, agent_id: str | None = None) -> dict:
    from warden.protocols.acp.token_vault import verify_spt
    result = verify_spt(token_id, expected_agent_id=agent_id)
    spt = result.get("spt")
    return {
        "valid":  result["valid"],
        "reason": result["reason"],
        "token":  spt.model_dump() if spt else None,
    }


@router.delete("/token/{token_id}", summary="Revoke SPT", dependencies=[_Gate])
async def revoke_token(token_id: str) -> dict:
    from warden.protocols.acp.token_vault import revoke_spt
    ok = revoke_spt(token_id)
    if not ok:
        raise HTTPException(404, "Token not found")
    return {"revoked": True, "token_id": token_id}


# ── Cart endpoints ────────────────────────────────────────────────────────────

@router.post("/cart", summary="Create a cart", dependencies=[_Gate])
async def create_cart(body: CreateCartRequest, request: Request) -> dict:
    from warden.protocols.acp.cart import create_cart as _create
    redis = getattr(request.app.state, "redis", None)
    cart = _create(
        tenant_id=body.tenant_id,
        agent_id=body.agent_id,
        merchant_id=body.merchant_id,
        mandate_id=body.mandate_id,
        currency=body.currency,
        redis=redis,
    )
    return cart.model_dump()


@router.get("/cart/{cart_id}", summary="Get cart", dependencies=[_Gate])
async def get_cart(cart_id: str, request: Request) -> dict:
    from warden.protocols.acp.cart import get_cart as _get
    redis = getattr(request.app.state, "redis", None)
    cart = _get(cart_id, redis)
    if cart is None:
        raise HTTPException(404, "Cart not found")
    d = cart.model_dump()
    d["total"] = cart.total
    return d


@router.post("/cart/{cart_id}/items", summary="Add item to cart", dependencies=[_Gate])
async def add_item(cart_id: str, body: AddItemRequest, request: Request) -> dict:
    from warden.protocols.acp.cart import add_item as _add
    from warden.protocols.acp.models import CartItem
    redis = getattr(request.app.state, "redis", None)
    try:
        cart = _add(cart_id, CartItem(**body.model_dump()), redis)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if cart is None:
        raise HTTPException(404, "Cart not found")
    return {"cart_id": cart_id, "total": cart.total, "item_count": len(cart.items)}


@router.post("/cart/{cart_id}/checkout", summary="Checkout cart (dual-ceiling validated)", dependencies=[_Gate])
async def checkout(cart_id: str, body: CheckoutRequest, request: Request) -> dict:
    from warden.protocols.acp.checkout import checkout as _checkout
    redis = getattr(request.app.state, "redis", None)
    result = await _checkout(
        cart_id=cart_id,
        spt_id=body.spt_id,
        agent_id=body.agent_id,
        tenant_id=body.tenant_id,
        redis=redis,
    )
    if not result["success"]:
        status = 402 if "budget" in result.get("reason", "") else 422
        raise HTTPException(status, result.get("reason", "checkout_failed"))
    return result


# ── Refund endpoints ──────────────────────────────────────────────────────────

@router.post("/refund", summary="Request a refund (PENDING_REVIEW)", dependencies=[_Gate])
async def request_refund(body: RefundRequestBody) -> dict:
    from warden.protocols.acp.refund import request_refund as _request
    refund = _request(
        order_id=body.order_id,
        merchant_id=body.merchant_id,
        agent_id=body.agent_id,
        tenant_id=body.tenant_id,
        amount=body.amount,
        currency=body.currency,
        reason=body.reason,
    )
    return {
        **refund.model_dump(),
        "note": "Refund is PENDING_REVIEW. Awaiting human compliance officer approval.",
    }


@router.get("/refund/{refund_id}", summary="Get refund status", dependencies=[_Gate])
async def get_refund(refund_id: str) -> dict:
    from warden.protocols.acp.refund import get_refund as _get
    r = _get(refund_id)
    if r is None:
        raise HTTPException(404, "Refund not found")
    return r.model_dump()


@router.get("/refunds", summary="List refunds for tenant", dependencies=[_Gate])
async def list_refunds(tenant_id: str, status: str | None = None) -> dict:
    from warden.protocols.acp.refund import list_refunds as _list
    refunds = _list(tenant_id, status)
    return {"refunds": [r.model_dump() for r in refunds], "count": len(refunds)}


@router.post("/refund/{refund_id}/resolve", summary="Human approval: approve/reject refund", dependencies=[_Gate])
async def resolve_refund(refund_id: str, body: ResolveRefundRequest) -> dict:
    from warden.protocols.acp.refund import resolve_refund as _resolve
    try:
        ok = _resolve(refund_id, body.action)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not ok:
        raise HTTPException(404, "Refund not found or not in PENDING_REVIEW")
    return {"refund_id": refund_id, "action": body.action, "resolved": True}
