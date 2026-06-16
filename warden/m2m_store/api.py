"""
warden/m2m_store/api.py
──────────────────────────
M2M Commerce Store — FastAPI router.

Prefix: /m2m-store
Tier:   Enterprise (feature gate: m2m_store_enabled)

Routes
──────
  GET  /m2m-store/catalog                 — search products (UCP-compatible)
  GET  /m2m-store/catalog/ucp             — UCP JSON catalog for external agents
  GET  /m2m-store/catalog/{id}            — product detail
  POST /m2m-store/offers                  — generate dynamic price offer
  POST /m2m-store/offers/{id}/reserve     — confirm/extend reservation
  POST /m2m-store/orders                  — create order (budget check + AP2 payment)
  GET  /m2m-store/orders/{id}             — order status
  GET  /m2m-store/orders/history          — agent order history
  POST /m2m-store/products                — add product to catalog (admin)
"""
from __future__ import annotations

import logging

from cachetools import TTLCache  # type: ignore[import-untyped]
from fastapi import APIRouter, Depends, HTTPException, Query

from warden.auth_guard import AuthResult, require_api_key
from warden.m2m_store.catalog import get_catalog
from warden.m2m_store.inventory import get_inventory
from warden.m2m_store.models import OfferRequest, OrderRequest, Product
from warden.m2m_store.security import (
    PromptInjectionError,
    check_rate_limit,
    validate_fido2_token,
    validate_offer_request,
    validate_order_request,
)
from warden.m2m_store.store_agent import get_agent

log = logging.getLogger("warden.m2m_store.api")

router = APIRouter(prefix="/m2m-store", tags=["M2M Store"])
AuthDep = Depends(require_api_key)

# In-process offer cache with 45-second TTL to prevent memory leak from abandoned offers
_offers: TTLCache = TTLCache(maxsize=10_000, ttl=45)


def _rate_guard(agent_id: str) -> None:
    if not check_rate_limit(agent_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded — 100 req/min per agent")


# ── Catalog ───────────────────────────────────────────────────────────────────

@router.get("/catalog", response_model=list[dict])
async def search_catalog(
    q: str = Query(default=""),
    category: str = Query(default=""),
    min_price: float = Query(default=0.0),
    max_price: float = Query(default=1_000_000.0),
    in_stock_only: bool = Query(default=True),
    auth: AuthResult = AuthDep,
):
    filters = {
        "category": category or None,
        "min_price": min_price,
        "max_price": max_price,
        "in_stock_only": in_stock_only,
    }
    products = get_catalog().search(q, filters)
    return [p.model_dump() for p in products]


@router.get("/catalog/ucp", response_model=dict)
async def ucp_catalog(auth: AuthResult = AuthDep):
    """UCP-compatible JSON catalog for external AI agent discovery."""
    return get_catalog().to_ucp_catalog()


@router.get("/catalog/{product_id}", response_model=dict)
async def get_product(product_id: str, auth: AuthResult = AuthDep):
    p = get_catalog().get_product(product_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return p.model_dump()


@router.post("/products", response_model=dict, status_code=201)
async def add_product(product: Product, auth: AuthResult = AuthDep):
    """Admin endpoint — add a product to the catalog."""
    saved = get_catalog().add_product(product)
    return {"id": saved.id, "name": saved.name}


# ── Offers ────────────────────────────────────────────────────────────────────

@router.post("/offers", response_model=dict, status_code=201)
async def create_offer(body: OfferRequest, auth: AuthResult = AuthDep):
    try:
        validate_offer_request(body.product_id, body.agent_id)
    except PromptInjectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _rate_guard(body.agent_id)

    agent = get_agent()
    offer = agent.generate_offer(
        agent_id=body.agent_id,
        product_id=body.product_id,
        qty=body.qty,
        tenant_id=auth.tenant_id,
    )
    if offer is None:
        raise HTTPException(status_code=409, detail="Product unavailable or insufficient stock")

    offer = agent.hold_reservation(offer)
    _offers[offer.id] = offer

    return offer.model_dump()


@router.post("/offers/{offer_id}/reserve", response_model=dict)
async def extend_reservation(
    offer_id: str,
    agent_id: str = Query(...),
    auth: AuthResult = AuthDep,
):
    offer = _offers.get(offer_id)
    if offer is None:
        raise HTTPException(status_code=404, detail="Offer not found or expired")
    _rate_guard(agent_id)

    import time
    offer.valid_until = int(time.time()) + 45
    return {"offer_id": offer_id, "valid_until": offer.valid_until}


# ── Orders ────────────────────────────────────────────────────────────────────

@router.post("/orders", response_model=dict, status_code=201)
async def create_order(body: OrderRequest, auth: AuthResult = AuthDep):
    try:
        validate_order_request(body.offer_id, body.mandate_id, body.payment_token)
    except PromptInjectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    offer = _offers.get(body.offer_id)
    if offer is None:
        raise HTTPException(status_code=404, detail="Offer not found or expired")

    import time
    if int(time.time()) > offer.valid_until:
        _offers.pop(body.offer_id, None)
        raise HTTPException(status_code=410, detail="Offer expired")

    _rate_guard(offer.agent_id)

    # FIDO2 validation for state-changing endpoint
    fido_result = validate_fido2_token(body.payment_token, offer.agent_id)
    if not fido_result["valid"]:
        raise HTTPException(status_code=401, detail=f"FIDO2 validation failed: {fido_result['reason']}")

    result = get_agent().finalize_order(
        offer=offer,
        mandate_id=body.mandate_id,
        payment_token=body.payment_token,
        tenant_id=auth.tenant_id,
    )

    if not result["success"]:
        reason = result.get("reason", "order_failed")
        if "budget" in reason:
            raise HTTPException(status_code=402, detail=result)
        raise HTTPException(status_code=400, detail=result)

    _offers.pop(body.offer_id, None)
    order = result["order"]
    return {
        "order_id":       order.id,
        "status":         order.status,
        "total":          order.total,
        "transaction_id": result.get("transaction_id"),
        "stix_chain_id":  order.stix_chain_id,
    }


@router.get("/orders/history", response_model=list[dict])
async def order_history(
    agent_id: str = Query(...),
    limit: int = Query(default=50, le=200),
    auth: AuthResult = AuthDep,
):
    orders = get_inventory().list_orders(agent_id=agent_id, limit=limit)
    return [o.model_dump() for o in orders]


@router.get("/orders/{order_id}", response_model=dict)
async def get_order(order_id: str, auth: AuthResult = AuthDep):
    order = get_inventory().get_order(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order.model_dump()
