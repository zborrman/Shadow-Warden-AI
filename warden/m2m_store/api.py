"""
warden/m2m_store/api.py
──────────────────────────
M2M Commerce Store — FastAPI router.

Prefix: /m2m-store
Tier:   every plan (API key only)

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
import time

from fastapi import APIRouter, Depends, HTTPException, Query

from warden.auth_guard import AuthResult, require_api_key
from warden.m2m_store.catalog import get_catalog
from warden.m2m_store.inventory import OwnershipError, get_inventory
from warden.m2m_store.models import OfferRequest, OrderRequest, Product
from warden.m2m_store.security import (
    PromptInjectionError,
    check_rate_limit,
    validate_content_string,
    validate_fido2_token,
    validate_offer_request,
    validate_order_request,
)
from warden.m2m_store.store_agent import get_agent

log = logging.getLogger("warden.m2m_store.api")

router = APIRouter(prefix="/m2m-store", tags=["M2M Store"])
AuthDep = Depends(require_api_key)

# Fields only the owner may see. The catalog is shared across sellers; the
# seller's tenant id is not part of what a buyer is shown.
_PRIVATE = {"tenant_id"}
# A seller can read an order for its product; the buyer's payment token is
# not part of that.
_ORDER_PRIVATE = {"payment_token"}


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
    return [p.model_dump(exclude=_PRIVATE) for p in products]


@router.get("/catalog/ucp", response_model=dict)
async def ucp_catalog(auth: AuthResult = AuthDep):
    """UCP-compatible JSON catalog for external AI agent discovery."""
    return get_catalog().to_ucp_catalog()


@router.get("/catalog/{product_id}", response_model=dict)
async def get_product(product_id: str, auth: AuthResult = AuthDep):
    p = get_catalog().get_product(product_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return p.model_dump(exclude=_PRIVATE)


@router.post("/products", response_model=dict, status_code=201)
async def add_product(product: Product, auth: AuthResult = AuthDep):
    """
    Create a product owned by the caller's tenant, or update one it owns.

    Catalog text is read by other tenants' buying agents, so it is screened
    for injection patterns before it is stored.
    """
    try:
        for field in ("name", "description", "category", "unit"):
            validate_content_string(getattr(product, field), field)
    except PromptInjectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        saved = get_inventory().add_product(product, tenant_id=auth.tenant_id)
    except OwnershipError as exc:
        raise HTTPException(status_code=409, detail="Product id belongs to another seller") from exc
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
    get_inventory().save_offer(offer)

    return offer.model_dump(exclude={"seller_tenant_id"})


@router.post("/offers/{offer_id}/reserve", response_model=dict)
async def extend_reservation(
    offer_id: str,
    agent_id: str = Query(...),
    auth: AuthResult = AuthDep,
):
    inv = get_inventory()
    offer = inv.get_offer(offer_id, auth.tenant_id)
    if offer is None:
        raise HTTPException(status_code=404, detail="Offer not found or expired")
    _rate_guard(agent_id)

    # The reservation is extended with the offer: extending only the offer let
    # the purge release the stock under a still-valid offer.
    valid_until = int(time.time()) + 45
    if not inv.extend_offer(offer_id, auth.tenant_id, valid_until):
        raise HTTPException(status_code=410, detail="Offer expired")
    if offer.reservation_id:
        inv.extend(offer.reservation_id, 45)
    return {"offer_id": offer_id, "valid_until": valid_until}


# ── Orders ────────────────────────────────────────────────────────────────────

@router.post("/orders", response_model=dict, status_code=201)
async def create_order(body: OrderRequest, auth: AuthResult = AuthDep):
    try:
        validate_order_request(body.offer_id, body.mandate_id, body.payment_token)
    except PromptInjectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    inv = get_inventory()
    # Scoped to the caller: another tenant's offer id reads as not found.
    offer = inv.get_offer(body.offer_id, auth.tenant_id)
    if offer is None:
        raise HTTPException(status_code=404, detail="Offer not found or expired")
    if int(time.time()) > offer.valid_until:
        raise HTTPException(status_code=410, detail="Offer expired")

    _rate_guard(offer.agent_id)

    # FIDO2 validation for state-changing endpoint
    fido_result = validate_fido2_token(body.payment_token, offer.agent_id)
    if not fido_result["valid"]:
        raise HTTPException(status_code=401, detail=f"FIDO2 validation failed: {fido_result['reason']}")

    # One order per offer, across workers. A failed order hands it back.
    if not inv.claim_offer(body.offer_id, auth.tenant_id):
        raise HTTPException(status_code=409, detail="Offer already used or expired")

    result = get_agent().finalize_order(
        offer=offer,
        mandate_id=body.mandate_id,
        payment_token=body.payment_token,
        tenant_id=auth.tenant_id,
    )

    if not result["success"]:
        inv.unclaim_offer(body.offer_id, auth.tenant_id)
        if "action" in result:  # a Budget Guardian decision
            raise HTTPException(status_code=402, detail=result)
        if result.get("reason") == "out_of_stock":
            raise HTTPException(status_code=409, detail=result)
        raise HTTPException(status_code=400, detail=result)

    order = result["order"]
    return {
        "order_id":       order.id,
        "status":         order.status,
        "total":          order.total,
        "total_minor":    order.total_minor,
        "currency":       order.currency,
        "transaction_id": result.get("transaction_id"),
        "stix_chain_id":  order.stix_chain_id,
    }


@router.get("/orders/history", response_model=list[dict])
async def order_history(
    agent_id: str = Query(...),
    limit: int = Query(default=50, le=200),
    auth: AuthResult = AuthDep,
):
    # The caller's own purchases only: the history used to be any agent's,
    # for any tenant that knew or guessed the agent id.
    orders = get_inventory().list_orders(agent_id=agent_id, limit=limit, tenant_id=auth.tenant_id)
    return [o.model_dump(exclude=_ORDER_PRIVATE) for o in orders]


@router.get("/orders/{order_id}", response_model=dict)
async def get_order(order_id: str, auth: AuthResult = AuthDep):
    # Buyer or seller of record only; anyone else gets the same 404 as a
    # missing id, so order ids cannot be probed.
    order = get_inventory().get_order(order_id, tenant_id=auth.tenant_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order.model_dump(exclude=_ORDER_PRIVATE)
