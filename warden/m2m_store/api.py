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
  POST /m2m-store/products                — create a product, or update one you own
  DELETE /m2m-store/products/{id}         — soft-delete a product you own

Store builder (plan stage M2) — owner routes act on the caller's own rows only
  POST/GET     /m2m-store/stores
  PATCH/DELETE /m2m-store/stores/{store_id}
  POST         /m2m-store/stores/{store_id}/categories
  PATCH/DELETE /m2m-store/categories/{category_id}
  POST/GET     /m2m-store/stores/{store_id}/shipping-zones
  DELETE       /m2m-store/shipping-zones/{zone_id}
  PUT          /m2m-store/products/{id}/prices
  PUT          /m2m-store/products/{id}/translations/{locale}

Storefront (buyer view of an active store)
  GET /m2m-store/storefront/{slug}                 — store + category tree
  GET /m2m-store/storefront/{slug}/catalog/ucp     — per-store UCP feed
  GET /m2m-store/storefront/{slug}/shipping/quote  — shipping + duty estimate
"""
from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import APIRouter, Depends, HTTPException, Query

from warden.auth_guard import AuthResult, require_api_key
from warden.m2m_store import storefront as sf
from warden.m2m_store.catalog import get_catalog
from warden.m2m_store.inventory import OwnershipError, get_inventory
from warden.m2m_store.models import (
    CategoryIn,
    CategoryPatch,
    OfferRequest,
    OrderRequest,
    PriceIn,
    Product,
    ShippingZoneIn,
    StoreIn,
    StorePatch,
    TranslationIn,
)
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


def _screen(*texts: str) -> None:
    """Catalog text is read by other tenants' buying agents: screen it before it is stored."""
    try:
        for text in texts:
            validate_content_string(text or "", "text")
    except PromptInjectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@contextmanager
def _store_errors() -> Iterator[None]:
    try:
        yield
    except sf.StoreNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"{exc} not found") from exc
    except sf.StoreConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except sf.StoreInvalidError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


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
    if p is None or p.deleted_at:
        raise HTTPException(status_code=404, detail="Product not found")
    return p.model_dump(exclude=_PRIVATE) | {
        "prices": sf.get_prices(p.id), "translations": sf.get_translations(p.id),
    }


@router.post("/products", response_model=dict, status_code=201)
async def add_product(product: Product, auth: AuthResult = AuthDep):
    """
    Create a product owned by the caller's tenant, or update one it owns.

    Catalog text is read by other tenants' buying agents, so it is screened
    for injection patterns before it is stored.
    """
    _screen(product.name, product.description, product.category, product.unit)
    product.deleted_at = ""
    if product.id:
        existing = get_inventory().get_product(product.id)
        if existing is not None and existing.deleted_at:
            raise HTTPException(status_code=409, detail="Product was deleted")
    with _store_errors():
        sf.check_placement(auth.tenant_id, product.store_id, product.category_id)
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


@router.delete("/products/{product_id}", status_code=204)
async def delete_product(product_id: str, auth: AuthResult = AuthDep):
    if not get_inventory().delete_product(product_id, auth.tenant_id):
        raise HTTPException(status_code=404, detail="Product not found")


@router.put("/products/{product_id}/prices", response_model=list[dict])
async def set_prices(product_id: str, prices: list[PriceIn], auth: AuthResult = AuthDep):
    if not prices or len(prices) > 32:
        raise HTTPException(status_code=422, detail="between 1 and 32 prices")
    with _store_errors():
        return sf.set_prices(product_id, auth.tenant_id, prices)


@router.put("/products/{product_id}/translations/{locale}", response_model=dict)
async def set_translation(product_id: str, locale: str, body: TranslationIn,
                          auth: AuthResult = AuthDep):
    _screen(body.name, body.description)
    with _store_errors():
        return sf.set_translation(product_id, auth.tenant_id, locale, body)


# ── Store builder ─────────────────────────────────────────────────────────────

@router.post("/stores", response_model=dict, status_code=201)
async def create_store(body: StoreIn, auth: AuthResult = AuthDep):
    _screen(body.name, body.description)
    with _store_errors():
        return sf.create_store(auth.tenant_id, body)


@router.get("/stores", response_model=list[dict])
async def list_stores(auth: AuthResult = AuthDep):
    return sf.list_stores(auth.tenant_id)


@router.patch("/stores/{store_id}", response_model=dict)
async def patch_store(store_id: str, body: StorePatch, auth: AuthResult = AuthDep):
    _screen(body.name or "", body.description or "")
    with _store_errors():
        return sf.patch_store(store_id, auth.tenant_id, body)


@router.delete("/stores/{store_id}", status_code=204)
async def delete_store(store_id: str, auth: AuthResult = AuthDep):
    with _store_errors():
        sf.delete_store(store_id, auth.tenant_id)


@router.post("/stores/{store_id}/categories", response_model=dict, status_code=201)
async def create_category(store_id: str, body: CategoryIn, auth: AuthResult = AuthDep):
    _screen(body.name)
    with _store_errors():
        return sf.create_category(store_id, auth.tenant_id, body)


@router.patch("/categories/{category_id}", response_model=dict)
async def patch_category(category_id: str, body: CategoryPatch, auth: AuthResult = AuthDep):
    _screen(body.name or "")
    with _store_errors():
        return sf.patch_category(category_id, auth.tenant_id, body)


@router.delete("/categories/{category_id}", status_code=204)
async def delete_category(category_id: str, auth: AuthResult = AuthDep):
    with _store_errors():
        sf.delete_category(category_id, auth.tenant_id)


@router.post("/stores/{store_id}/shipping-zones", response_model=dict, status_code=201)
async def create_zone(store_id: str, body: ShippingZoneIn, auth: AuthResult = AuthDep):
    _screen(body.name)
    with _store_errors():
        return sf.create_zone(store_id, auth.tenant_id, body)


@router.get("/stores/{store_id}/shipping-zones", response_model=list[dict])
async def list_zones(store_id: str, auth: AuthResult = AuthDep):
    with _store_errors():
        sf.get_store(store_id, auth.tenant_id)
        return sf.list_zones(store_id)


@router.delete("/shipping-zones/{zone_id}", status_code=204)
async def delete_zone(zone_id: str, auth: AuthResult = AuthDep):
    with _store_errors():
        sf.delete_zone(zone_id, auth.tenant_id)


# ── Storefront ────────────────────────────────────────────────────────────────

@router.get("/storefront/{slug}", response_model=dict)
async def storefront(slug: str, auth: AuthResult = AuthDep):
    with _store_errors():
        store = sf.get_public_store(slug)
        return store | {"categories": sf.category_tree(store["id"])}


@router.get("/storefront/{slug}/catalog/ucp", response_model=dict)
async def storefront_ucp(slug: str, auth: AuthResult = AuthDep):
    with _store_errors():
        return sf.store_ucp_catalog(slug)


@router.get("/storefront/{slug}/shipping/quote", response_model=dict)
async def shipping_quote(
    slug: str,
    country: str = Query(..., min_length=2, max_length=2),
    currency: str = Query(..., min_length=3, max_length=3),
    subtotal_minor: int = Query(default=0, ge=0, le=10**12),
    auth: AuthResult = AuthDep,
):
    with _store_errors():
        return sf.quote_shipping(slug, country, currency, subtotal_minor)
