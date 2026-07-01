"""
ACP Cart manager — Redis-backed, 30-minute TTL, reset on each mutation.

Cart lifecycle: OPEN → (checkout) → CHECKED_OUT | ABANDONED
"""
from __future__ import annotations

import logging
import uuid
from contextlib import suppress
from datetime import UTC, datetime

from warden.protocols.acp.models import Cart, CartItem

log = logging.getLogger("warden.acp.cart")

_REDIS_PREFIX = "acp:cart:"
_CART_TTL_S   = 1800   # 30 minutes

# In-process fallback for when Redis is unavailable (dev / tests)
_LOCAL_CARTS: dict[str, str] = {}


# ── Redis helpers ──────────────────────────────────────────────────────────────

def _key(cart_id: str) -> str:
    return f"{_REDIS_PREFIX}{cart_id}"


def _save(cart: Cart, redis) -> None:
    raw = cart.model_dump_json()
    _LOCAL_CARTS[cart.cart_id] = raw
    if redis is None:
        return
    try:
        redis.set(_key(cart.cart_id), raw, ex=_CART_TTL_S)
    except Exception as exc:
        log.debug("ACP cart Redis save failed (using local): %s", exc)


def _load(cart_id: str, redis) -> Cart | None:
    if redis is not None:
        try:
            raw = redis.get(_key(cart_id))
            if raw:
                return Cart.model_validate_json(raw)
        except Exception:
            pass
    # Fallback: in-process dict
    raw = _LOCAL_CARTS.get(cart_id)
    if raw:
        return Cart.model_validate_json(raw)
    return None


def _delete(cart_id: str, redis) -> None:
    _LOCAL_CARTS.pop(cart_id, None)
    if redis is None:
        return
    with suppress(Exception):
        redis.delete(_key(cart_id))


# ── Public API ─────────────────────────────────────────────────────────────────

def create_cart(
    tenant_id: str,
    agent_id: str,
    merchant_id: str,
    mandate_id: str,
    currency: str = "USD",
    redis=None,
) -> Cart:
    cart = Cart(
        cart_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        agent_id=agent_id,
        merchant_id=merchant_id,
        mandate_id=mandate_id,
        currency=currency,
        created_at=datetime.now(UTC).isoformat(),
    )
    _save(cart, redis)
    log.info("ACP: cart created cart=%s tenant=%s", cart.cart_id, tenant_id)
    return cart


def get_cart(cart_id: str, redis) -> Cart | None:
    return _load(cart_id, redis)


def add_item(cart_id: str, item: CartItem, redis) -> Cart | None:
    cart = _load(cart_id, redis)
    if cart is None:
        return None
    if cart.status != "OPEN":
        raise ValueError(f"Cart {cart_id} is {cart.status}, cannot add items")

    # Merge with existing item (same product_id)
    for existing in cart.items:
        if existing.product_id == item.product_id:
            existing.qty += item.qty
            _save(cart, redis)
            return cart

    cart.items.append(item)
    _save(cart, redis)
    return cart


def bind_spt(cart_id: str, spt_id: str, redis) -> Cart | None:
    """Bind an SPT to the cart before checkout."""
    cart = _load(cart_id, redis)
    if cart is None:
        return None
    cart.spt_id = spt_id
    _save(cart, redis)
    return cart


def close_cart(cart_id: str, status: str, redis) -> None:
    cart = _load(cart_id, redis)
    if cart is None:
        return
    cart.status = status
    _save(cart, redis)
    if status in ("CHECKED_OUT", "ABANDONED"):
        # Let TTL clean up naturally; we keep a record in Redis for receipt lookup
        log.info("ACP: cart closed cart=%s status=%s", cart_id, status)
