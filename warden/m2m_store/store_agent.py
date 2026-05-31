"""
warden/m2m_store/store_agent.py
────────────────────────────────
StoreAgent — AI seller: dynamic pricing, reservations, order finalization.

Pricing algorithm:
  price_final = price_base × demand_factor × loyalty_factor
  demand_factor  = 1.0 + (1.0 - stock_pct) × 0.20  (up to +20% when low stock)
  loyalty_factor = max(0.80, 1.0 - purchase_history × 0.02)  (up to -20% for repeat buyers)
  max_discount   = StoreConfig.max_discount
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import UTC, datetime

from warden.m2m_store.catalog import get_catalog
from warden.m2m_store.inventory import get_inventory
from warden.m2m_store.models import Offer, Order, StoreConfig

log = logging.getLogger("warden.m2m_store.agent")

# Default store config (overridden per-tenant via Redis/DB)
_DEFAULT_CONFIG = StoreConfig(
    tenant_id="default",
    max_discount=20.0,
    default_ttl_seconds=45,
    rate_limit_per_minute=100,
)


def _get_config(tenant_id: str) -> StoreConfig:
    try:
        from warden.settings.service import get_service
        cfg = get_service().get_commerce(tenant_id)
        return StoreConfig(
            tenant_id=tenant_id,
            max_discount=min(cfg.per_transaction_limit_usd / 100.0, 30.0) if cfg.per_transaction_limit_usd else 20.0,
            default_ttl_seconds=45,
            rate_limit_per_minute=100,
        )
    except Exception:
        return _DEFAULT_CONFIG


def _purchase_history(agent_id: str) -> int:
    """Rough order count for loyalty discount — reads from inventory SQLite."""
    try:
        orders = get_inventory().list_orders(agent_id=agent_id, limit=200)
        return len([o for o in orders if o.status in ("PAID", "SHIPPED")])
    except Exception:
        return 0


class StoreAgent:
    """AI pricing agent for the M2M Commerce Store seller side."""

    def generate_offer(
        self,
        agent_id: str,
        product_id: str,
        qty: int = 1,
        tenant_id: str = "default",
    ) -> Offer | None:
        """
        Generate a dynamic price offer for the requesting agent.
        Returns None if product unavailable.
        """
        product = get_catalog().get_product(product_id)
        if product is None or not product.active:
            return None
        if product.available < qty:
            log.info("StoreAgent: insufficient stock product=%s avail=%d req=%d", product_id, product.available, qty)
            return None

        cfg = _get_config(tenant_id)

        # ── Demand factor (higher when stock is low) ──────────────────────────
        stock_pct = product.available / max(product.stock, 1)
        demand_factor = 1.0 + (1.0 - stock_pct) * 0.20

        # ── Loyalty factor (discount for repeat buyers) ───────────────────────
        history = _purchase_history(agent_id)
        loyalty_discount_pct = min(history * 2.0, cfg.max_discount)
        loyalty_factor = 1.0 - loyalty_discount_pct / 100.0

        price_final = round(product.price_base * demand_factor * loyalty_factor * qty, 2)
        discount_pct = round(max(0, (1 - loyalty_factor) * 100), 1)

        # ── Optional LLM explanation (Haiku, non-blocking) ───────────────────
        explanation = _generate_explanation(
            product.name, discount_pct, loyalty_discount_pct, demand_factor, qty
        )

        offer = Offer(
            id=str(uuid.uuid4()),
            product_id=product_id,
            agent_id=agent_id,
            qty=qty,
            price_base=product.price_base * qty,
            price_final=price_final,
            discount_percent=discount_pct,
            valid_until=int(time.time()) + cfg.default_ttl_seconds,
            explanation=explanation,
            tenant_id=tenant_id,
        )
        log.info(
            "Offer generated agent=%s product=%s qty=%d price=%.2f discount=%.1f%%",
            agent_id, product_id, qty, price_final, discount_pct,
        )
        return offer

    def hold_reservation(
        self,
        offer: Offer,
        ttl_seconds: int = 45,
    ) -> Offer:
        """Reserve stock for the offer and attach reservation_id."""
        inv = get_inventory()
        reservation_id = inv.reserve(offer.product_id, offer.qty, ttl_seconds)
        if reservation_id:
            offer.reservation_id = reservation_id
        else:
            log.warning("StoreAgent: could not reserve product=%s qty=%d", offer.product_id, offer.qty)
        return offer

    def finalize_order(
        self,
        offer: Offer,
        mandate_id: str,
        payment_token: str,
        tenant_id: str = "default",
    ) -> dict:
        """
        Execute payment via AP2, deduct stock, create order record.
        Returns {"success": True/False, "order": Order | None, ...}
        """
        # ── Budget guardian pre-check ─────────────────────────────────────────
        try:
            from warden.business_community.agentic_commerce.semantic_budget import check_budget
            decision = check_budget(tenant_id, offer.price_final, merchant="m2m-store")
            if not decision.allowed:
                return {
                    "success": False,
                    "reason": decision.reason,
                    "remaining_budget": decision.remaining_usd,
                    "action": decision.action,
                }
        except Exception as exc:
            log.warning("Budget check failed (fail-open): %s", exc)

        # ── AP2 payment execution ─────────────────────────────────────────────
        try:
            from warden.business_community.agentic_commerce.ap2 import AP2Processor
            ap2 = AP2Processor()
            payment = ap2.execute_payment(
                mandate_id=mandate_id,
                tenant_id=tenant_id,
                amount=offer.price_final,
                merchant="m2m-store",
                order_ref=offer.id,
            )
            if not payment.get("success"):
                return {"success": False, "reason": payment.get("reason", "payment_failed")}
        except Exception as exc:
            log.error("AP2 payment failed: %s", exc)
            return {"success": False, "reason": "payment_error"}

        # ── Deduct stock + create order ───────────────────────────────────────
        get_inventory().update_stock(offer.product_id, -offer.qty)
        if offer.reservation_id:
            get_inventory().release(offer.reservation_id)

        order = Order(
            id=str(uuid.uuid4()),
            agent_id=offer.agent_id,
            offer_id=offer.id,
            product_id=offer.product_id,
            mandate_id=mandate_id,
            qty=offer.qty,
            total=offer.price_final,
            status="PAID",
            payment_token=payment_token,
            reservation_id=offer.reservation_id,
            created_at=datetime.now(UTC).isoformat(),
            tenant_id=tenant_id,
        )

        # STIX audit
        try:
            from warden.communities.sep import new_ueciid
            from warden.communities.stix_audit import append_transfer
            _, ueciid = new_ueciid()
            order.stix_chain_id = str(getattr(
                append_transfer(
                    transfer_id=order.id,
                    source_community_id=tenant_id,
                    target_community_id="m2m-store",
                    entity_ueciid=ueciid,
                    initiator_mid=offer.agent_id,
                    purpose="m2m_purchase",
                    ctp_hmac_signature="",
                ),
                "transfer_id", order.id,
            ))
        except Exception as exc:
            log.debug("STIX audit skipped: %s", exc)

        get_inventory().save_order(order)
        log.info("Order finalized order=%s total=%.2f", order.id, order.total)
        return {"success": True, "order": order, "transaction_id": payment.get("transaction_id")}


def _generate_explanation(
    product_name: str,
    discount_pct: float,
    loyalty_pct: float,
    demand_factor: float,
    qty: int,
) -> str:
    """Optional Claude Haiku explanation for the discount (non-blocking)."""
    if not os.getenv("ANTHROPIC_API_KEY") or discount_pct < 1.0:
        return ""
    try:
        import anthropic
        client = anthropic.Anthropic()
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=80,
            messages=[{
                "role": "user",
                "content": (
                    f"You are an AI store assistant. Generate a one-sentence explanation "
                    f"for why the buyer gets a {discount_pct:.0f}% discount on {qty}× {product_name}. "
                    f"Loyalty history: {loyalty_pct:.0f}% off. Demand factor: {demand_factor:.2f}. "
                    f"Be friendly and brief."
                ),
            }],
        )
        block = msg.content[0]
        return (block.text if hasattr(block, "text") else "").strip()
    except Exception:
        return ""


_agent = StoreAgent()


def get_agent() -> StoreAgent:
    return _agent
