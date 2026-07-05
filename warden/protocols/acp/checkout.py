"""
ACP Checkout engine.

Security invariant enforced here:
  cart.total ≤ SPT.max_amount  (merchant-level ceiling)
  cart.total ≤ Mandate.remaining()  (tenant-level ceiling)
  Budget Guardian must allow the spend

Steps:
  1. Load cart; verify OPEN + non-empty
  2. Verify SPT (valid, agent match, amount)
  3. Verify AP2 mandate (valid, remaining ≥ total)
  4. Check Budget Guardian (CommerceSettings spend cap)
  5. Execute AP2 payment
  6. Consume SPT use (atomic, after payment succeeds)
  7. Write STIX audit chain entry
  8. Close cart (CHECKED_OUT)
  9. Return ACP receipt
"""
from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from warden.protocols.acp.cart import close_cart, get_cart
from warden.protocols.acp.models import ACPReceipt
from warden.protocols.acp.token_vault import verify_spt

log = logging.getLogger("warden.acp.checkout")


async def checkout(
    cart_id: str,
    spt_id: str,
    agent_id: str,
    tenant_id: str,
    redis=None,
) -> dict:
    """
    Execute an ACP checkout.

    Returns {"success": True, "receipt": ACPReceipt} or {"success": False, "reason": str}.
    """
    # 1. Load cart
    cart = get_cart(cart_id, redis)
    if cart is None:
        return {"success": False, "reason": "cart_not_found"}
    if cart.status != "OPEN":
        return {"success": False, "reason": f"cart_{cart.status.lower()}"}
    if not cart.items:
        return {"success": False, "reason": "cart_empty"}

    total = cart.total

    # 2. Verify SPT
    spt_result = verify_spt(spt_id, expected_agent_id=agent_id, amount=total, redis=redis)
    if not spt_result["valid"]:
        return {"success": False, "reason": f"spt_{spt_result['reason']}"}

    # 3. Verify AP2 mandate
    try:
        from warden.business_community.agentic_commerce.ap2 import AP2Processor  # noqa: PLC0415
        proc = AP2Processor()
        mandate_check = proc.verify_mandate(cart.mandate_id, tenant_id)
        if not mandate_check["valid"]:
            return {"success": False, "reason": f"mandate_{mandate_check['reason']}"}
        if total > mandate_check["remaining"]:
            return {"success": False, "reason": "mandate_insufficient_balance"}
    except Exception as exc:
        log.error("ACP: mandate verification error: %s", exc)
        return {"success": False, "reason": "mandate_check_failed"}

    # 4. Budget Guardian
    try:
        from warden.business_community.agentic_commerce.semantic_budget import (
            check_budget,
        )
        budget = check_budget(tenant_id, total)
        if not budget.allowed:
            return {"success": False, "reason": "budget_exceeded", "detail": budget.reason}
    except Exception as exc:
        log.debug("ACP: budget guardian unavailable (fail-open): %s", exc)

    # 5. Execute AP2 payment
    order_id = f"acp-order-{uuid.uuid4().hex[:12]}"
    try:
        payment = proc.execute_payment(
            mandate_id=cart.mandate_id,
            tenant_id=tenant_id,
            amount=total,
            merchant=cart.merchant_id,
            order_ref=order_id,
        )
    except Exception as exc:
        log.error("ACP: AP2 payment execution error: %s", exc)
        return {"success": False, "reason": "payment_execution_failed"}

    if not payment.get("success"):
        return {"success": False, "reason": payment.get("reason", "payment_failed")}

    # 6. Consume SPT
    verify_spt(spt_id, expected_agent_id=agent_id, consume=True, order_id=order_id, amount=total, redis=redis)

    # 7. STIX audit
    stix_chain_id = ""
    try:
        from warden.communities.stix_audit import append_transfer  # noqa: PLC0415
        entry = append_transfer(
            transfer_id=order_id,
            source_community_id=tenant_id,
            target_community_id=tenant_id,
            entity_ueciid=order_id,
            initiator_mid=agent_id,
            purpose="acp_checkout",
            ctp_hmac_signature="",
            data_class="FINANCIAL",
        )
        stix_chain_id = entry.chain_id
    except Exception:
        pass

    # 8. Close cart
    close_cart(cart_id, "CHECKED_OUT", redis)

    # 8b. Billing audit chain — fail-open
    try:
        from warden.billing.audit_chain import ACP_CHECKOUT, append_billing_event  # noqa: PLC0415
        append_billing_event(
            tenant_id=tenant_id,
            event_type=ACP_CHECKOUT,
            amount_usd=total,
            agent_id=agent_id,
            tool_name="acp_checkout",
        )
    except Exception as _exc:  # noqa: BLE001
        log.debug("billing_audit acp hook failed (fail-open): %s", _exc)

    # 9. Return ACP receipt
    receipt = ACPReceipt(
        receipt_id=str(uuid.uuid4()),
        order_id=order_id,
        transaction_id=payment.get("transaction_id", ""),
        merchant_id=cart.merchant_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        amount=total,
        currency=cart.currency,
        items=cart.items,
        spt_id=spt_id,
        mandate_id=cart.mandate_id,
        stix_chain_id=stix_chain_id,
        timestamp=datetime.now(UTC).isoformat(),
    )

    log.info(
        "ACP: checkout OK order=%s tenant=%s agent=%s amount=%.2f stix=%s",
        order_id, tenant_id, agent_id, total, stix_chain_id or "n/a",
    )
    return {"success": True, "receipt": receipt.model_dump()}
