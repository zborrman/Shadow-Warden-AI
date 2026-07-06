"""
warden/api/subscription.py
───────────────────────────
Lemon Squeezy subscription endpoints — extracted from main.py (Phase 3).

Self-contained: the billing client is resolved lazily via
``warden.lemon_billing.get_lemon_billing()`` on each call — no gateway state,
no ``warden.main`` import. Route paths/behaviour identical to the previous
inline handlers; the route-inventory guard verifies the move.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter(tags=["subscription"])


class _CheckoutRequest(BaseModel):
    tenant_id:      str
    plan:           str            # "individual" | "pro" | "enterprise"
    success_url:    str
    cancel_url:     str
    customer_email: str | None = None


@router.get(
    "/subscription/status",
    summary="Current subscription plan and quota for a tenant",
)
async def billing_status(tenant_id: str):
    from warden.lemon_billing import get_lemon_billing  # noqa: PLC0415
    return get_lemon_billing().get_status(tenant_id)


@router.post(
    "/subscription/checkout",
    summary="Create a Lemon Squeezy checkout session — returns hosted payment URL",
)
async def billing_checkout(body: _CheckoutRequest):
    from warden.lemon_billing import get_lemon_billing  # noqa: PLC0415
    lb = get_lemon_billing()
    if not lb._enabled:
        raise HTTPException(503, "Lemon Squeezy billing not configured on this instance.")
    try:
        url = lb.create_checkout_session(
            body.tenant_id, body.plan,
            body.success_url, body.cancel_url,
            body.customer_email,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"checkout_url": url}


@router.get(
    "/subscription/portal",
    summary="Return Lemon Squeezy customer portal URL for self-serve plan management",
)
async def billing_portal(tenant_id: str):
    from warden.lemon_billing import get_lemon_billing  # noqa: PLC0415
    try:
        url = get_lemon_billing().get_portal_url(tenant_id)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"portal_url": url}


@router.post(
    "/subscription/webhook",
    summary="Lemon Squeezy webhook receiver — validates signature and updates subscription state",
    include_in_schema=False,
)
async def billing_webhook(request: Request):
    from warden.lemon_billing import get_lemon_billing  # noqa: PLC0415
    lb         = get_lemon_billing()
    payload    = await request.body()
    sig_header = request.headers.get("X-Signature", "")
    try:
        etype = lb.handle_webhook(payload, sig_header)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"received": True, "event_type": etype}
