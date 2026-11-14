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

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from warden.billing.router import _caller_tenant

router = APIRouter(tags=["subscription"])


def _own_tenant(
    tenant_id: str | None = None,
    caller: str = Depends(_caller_tenant),
) -> str:
    """The tenant a subscription route acts on: the caller's own.

    ``tenant_id`` used to be a bare query parameter with no credential behind
    it, so anyone could read any tenant's plan and - worse - fetch the customer
    portal URL that manages that tenant's subscription. The tenant now comes
    from the API key; naming a different one is refused rather than ignored.
    The operator path (X-Admin-Key + X-Tenant-ID) lives in ``_caller_tenant``.
    """
    if tenant_id and tenant_id != caller:
        raise HTTPException(403, "tenant_id does not match the authenticated tenant.")
    return caller


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
async def billing_status(tenant_id: str = Depends(_own_tenant)):
    from warden.lemon_billing import get_lemon_billing  # noqa: PLC0415
    return get_lemon_billing().get_status(tenant_id)


@router.post(
    "/subscription/checkout",
    summary="Create a Lemon Squeezy checkout session — returns hosted payment URL",
)
async def billing_checkout(body: _CheckoutRequest, caller: str = Depends(_caller_tenant)):
    from warden.lemon_billing import get_lemon_billing  # noqa: PLC0415
    lb = get_lemon_billing()
    if not lb._enabled:
        raise HTTPException(503, "Lemon Squeezy billing not configured on this instance.")
    # A checkout binds a payment to a tenant. Without this, anyone could open
    # one against a tenant they do not hold a key for.
    if body.tenant_id != caller:
        raise HTTPException(403, "tenant_id does not match the authenticated tenant.")
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
async def billing_portal(tenant_id: str = Depends(_own_tenant)):
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
