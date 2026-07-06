"""
warden/api/webhook_config.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Per-tenant webhook registration REST API (singular ``/webhook``).

Endpoints
─────────
  POST   /webhook  — register or update the tenant's event webhook
  GET    /webhook  — get the current webhook configuration
  DELETE /webhook  — deregister the webhook

Extracted from ``warden/main.py`` (Phase 3b). The WebhookStore singleton is
published to ``warden.runtime`` in the app lifespan; the shared slowapi limiter
comes from ``warden.limiter`` so the same rate-limit buckets apply as before.

Distinct from ``api/webhook.py`` (``/billing/webhook`` Lemon Squeezy) and
``api/webhooks.py`` (``/webhooks/*`` CRUD).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from warden.auth_guard import AuthResult, require_api_key
from warden.limiter import limiter as _limiter
from warden.runtime import runtime as _runtime
from warden.schemas import WebhookRegisterRequest, WebhookStatusResponse

router = APIRouter()


def _require_webhook_store():
    store = _runtime.get("webhook_store")
    if store is None:
        raise HTTPException(503, "Webhook store not available.")
    return store


@router.post(
    "/webhook",
    response_model=WebhookStatusResponse,
    tags=["webhooks"],
    summary="Register or update a webhook for the authenticated tenant",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit("10/minute")
async def register_webhook(
    request: Request,
    payload: WebhookRegisterRequest,
    auth:    AuthResult = Depends(require_api_key),
) -> WebhookStatusResponse:
    """
    Register (or update) a webhook URL for your tenant.
    Shadow Warden will POST a signed JSON event to this URL whenever
    a request meets or exceeds ``min_risk`` (default: high).
    """
    store = _require_webhook_store()
    tenant_id = auth.tenant_id if auth.tenant_id != "default" else "default"
    store.register(
        tenant_id = tenant_id,
        url       = payload.url,
        secret    = payload.secret,
        min_risk  = payload.min_risk,
    )
    cfg = store.get(tenant_id)
    return WebhookStatusResponse(
        tenant_id     = tenant_id,
        url           = cfg["url"],
        min_risk      = cfg["min_risk"],
        registered_at = cfg["created_at"],
        updated_at    = cfg["updated_at"],
    )


@router.get(
    "/webhook",
    response_model=WebhookStatusResponse,
    tags=["webhooks"],
    summary="Get the current webhook configuration for the authenticated tenant",
)
@_limiter.limit("30/minute")
async def get_webhook(
    request: Request,
    auth:    AuthResult = Depends(require_api_key),
) -> WebhookStatusResponse:
    store = _require_webhook_store()
    tenant_id = auth.tenant_id if auth.tenant_id != "default" else "default"
    cfg = store.get(tenant_id)
    if cfg is None:
        raise HTTPException(404, f"No webhook registered for tenant '{tenant_id}'.")
    return WebhookStatusResponse(
        tenant_id     = tenant_id,
        url           = cfg["url"],
        min_risk      = cfg["min_risk"],
        registered_at = cfg["created_at"],
        updated_at    = cfg["updated_at"],
    )


@router.delete(
    "/webhook",
    tags=["webhooks"],
    summary="Deregister the webhook for the authenticated tenant",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit("10/minute")
async def delete_webhook(
    request: Request,
    auth:    AuthResult = Depends(require_api_key),
) -> dict:
    store = _require_webhook_store()
    tenant_id = auth.tenant_id if auth.tenant_id != "default" else "default"
    deleted = store.deregister(tenant_id)
    if not deleted:
        raise HTTPException(404, f"No webhook registered for tenant '{tenant_id}'.")
    return {"status": "deleted", "tenant_id": tenant_id}
