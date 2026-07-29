"""
warden/api/webhooks.py  (DEV-05)
──────────────────────────────────
FastAPI router — /webhooks/*

Endpoints
---------
POST   /webhooks/                  — register new endpoint
GET    /webhooks/                  — list endpoints for tenant
DELETE /webhooks/{id}              — delete endpoint
GET    /webhooks/{id}/history      — delivery history
GET    /webhooks/events            — supported event type list
POST   /webhooks/test/{id}         — send a test event to endpoint
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl

from warden.auth_guard import AuthResult, require_api_key

# ── Authentication ───────────────────────────────────────────────────────────
#
# Every route requires a valid API key, and the tenant comes from that key.
#
# This module previously had NO auth of any kind, and three compounding bugs
# (all verified against production 2026-07-29):
#
#  1. `GET /webhooks/` returned 200 to an anonymous caller. So did
#     `GET /webhooks/events`. `POST /` — register a webhook URL — was equally
#     open, which is an exfiltration channel: point an endpoint at your own
#     host and receive that tenant's future events.
#
#  2. Handlers took `request: Any = None`. FastAPI does not inject a Request
#     for an `Any`-annotated parameter with a default — it publishes it as a
#     QUERY parameter (confirmed in the OpenAPI schema). So the Request was
#     always None, `_tenant()` never ran, and EVERY caller resolved to the
#     "default" tenant. Cross-tenant isolation did not exist; all tenants shared
#     one bucket. Annotate it `Request` or don't take it.
#
#  3. Because it was a query parameter, `GET /webhooks/?request=x` passed the
#     string "x" into `_tenant()`, which did `request.headers` on a str →
#     AttributeError → HTTP 500. Confirmed against production.
#
# Even had (2) worked, reading the tenant from an X-Tenant-ID header on an
# unauthenticated route is caller-controlled identity. `AuthResult.tenant_id`
# is derived from the presented key, so it cannot be spoofed.
router = APIRouter(
    prefix="/webhooks",
    tags=["Webhooks"],
    dependencies=[Depends(require_api_key)],
)


# ── Auth dependency ────────────────────────────────────────────────────────────

def _tenant(auth: AuthResult) -> str:
    """Tenant identity comes from the presented API key, never from a header."""
    return auth.tenant_id or "default"


# ── Schemas ────────────────────────────────────────────────────────────────────

class WebhookCreate(BaseModel):
    url:    HttpUrl
    secret: str
    events: list[str]


class WebhookOut(BaseModel):
    id:         str
    url:        str
    events:     list[str]
    enabled:    bool
    created_at: str


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/", response_model=WebhookOut)
async def create_webhook(body: WebhookCreate, auth: AuthResult = Depends(require_api_key)):
    from warden.net_guard import SSRFError  # noqa: PLC0415
    from warden.webhooks.engine import create_endpoint  # noqa: PLC0415
    tenant_id = _tenant(auth)
    try:
        ep = create_endpoint(
            tenant_id=tenant_id,
            url=str(body.url),
            secret=body.secret,
            events=body.events,
        )
    except SSRFError as exc:
        raise HTTPException(status_code=422, detail=f"URL rejected: {exc}") from exc
    return WebhookOut(id=ep.id, url=ep.url, events=ep.events,
                      enabled=ep.enabled, created_at=ep.created_at)


@router.get("/", response_model=list[WebhookOut])
async def list_webhooks(auth: AuthResult = Depends(require_api_key)):
    from warden.webhooks.engine import list_endpoints  # noqa: PLC0415
    tenant_id = _tenant(auth)
    eps = list_endpoints(tenant_id)
    return [WebhookOut(id=e.id, url=e.url, events=e.events,
                       enabled=e.enabled, created_at=e.created_at) for e in eps]


@router.delete("/{endpoint_id}")
async def delete_webhook(endpoint_id: str, auth: AuthResult = Depends(require_api_key)):
    from warden.webhooks.engine import delete_endpoint  # noqa: PLC0415
    tenant_id = _tenant(auth)
    ok = delete_endpoint(endpoint_id, tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"deleted": endpoint_id}


@router.get("/{endpoint_id}/history")
async def webhook_history(endpoint_id: str, limit: int = 50,
                          auth: AuthResult = Depends(require_api_key)):
    from warden.webhooks.engine import delivery_history, list_endpoints  # noqa: PLC0415
    # Scope by tenant: this route took only an endpoint_id, so any caller who
    # knew (or guessed) an id could read another tenant's delivery history.
    if not any(e.id == endpoint_id for e in list_endpoints(_tenant(auth))):
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return delivery_history(endpoint_id, limit)


@router.get("/events")
async def list_event_types():
    from warden.webhooks.engine import EVENT_TYPES  # noqa: PLC0415
    return sorted(EVENT_TYPES)


@router.post("/test/{endpoint_id}")
async def test_webhook(endpoint_id: str, auth: AuthResult = Depends(require_api_key)):
    from warden.webhooks.engine import fire_event, list_endpoints  # noqa: PLC0415
    tenant_id = _tenant(auth)
    eps = [e for e in list_endpoints(tenant_id) if e.id == endpoint_id]
    if not eps:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    await fire_event(
        "filter.blocked", tenant_id,
        {"request_id": "test", "risk_score": 0.99, "flags": ["test_event"]},
    )
    return {"status": "queued", "endpoint_id": endpoint_id}
