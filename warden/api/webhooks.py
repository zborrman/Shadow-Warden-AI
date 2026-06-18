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

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


# ── Auth dependency ────────────────────────────────────────────────────────────

def _tenant(request: Any) -> str:
    try:
        from warden.auth_guard import get_tenant_id  # noqa: PLC0415
        return get_tenant_id(request)
    except Exception:
        return request.headers.get("X-Tenant-ID", "default")


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
async def create_webhook(body: WebhookCreate, request: Any = None):
    from warden.webhooks.engine import create_endpoint  # noqa: PLC0415
    tenant_id = _tenant(request) if request else "default"
    ep = create_endpoint(
        tenant_id=tenant_id,
        url=str(body.url),
        secret=body.secret,
        events=body.events,
    )
    return WebhookOut(id=ep.id, url=ep.url, events=ep.events,
                      enabled=ep.enabled, created_at=ep.created_at)


@router.get("/", response_model=list[WebhookOut])
async def list_webhooks(request: Any = None):
    from warden.webhooks.engine import list_endpoints  # noqa: PLC0415
    tenant_id = _tenant(request) if request else "default"
    eps = list_endpoints(tenant_id)
    return [WebhookOut(id=e.id, url=e.url, events=e.events,
                       enabled=e.enabled, created_at=e.created_at) for e in eps]


@router.delete("/{endpoint_id}")
async def delete_webhook(endpoint_id: str, request: Any = None):
    from warden.webhooks.engine import delete_endpoint  # noqa: PLC0415
    tenant_id = _tenant(request) if request else "default"
    ok = delete_endpoint(endpoint_id, tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"deleted": endpoint_id}


@router.get("/{endpoint_id}/history")
async def webhook_history(endpoint_id: str, limit: int = 50):
    from warden.webhooks.engine import delivery_history  # noqa: PLC0415
    return delivery_history(endpoint_id, limit)


@router.get("/events")
async def list_event_types():
    from warden.webhooks.engine import EVENT_TYPES  # noqa: PLC0415
    return sorted(EVENT_TYPES)


@router.post("/test/{endpoint_id}")
async def test_webhook(endpoint_id: str, request: Any = None):
    from warden.webhooks.engine import fire_event, list_endpoints  # noqa: PLC0415
    tenant_id = _tenant(request) if request else "default"
    eps = [e for e in list_endpoints(tenant_id) if e.id == endpoint_id]
    if not eps:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    await fire_event(
        "filter.blocked", tenant_id,
        {"request_id": "test", "risk_score": 0.99, "flags": ["test_event"]},
    )
    return {"status": "queued", "endpoint_id": endpoint_id}
