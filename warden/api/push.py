"""
warden/api/push.py
────────────────────
FastAPI router — Mobile SOC push notification device management.

Prefix: /push
Tier:   Pro+ (mobile_push_enabled)

Endpoints
─────────
POST /push/register              Register a device token for push alerts
DELETE /push/devices/{token}     Unregister a device token
GET  /push/devices               List registered devices for the tenant
GET  /push/health                FCM service availability check
POST /push/test                  Send a test push to all tenant devices
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

log = logging.getLogger("warden.api.push")

router = APIRouter(prefix="/push", tags=["Mobile Push"])
_Gate  = require_feature("mobile_push_enabled")


class RegisterRequest(BaseModel):
    device_token: str  = Field(..., min_length=10, description="FCM or APNs device token")
    platform:     str  = Field(default="android", pattern="^(android|ios)$")
    tenant_id:    str  = Field(default="default")


@router.post("/register", summary="Register a device for push alerts", dependencies=[_Gate])
async def register_device(body: RegisterRequest) -> dict:
    from warden.push.registry import register_device as _reg
    return _reg(body.tenant_id, body.device_token, body.platform)


@router.delete("/devices/{device_token}", summary="Unregister a device token", dependencies=[_Gate])
async def unregister_device(device_token: str) -> dict:
    from warden.push.registry import unregister_device as _unreg
    removed = _unreg(device_token)
    if not removed:
        raise HTTPException(status_code=404, detail="Device token not found")
    return {"status": "unregistered"}


@router.get("/devices", summary="List registered devices for a tenant", dependencies=[_Gate])
async def list_devices(tenant_id: str = "default") -> dict:
    from warden.push.registry import list_devices as _list
    devices = _list(tenant_id)
    return {
        "tenant_id": tenant_id,
        "count":     len(devices),
        "max":       50,
        "devices":   devices,
    }


@router.get("/health", summary="FCM service availability check")
async def push_health() -> dict:
    from warden.push.service import get_push_service
    svc = get_push_service()
    return {
        "status":    "ok" if svc.available else "degraded",
        "fcm":       "available" if svc.available else "unavailable",
        "hint":      "" if svc.available else "Set FIREBASE_CREDENTIALS_JSON or FIREBASE_CREDENTIALS_FILE",
    }


@router.post("/test", summary="Send a test push to all tenant devices", dependencies=[_Gate])
async def send_test_push(tenant_id: str = "default") -> dict:
    from warden.push.registry import get_tokens_for_tenant
    from warden.push.service import get_push_service
    tokens = get_tokens_for_tenant(tenant_id)
    if not tokens:
        return {"sent": 0, "reason": "No registered devices for this tenant"}
    svc = get_push_service()
    sent = svc.send_verdict_alert(tokens, {
        "risk_level":  "high",
        "attack_type": "test_alert",
        "request_id":  "TEST-0000000",
        "tenant_id":   tenant_id,
        "rule_summary": "This is a Shadow Warden test notification.",
    })
    return {"sent": sent, "devices": len(tokens)}
