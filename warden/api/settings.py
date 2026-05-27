"""FastAPI router for /settings/* — tenant settings management."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from warden.auth_guard import AuthResult, require_api_key
from warden.settings import service as svc
from warden.settings.models import (
    AgentConfig,
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    ChannelCreate,
    NotificationChannel,
    SecretCreate,
    SecretOut,
    SecretUpdate,
    SettingsSummary,
    TestResult,
)

log = logging.getLogger("warden.api.settings")

router = APIRouter(prefix="/settings", tags=["Settings"])


def _tid(auth: AuthResult) -> str:
    return auth.tenant_id


# ── Summary ───────────────────────────────────────────────────────────────────

@router.get("", response_model=SettingsSummary, summary="Get all settings summary")
async def get_settings(auth: AuthResult = Depends(require_api_key)):
    return svc.get_settings_summary(_tid(auth))


# ── API Keys ──────────────────────────────────────────────────────────────────

@router.get("/api-keys", response_model=list[ApiKeyOut], summary="List API keys")
async def list_api_keys(auth: AuthResult = Depends(require_api_key)):
    return svc.get_api_keys(_tid(auth))


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=201,
             summary="Create API key — full key shown once")
async def create_api_key(body: ApiKeyCreate, auth: AuthResult = Depends(require_api_key)):
    return svc.create_api_key(_tid(auth), body.label)


@router.delete("/api-keys/{key_id}", status_code=204, summary="Revoke API key")
async def revoke_api_key(key_id: str, auth: AuthResult = Depends(require_api_key)):
    if not svc.revoke_api_key(_tid(auth), key_id):
        raise HTTPException(404, detail="API key not found")


# ── Secrets ───────────────────────────────────────────────────────────────────

@router.get("/secrets", response_model=list[SecretOut], summary="List secrets (metadata only)")
async def list_secrets(auth: AuthResult = Depends(require_api_key)):
    return svc.get_secrets(_tid(auth))


@router.post("/secrets", response_model=SecretOut, status_code=201,
             summary="Create secret (value encrypted at rest)")
async def create_secret(body: SecretCreate, auth: AuthResult = Depends(require_api_key)):
    return svc.create_secret(
        _tid(auth), body.name, body.value, body.description,
        body.expires_at.isoformat() if body.expires_at else None,
    )


@router.put("/secrets/{secret_id}", response_model=SecretOut, summary="Update secret")
async def update_secret(
    secret_id: str,
    body: SecretUpdate,
    auth: AuthResult = Depends(require_api_key),
):
    result = svc.update_secret(
        _tid(auth), secret_id, body.value,
        body.description,
        body.expires_at.isoformat() if body.expires_at else None,
    )
    if not result:
        raise HTTPException(404, detail="Secret not found")
    return result


@router.delete("/secrets/{secret_id}", status_code=204, summary="Delete secret")
async def delete_secret(secret_id: str, auth: AuthResult = Depends(require_api_key)):
    if not svc.delete_secret(_tid(auth), secret_id):
        raise HTTPException(404, detail="Secret not found")


# ── Agent Config ──────────────────────────────────────────────────────────────

@router.get("/agents", response_model=AgentConfig, summary="Get agent config")
async def get_agent_config(auth: AuthResult = Depends(require_api_key)):
    return svc.get_agent_config(_tid(auth))


@router.patch("/agents", response_model=AgentConfig, summary="Update agent config")
async def update_agent_config(
    body: AgentConfig,
    auth: AuthResult = Depends(require_api_key),
):
    return svc.update_agent_config(_tid(auth), body.model_dump(exclude_unset=False))


# ── Notifications ─────────────────────────────────────────────────────────────

@router.get("/notifications", response_model=list[NotificationChannel],
            summary="List notification channels")
async def list_channels(auth: AuthResult = Depends(require_api_key)):
    return svc.get_notification_channels(_tid(auth))


@router.post("/notifications/channels", response_model=NotificationChannel, status_code=201,
             summary="Add notification channel")
async def add_channel(body: ChannelCreate, auth: AuthResult = Depends(require_api_key)):
    return svc.add_notification_channel(_tid(auth), body.type, body.label, body.config)


@router.post("/notifications/channels/{channel_id}/test", response_model=TestResult,
             summary="Send test notification")
async def test_channel(channel_id: str, auth: AuthResult = Depends(require_api_key)):
    return svc.test_notification_channel(_tid(auth), channel_id)


@router.delete("/notifications/channels/{channel_id}", status_code=204,
               summary="Delete notification channel")
async def delete_channel(channel_id: str, auth: AuthResult = Depends(require_api_key)):
    if not svc.delete_notification_channel(_tid(auth), channel_id):
        raise HTTPException(404, detail="Channel not found")


# ── PATCH /settings/{section} convenience endpoint ───────────────────────────

@router.patch("/{section}", summary="Update named settings section")
async def patch_section(
    section: str,
    body: dict[str, Any],
    auth: AuthResult = Depends(require_api_key),
):
    tid = _tid(auth)
    if section == "agents":
        return svc.update_agent_config(tid, body)
    raise HTTPException(400, detail=f"Unknown section '{section}'. Use /settings/agents, etc.")
