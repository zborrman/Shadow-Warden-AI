"""
warden/settings/api.py
───────────────────────
Unified Settings Hub — REST API.

Routes
──────
  GET    /settings                     — all settings for tenant
  GET    /settings/agents              — SOVA + MasterAgent config
  PATCH  /settings/agents              — update agent config
  GET    /settings/notifications       — notification channels
  POST   /settings/notifications       — add channel
  PATCH  /settings/notifications/{id} — update channel
  POST   /settings/notifications/{id}/test — fire test message
  DELETE /settings/notifications/{id} — remove channel
  GET    /settings/commerce            — Agentic Commerce config
  PATCH  /settings/commerce            — update commerce config
  GET    /settings/semantic            — Semantic Layer config
  PATCH  /settings/semantic            — update semantic config

Auth: standard X-API-Key. No tier gate — all authenticated tenants can read/write
their own settings (per-section feature gating enforced downstream).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from warden.auth_guard import AuthResult, require_api_key
from warden.settings.models import (
    AgentSettingsPatch,
    AllSettings,
    CommerceSettingsPatch,
    NotificationChannel,
    NotificationChannelPatch,
    SemanticSettingsPatch,
)
from warden.settings.service import get_service

router = APIRouter(prefix="/settings", tags=["Settings"])
AuthDep = Depends(require_api_key)


@router.get("", response_model=AllSettings)
async def get_all(auth: AuthResult = AuthDep):
    return get_service().get_all(auth.tenant_id)


# ── Agents ────────────────────────────────────────────────────────────────────

@router.get("/agents")
async def get_agents(auth: AuthResult = AuthDep):
    return get_service().get_agents(auth.tenant_id)


@router.patch("/agents")
async def patch_agents(body: AgentSettingsPatch, auth: AuthResult = AuthDep):
    return get_service().update_agents(auth.tenant_id, body)


# ── Notifications ─────────────────────────────────────────────────────────────

@router.get("/notifications")
async def list_notifications(auth: AuthResult = AuthDep):
    return get_service().list_notifications(auth.tenant_id)


@router.post("/notifications", status_code=201)
async def add_notification(body: NotificationChannel, auth: AuthResult = AuthDep):
    return get_service().add_notification(auth.tenant_id, body)


@router.patch("/notifications/{channel_id}")
async def update_notification(
    channel_id: str, body: NotificationChannelPatch, auth: AuthResult = AuthDep
):
    try:
        return get_service().update_notification(auth.tenant_id, channel_id, body)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/notifications/{channel_id}/test")
async def test_notification(channel_id: str, auth: AuthResult = AuthDep):
    try:
        return get_service().test_notification(auth.tenant_id, channel_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/notifications/{channel_id}", status_code=204)
async def delete_notification(channel_id: str, auth: AuthResult = AuthDep):
    get_service().delete_notification(auth.tenant_id, channel_id)


# ── Commerce ──────────────────────────────────────────────────────────────────

@router.get("/commerce")
async def get_commerce(auth: AuthResult = AuthDep):
    return get_service().get_commerce(auth.tenant_id)


@router.patch("/commerce")
async def patch_commerce(body: CommerceSettingsPatch, auth: AuthResult = AuthDep):
    return get_service().update_commerce(auth.tenant_id, body)


# ── Semantic Layer ────────────────────────────────────────────────────────────

@router.get("/semantic")
async def get_semantic(auth: AuthResult = AuthDep):
    return get_service().get_semantic(auth.tenant_id)


@router.patch("/semantic")
async def patch_semantic(body: SemanticSettingsPatch, auth: AuthResult = AuthDep):
    return get_service().update_semantic(auth.tenant_id, body)
