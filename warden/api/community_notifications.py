"""
warden/api/community_notifications.py
────────────────────────────────────
REST endpoints for Community Event Notifications.

Routes
──────
  POST   /communities/{id}/notifications/subscribe
  GET    /communities/{id}/notifications/subscriptions
  DELETE /communities/{id}/notifications/{sub_id}
  PATCH  /communities/{id}/notifications/{sub_id}
  POST   /communities/{id}/notifications/test
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from warden.communities.notifications import (
    VALID_CHANNELS,
    VALID_EVENTS,
    fire_event,
    list_subscriptions,
    set_active,
    subscribe,
    unsubscribe,
)

log = logging.getLogger("warden.api.community_notifications")

router = APIRouter(prefix="/communities", tags=["Community Notifications"])


class SubscribeRequest(BaseModel):
    tenant_id: str
    channel:   str = Field(..., pattern="^(slack|teams|email)$")
    target:    str = Field(..., min_length=1)
    label:     str = Field("", max_length=80)
    events:    list[str] | None = None


class PatchSubRequest(BaseModel):
    active: bool | None = None
    events: list[str] | None = None


class TestRequest(BaseModel):
    tenant_id:  str
    event_type: str = "member_joined"


# ── Subscribe ─────────────────────────────────────────────────────────────────

@router.post("/{community_id}/notifications/subscribe", status_code=201)
async def subscribe_endpoint(community_id: str, req: SubscribeRequest) -> dict[str, Any]:
    if req.channel not in VALID_CHANNELS:
        raise HTTPException(400, f"channel must be one of {VALID_CHANNELS}")
    if req.events:
        bad = [e for e in req.events if e not in VALID_EVENTS]
        if bad:
            raise HTTPException(400, f"Unknown events: {bad}. Valid: {list(VALID_EVENTS)}")
    try:
        sub = subscribe(
            community_id = community_id,
            tenant_id    = req.tenant_id,
            channel      = req.channel,
            target       = req.target,
            label        = req.label,
            events       = req.events,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return sub.to_dict()


# ── List ──────────────────────────────────────────────────────────────────────

@router.get("/{community_id}/notifications/subscriptions")
async def list_subs(
    community_id: str,
    tenant_id: str | None = Query(None),
) -> list[dict[str, Any]]:
    return [s.to_dict() for s in list_subscriptions(community_id, tenant_id)]


# ── Delete ────────────────────────────────────────────────────────────────────

@router.delete("/{community_id}/notifications/{sub_id}", status_code=204)
async def delete_sub(community_id: str, sub_id: str, tenant_id: str = Query(...)) -> None:
    if not unsubscribe(sub_id, tenant_id):
        raise HTTPException(404, "Subscription not found or not owned by tenant")


# ── Patch (toggle active / update events) ────────────────────────────────────

@router.patch("/{community_id}/notifications/{sub_id}")
async def patch_sub(
    community_id: str,
    sub_id:       str,
    req:          PatchSubRequest,
    tenant_id:    str = Query(...),
) -> dict[str, Any]:
    if req.active is not None and not set_active(sub_id, tenant_id, req.active):
        raise HTTPException(404, "Subscription not found or not owned by tenant")
    subs = [s for s in list_subscriptions(community_id, tenant_id) if s.sub_id == sub_id]
    if not subs:
        raise HTTPException(404, "Subscription not found")
    return subs[0].to_dict()


# ── Test fire ─────────────────────────────────────────────────────────────────

@router.post("/{community_id}/notifications/test")
async def test_notification(community_id: str, req: TestRequest) -> dict[str, Any]:
    if req.event_type not in VALID_EVENTS:
        raise HTTPException(400, f"event_type must be one of {list(VALID_EVENTS)}")
    sample_payloads: dict[str, dict] = {
        "member_joined":       {"tenant_id": req.tenant_id, "display_name": "Test User", "role": "member"},
        "transfer_completed":  {"ueciid": "SEP-TestEntity001", "target_community_id": "community-test", "status": "completed", "risk_score": 0.12},
        "compliance_changed":  {"old_score": 72, "new_score": 85, "status": "COMPLIANT"},
        "evolution_published": {"title": "Test Bundle", "rule_type": "semantic", "threat_score": 0.55},
    }
    sent = await fire_event(
        community_id   = community_id,
        event_type     = req.event_type,
        payload        = sample_payloads[req.event_type],
        community_name = f"Community {community_id[:8]}",
    )
    return {"sent": sent, "event_type": req.event_type, "community_id": community_id}
