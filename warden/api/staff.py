"""
Digital Staff REST API — STAFF-01 + STAFF-06 (FastAPI router /staff/*).

Endpoints:
  GET  /staff/boundaries          → list all agent boundaries
  GET  /staff/boundaries/{id}     → single boundary
  PUT  /staff/boundaries/{id}     → update boundary (allowed_tools, caps, level)
  POST /staff/boundaries/{id}/suspend  → veto / suspend agent
  POST /staff/boundaries/{id}/restore  → restore suspended agent
  GET  /staff/activity            → last N velocity events from Redis
  POST /staff/intent/refund       → sign a refund intent (Rec-3)
"""
from __future__ import annotations

import json
import logging
import time
from decimal import Decimal
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from warden.auth_guard import require_api_key

try:
    from warden.billing.feature_gate import require_feature as _require_feature
    _STAFF_GATE_DEP = [_require_feature("master_agent_enabled")]
except Exception:  # noqa: BLE001
    _STAFF_GATE_DEP = []

from warden.staff.boundaries import (
    BoundaryViolationError,
    get_registry,
)

log = logging.getLogger(__name__)
router = APIRouter(
    prefix="/staff",
    tags=["Digital Staff"],
    dependencies=[Depends(require_api_key), *_STAFF_GATE_DEP],
)


# ── Pydantic models ───────────────────────────────────────────────────────────

class BoundaryUpdate(BaseModel):
    allowed_tools: list[str] | None = None
    spend_ceiling_usd_daily: str | None = None
    refund_cap_usd: str | None = None
    autonomy_level: int | None = None
    escalation_threshold: str | None = None
    max_calls_per_hour: int | None = None
    loop_detection_max: int | None = None

    @field_validator("autonomy_level")
    @classmethod
    def _validate_level(cls, v):
        if v is not None and v not in (1, 2, 3):
            raise ValueError("autonomy_level must be 1, 2, or 3")
        return v


class RefundIntentRequest(BaseModel):
    agent_id: str
    tenant_id: str
    amount_usd: str
    reason: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_redis():
    try:
        from warden.cache import _get_redis_client  # noqa: PLC0415
        return _get_redis_client()
    except Exception:  # noqa: BLE001
        return None


def _registry():
    return get_registry(redis=_get_redis())


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/boundaries", dependencies=_STAFF_GATE_DEP)
def list_boundaries() -> list[dict[str, Any]]:
    return _registry().list_all()


@router.get("/boundaries/{agent_id}", dependencies=_STAFF_GATE_DEP)
def get_boundary(agent_id: str) -> dict[str, Any]:
    reg = _registry()
    b = reg.get(agent_id)
    if b is None:
        raise HTTPException(404, f"No boundary for agent '{agent_id}'")
    return json.loads(b.to_redis())


@router.put("/boundaries/{agent_id}", dependencies=_STAFF_GATE_DEP)
def update_boundary(agent_id: str, update: BoundaryUpdate) -> dict[str, Any]:
    import dataclasses  # noqa: PLC0415
    reg = _registry()
    b = reg.get(agent_id)
    if b is None:
        raise HTTPException(404, f"No boundary for agent '{agent_id}'")

    kwargs: dict[str, Any] = {}
    if update.allowed_tools is not None:
        kwargs["allowed_tools"] = frozenset(update.allowed_tools)
    if update.spend_ceiling_usd_daily is not None:
        kwargs["spend_ceiling_usd_daily"] = Decimal(update.spend_ceiling_usd_daily)
    if update.refund_cap_usd is not None:
        kwargs["refund_cap_usd"] = Decimal(update.refund_cap_usd)
    if update.autonomy_level is not None:
        kwargs["autonomy_level"] = update.autonomy_level
    if update.escalation_threshold is not None:
        kwargs["escalation_threshold"] = update.escalation_threshold
    if update.max_calls_per_hour is not None:
        kwargs["max_calls_per_hour"] = update.max_calls_per_hour
    if update.loop_detection_max is not None:
        kwargs["loop_detection_max"] = update.loop_detection_max

    updated = dataclasses.replace(b, **kwargs)
    reg.put(updated)
    log.info("STAFF: boundary %s updated fields=%s", agent_id, list(kwargs))
    return {"agent_id": agent_id, "updated": True, "fields": list(kwargs)}


@router.post("/boundaries/{agent_id}/suspend", dependencies=_STAFF_GATE_DEP)
def suspend_agent(agent_id: str) -> dict[str, Any]:
    ok = _registry().suspend(agent_id)
    if not ok:
        raise HTTPException(404, f"No boundary for agent '{agent_id}'")
    return {"agent_id": agent_id, "suspended": True, "ts": int(time.time())}


@router.post("/boundaries/{agent_id}/restore", dependencies=_STAFF_GATE_DEP)
def restore_agent(agent_id: str) -> dict[str, Any]:
    ok = _registry().restore(agent_id)
    if not ok:
        raise HTTPException(404, f"No boundary for agent '{agent_id}'")
    return {"agent_id": agent_id, "suspended": False, "ts": int(time.time())}


@router.get("/activity", dependencies=_STAFF_GATE_DEP)
def get_velocity_activity(limit: int = 50) -> list[dict[str, Any]]:
    r = _get_redis()
    if r is None:
        return []
    try:
        keys = r.keys("staff:velocity:*")
        events = []
        for key in keys[:limit]:
            key_str = key.decode() if isinstance(key, bytes) else key
            count = r.zcard(key_str)
            events.append({"key": key_str, "count": count})
        return sorted(events, key=lambda x: x["count"], reverse=True)[:limit]
    except Exception as exc:  # noqa: BLE001
        log.debug("Staff activity error: %s", exc)
        return []


@router.post("/intent/refund", dependencies=_STAFF_GATE_DEP)
def sign_refund_intent(req: RefundIntentRequest) -> dict[str, Any]:
    reg = _registry()
    b = reg.get(req.agent_id)
    if b is None:
        raise HTTPException(404, f"No boundary for agent '{req.agent_id}'")
    try:
        intent = b.sign_refund_intent(
            req.tenant_id, Decimal(req.amount_usd), req.reason
        )
    except BoundaryViolationError as exc:
        raise HTTPException(403, str(exc)) from exc
    return intent
