"""
warden/api/action_whitelist.py
──────────────────────────────
FastAPI router for Agent Action Whitelist.
Exposes CRUD endpoints for whitelisting rules and action checks.
"""
from __future__ import annotations

import os
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from warden.agentic.action_whitelist import ActionWhitelist
from warden.agentic.registry import get_registry

router = APIRouter(tags=["admin"])

_ADMIN_KEY = os.getenv("ADMIN_KEY", "")


def _require_admin(x_admin_key: Annotated[str, Header(alias="X-Admin-Key")] = "") -> None:
    if _ADMIN_KEY and x_admin_key != _ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin key required.")


_aw: ActionWhitelist | None = None


def get_whitelist() -> ActionWhitelist:
    global _aw
    if _aw is None:
        registry = get_registry()
        _aw = ActionWhitelist(registry._conn, registry._lock)
    return _aw


# ── Models ────────────────────────────────────────────────────────────────────

class RuleCreateSchema(BaseModel):
    http_method: str = Field(default="*", description="HTTP method (e.g. GET, POST, or *)")
    endpoint_glob: str = Field(default="*", description="Glob pattern matching endpoint")
    max_rps: float = Field(default=0.0, description="Max requests per second (0.0 for unlimited)")


class ActionCheckRequest(BaseModel):
    http_method: str = Field(..., description="HTTP method to check")
    endpoint: str = Field(..., description="Requested endpoint to match against glob")


class ActionCheckResponse(BaseModel):
    allowed: bool = Field(..., description="Whether action is permitted")
    reason: str = Field(..., description="Explanation of authorization decision")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/admin/agents/{agent_id}/whitelist", response_model=list[dict], summary="List whitelist rules for agent")
@router.get("/agents/{agent_id}/whitelist", response_model=list[dict], include_in_schema=False)
async def list_rules(
    agent_id: str,
    _: None = Depends(_require_admin),
    aw: ActionWhitelist = Depends(get_whitelist),
) -> list[dict]:
    return aw.get_rules(agent_id)


@router.post("/admin/agents/{agent_id}/whitelist", response_model=dict, status_code=201, summary="Add whitelist rule for agent")
@router.post("/agents/{agent_id}/whitelist", response_model=dict, status_code=201, include_in_schema=False)
async def add_rule(
    agent_id: str,
    body: RuleCreateSchema,
    _: None = Depends(_require_admin),
    aw: ActionWhitelist = Depends(get_whitelist),
) -> dict:
    try:
        return aw.add_rule(
            agent_id=agent_id,
            http_method=body.http_method,
            endpoint_glob=body.endpoint_glob,
            max_rps=body.max_rps,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/admin/agents/{agent_id}/whitelist/{rule_id}", response_model=dict, summary="Remove whitelist rule for agent")
@router.delete("/agents/{agent_id}/whitelist/{rule_id}", response_model=dict, include_in_schema=False)
async def delete_rule(
    agent_id: str,
    rule_id: str,
    _: None = Depends(_require_admin),
    aw: ActionWhitelist = Depends(get_whitelist),
) -> dict:
    if not aw.delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found.")
    return {"deleted": True, "rule_id": rule_id}


@router.post("/admin/agents/{agent_id}/whitelist/check", response_model=ActionCheckResponse, summary="Check if agent action is allowed")
@router.post("/agents/{agent_id}/whitelist/check", response_model=ActionCheckResponse, include_in_schema=False)
async def check_action(
    agent_id: str,
    body: ActionCheckRequest,
    _: None = Depends(_require_admin),
    aw: ActionWhitelist = Depends(get_whitelist),
) -> ActionCheckResponse:
    allowed, reason = aw.check_action(
        agent_id=agent_id,
        http_method=body.http_method,
        endpoint=body.endpoint,
    )
    return ActionCheckResponse(allowed=allowed, reason=reason)
