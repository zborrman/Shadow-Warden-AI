"""
warden/api/red_team.py  (AR-11)
────────────────────────────────
REST endpoints for the red-team autopilot.

Endpoints
─────────
  POST /agent/red-team          — start a red-team session (requires RED_TEAM_ENABLED=true)
  GET  /agent/red-team/status   — last session result
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from warden.auth_guard import require_api_key

router = APIRouter(
    prefix="/agent/red-team",
    tags=["Red Team"],
    dependencies=[Depends(require_api_key)],
)

_ENABLED = os.getenv("RED_TEAM_ENABLED", "false").lower() == "true"


class RedTeamRequest(BaseModel):
    attack_class: str = "jailbreak"


@router.post("", summary="Start a red-team probe session")
async def start_red_team(body: RedTeamRequest):
    if not _ENABLED:
        raise HTTPException(
            status_code=403,
            detail="Red-team autopilot is disabled. Set RED_TEAM_ENABLED=true to enable.",
        )
    try:
        from warden.agent.red_team import run_session  # noqa: PLC0415
    except ImportError as exc:
        raise HTTPException(status_code=503, detail=f"red_team module unavailable: {exc}") from exc

    result = await run_session(body.attack_class)
    return result.__dict__


@router.get("/status", summary="Last red-team session result")
async def red_team_status():
    try:
        from warden.agent.red_team import get_last_result  # noqa: PLC0415
    except ImportError as exc:
        raise HTTPException(status_code=503, detail=f"red_team module unavailable: {exc}") from exc

    r = get_last_result()
    if r is None:
        return {"status": "no_session", "message": "No red-team session has run yet."}
    return r.__dict__
