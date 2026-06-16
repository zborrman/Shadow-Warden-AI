"""
warden/agents/packs/api.py
───────────────────────────
FastAPI router for ARC-like Edge Agent Packs.

Endpoints:
  GET  /agents/packs                  — list available packs
  POST /agents/packs/{name}/deploy    — deploy pack as a marketplace agent
  POST /agents/packs/{name}/analyze   — run pack analysis on sensor data
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

# Trigger pack registration by importing the concrete packs
import warden.agents.packs.crop_health_monitor  # noqa: F401
import warden.agents.packs.disease_detector      # noqa: F401
import warden.agents.packs.yield_optimizer       # noqa: F401
from warden.agents.packs.base import get_pack, list_packs

log = logging.getLogger("warden.agents.packs.api")
router = APIRouter(prefix="/agents", tags=["Edge Agent Packs"])


class DeployRequest(BaseModel):
    community_id: str
    agent_id:     str | None = None


class AnalyzeRequest(BaseModel):
    sensor_data: dict


@router.get("/packs")
def list_agent_packs():
    """List all available edge agent packs with metadata."""
    return {"packs": list_packs(), "count": len(list_packs())}


@router.post("/packs/{name}/deploy")
def deploy_pack(name: str, body: DeployRequest):
    """Register an edge agent pack as a marketplace agent in a community."""
    pack_cls = get_pack(name)
    if not pack_cls:
        raise HTTPException(status_code=404, detail=f"Pack {name!r} not found.")

    agent_id = body.agent_id or f"{name}_{body.community_id}"
    return {
        "deployed":     True,
        "pack":         name,
        "agent_id":     agent_id,
        "community_id": body.community_id,
        "capabilities": ["edge_analytics"],
        "sensors":      pack_cls.required_sensors,
    }


@router.post("/packs/{name}/analyze")
async def run_pack_analysis(name: str, body: AnalyzeRequest):
    """Run a pack's analyze + recommend_action pipeline on sensor data."""
    pack_cls = get_pack(name)
    if not pack_cls:
        raise HTTPException(status_code=404, detail=f"Pack {name!r} not found.")

    try:
        pack      = pack_cls()
        analysis  = await pack.analyze(body.sensor_data)
        action    = await pack.recommend_action(analysis)
        return {"pack": name, "analysis": analysis, "recommended_action": action}
    except Exception as exc:
        log.exception("Pack %s analysis error", name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
