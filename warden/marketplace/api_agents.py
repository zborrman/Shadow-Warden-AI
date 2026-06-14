"""warden/marketplace/api_agents.py — Agent DID registration endpoints."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

log = logging.getLogger("warden.marketplace.api_agents")

try:
    from warden.metrics import MARKETPLACE_AGENTS_ACTIVE
except Exception:
    pass

router = APIRouter(tags=["Marketplace Agents"])


class AgentRegisterRequest(BaseModel):
    tenant_id:    str
    community_id: str
    public_key:   str
    capabilities: list[str]


class CapabilitiesUpdateRequest(BaseModel):
    tenant_id:    str
    capabilities: list[str]


@router.get("/agents")
async def list_agents(
    tenant_id:    str | None = Query(default=None),
    community_id: str | None = Query(default=None),
    limit:        int        = Query(default=50, le=100),
) -> list[dict]:
    from warden.marketplace.agent import list_agents as _list
    return [a.to_dict() for a in _list(tenant_id=tenant_id, community_id=community_id, limit=limit)]


@router.post("/agents/register", status_code=201)
async def register_agent(body: AgentRegisterRequest) -> dict:
    from warden.marketplace.agent import register_agent as _register
    try:
        agent = _register(
            tenant_id=body.tenant_id,
            community_id=body.community_id,
            public_key_b64=body.public_key,
            capabilities=body.capabilities,
        )
        try:
            MARKETPLACE_AGENTS_ACTIVE.inc()
        except Exception:
            pass
        return agent.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str) -> dict:
    from warden.marketplace.agent import get_agent as _get
    agent = _get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return agent.to_dict()


@router.put("/agents/{agent_id}/capabilities")
async def update_capabilities(agent_id: str, body: CapabilitiesUpdateRequest) -> dict:
    from warden.marketplace.agent import update_capabilities as _update
    try:
        updated = _update(agent_id, body.tenant_id, body.capabilities)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Agent not found or wrong tenant.")
    return {"updated": True, "agent_id": agent_id, "capabilities": body.capabilities}


@router.get("/agents/{agent_id}/trust")
async def get_agent_trust(agent_id: str) -> dict:
    """TrustRank score, Sybil flag status, and top-5 transitive peers for *agent_id*."""
    from warden.marketplace.trust_graph import TrustGraph
    from warden.marketplace.sybil_guard import SybilGuard

    tg = TrustGraph()
    try:
        tg.build_graph()
    except Exception:
        pass

    sg = SybilGuard()

    trust_score  = tg.get_trust_score(agent_id)
    sybil_flag   = sg.is_flagged(agent_id)
    sybil_reason = sg.get_flag_reason(agent_id)

    # Top-5 peers excluding self, sorted by transitive trust
    top_all = tg.top_agents(n=20)
    peers = []
    for entry in top_all:
        peer_id = entry["agent_id"]
        if peer_id == agent_id:
            continue
        tt = tg.get_transitive_trust(agent_id, peer_id)
        peers.append({"agent_id": peer_id, "trust_rank": entry["trust_rank"], "transitive_trust": round(tt, 4)})
        if len(peers) >= 5:
            break

    return {
        "agent_id":       agent_id,
        "trust_score":    round(trust_score, 4),
        "trust_rank":     round(trust_score, 4),
        "sybil_flag":     sybil_flag,
        "sybil_reason":   sybil_reason,
        "transitive_peers": peers,
    }
