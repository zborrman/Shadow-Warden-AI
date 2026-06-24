"""warden/marketplace/api_agents.py — Agent DID registration endpoints."""
from __future__ import annotations

import contextlib
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from warden.marketplace.rate_limit import marketplace_rate_limit

log = logging.getLogger("warden.marketplace.api_agents")

with contextlib.suppress(Exception):
    from warden.metrics import MARKETPLACE_AGENTS_ACTIVE

router = APIRouter(tags=["Marketplace Agents"], dependencies=[Depends(marketplace_rate_limit)])


class AgentRegisterRequest(BaseModel):
    tenant_id:    str
    community_id: str
    public_key:   str
    capabilities: list[str]


class CapabilitiesUpdateRequest(BaseModel):
    tenant_id:    str
    capabilities: list[str]


class AgentPatchRequest(BaseModel):
    name:         str | None = None
    budget_limit: float | None = None


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
    from warden.marketplace.agent import pubkey_to_agent_id
    from warden.marketplace.agent import register_agent as _register

    # Federation deny list — check if the agent DID is flagged across peered communities
    try:
        from warden.communities.federation import check_threat_hash
        candidate_id = pubkey_to_agent_id(body.public_key)
        verdict = check_threat_hash(body.community_id, candidate_id)
        if verdict and verdict.verdict in ("HIGH", "BLOCK"):
            log.warning(
                "register_agent: federated deny list hit agent=%s community=%s",
                candidate_id, body.community_id,
            )
            raise HTTPException(
                status_code=403,
                detail="Agent DID is on the federated deny list for this community.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        log.debug("federation deny-list check failed (fail-open): %s", exc)

    try:
        agent = _register(
            tenant_id=body.tenant_id,
            community_id=body.community_id,
            public_key_b64=body.public_key,
            capabilities=body.capabilities,
        )
        with contextlib.suppress(Exception):
            MARKETPLACE_AGENTS_ACTIVE.inc()
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
    from warden.marketplace.sybil_guard import SybilGuard
    from warden.marketplace.trust_graph import TrustGraph

    tg = TrustGraph()
    with contextlib.suppress(Exception):
        tg.build_graph()

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


@router.patch("/agents/{agent_id}", status_code=200)
async def patch_agent(agent_id: str, body: AgentPatchRequest) -> dict:
    """Update agent name and/or monthly budget limit."""
    from warden.marketplace.agent import update_agent as _update
    updated = _update(agent_id, name=body.name, budget_limit=body.budget_limit)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return {"updated": True, "agent_id": agent_id}


@router.delete("/agents/{agent_id}", status_code=200)
async def deactivate_agent_endpoint(agent_id: str) -> dict:
    """Soft-delete an agent (status → inactive). Preserves audit trail."""
    from warden.marketplace.agent import deactivate_agent as _deactivate
    deactivated = _deactivate(agent_id)
    if not deactivated:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return {"deactivated": True, "agent_id": agent_id}
