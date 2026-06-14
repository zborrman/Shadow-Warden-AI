"""
warden/marketplace/api_governance.py
──────────────────────────────────────
FastAPI router for Community DAO Governance.

Endpoints:
  POST /marketplace/proposals                   — create proposal
  GET  /marketplace/proposals                   — list proposals for a community
  GET  /marketplace/proposals/{proposal_id}     — get single proposal + tally
  POST /marketplace/proposals/{proposal_id}/vote    — cast a vote
  POST /marketplace/proposals/{proposal_id}/execute — execute a passed proposal
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from warden.marketplace.governance import GovernanceService, PROPOSAL_TYPES

log = logging.getLogger("warden.marketplace.api_governance")

router = APIRouter(prefix="/marketplace", tags=["Marketplace Governance"])
_svc = GovernanceService()


# ── Request / Response models ─────────────────────────────────────────────────

class ProposalCreate(BaseModel):
    community_id:  str
    proposer_id:   str
    proposal_type: str
    target_id:     str
    title:         str
    description:   str = ""
    options:       Optional[list[str]] = None


class VoteCast(BaseModel):
    voter_id: str
    choice:   int


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/proposals", status_code=201)
async def create_proposal(body: ProposalCreate):
    if body.proposal_type not in PROPOSAL_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"proposal_type must be one of {sorted(PROPOSAL_TYPES)}",
        )
    try:
        proposal = _svc.create_proposal(
            community_id=body.community_id,
            proposer_id=body.proposer_id,
            proposal_type=body.proposal_type,
            target_id=body.target_id,
            title=body.title,
            description=body.description,
            options=body.options,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return proposal.to_dict()


@router.get("/proposals")
async def list_proposals(
    community_id: str = Query(...),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
):
    proposals = _svc.get_proposals(
        community_id=community_id, status_filter=status, limit=limit
    )
    return [p.to_dict() for p in proposals]


@router.get("/proposals/{proposal_id}")
async def get_proposal(proposal_id: str):
    prop = _svc.get_proposal(proposal_id)
    if prop is None:
        raise HTTPException(status_code=404, detail="Proposal not found.")
    tally = _svc.tally_votes(proposal_id)
    votes = [v.to_dict() for v in _svc.get_votes(proposal_id)]
    return {**prop.to_dict(), "tally": tally, "votes": votes}


@router.post("/proposals/{proposal_id}/vote", status_code=201)
async def cast_vote(proposal_id: str, body: VoteCast):
    try:
        vote = _svc.cast_vote(
            proposal_id=proposal_id,
            voter_id=body.voter_id,
            choice=body.choice,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return vote.to_dict()


@router.post("/proposals/{proposal_id}/execute")
async def execute_proposal(proposal_id: str):
    prop = _svc.get_proposal(proposal_id)
    if prop is None:
        raise HTTPException(status_code=404, detail="Proposal not found.")

    # Auto-finalize tally before executing
    tally = _svc.finalize_tally(proposal_id)
    prop = _svc.get_proposal(proposal_id)
    if prop is None or prop.status != "passed":
        raise HTTPException(
            status_code=409,
            detail=f"Proposal cannot be executed (status={prop.status if prop else 'unknown'}, "
                   f"tally={tally.get('status')}).",
        )
    try:
        result = _svc.execute_proposal(proposal_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return result
