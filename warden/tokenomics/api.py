"""
warden/tokenomics/api.py
──────────────────────────
FastAPI router for Warden Agent Token (WAT) tokenomics.

Endpoints:
  POST /tokenomics/mint                     — admin: mint WAT
  GET  /tokenomics/balance/{agent_id}       — query balance
  POST /tokenomics/listings/outcome         — create outcome-based listing
  GET  /tokenomics/listings/outcome         — list outcome listings
  POST /tokenomics/listings/{id}/settle     — settle outcome (oracle/admin)
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from warden.admin_guard import require_admin_key
from warden.auth_guard import require_api_key
from warden.tokenomics.agent_token import get_agent_token
from warden.tokenomics.outcome_pricing import OutcomePricingService

log = logging.getLogger("warden.tokenomics.api")
# Router-level authentication (anonymous-route audit, 2026-07-29).
#
# Every route in this module was reachable without credentials in production.
# There is no global auth middleware in warden/main.py — only attach_request_id
# and security_headers — so an absent dependency means genuinely no auth.
#
# Marketplace reputation endpoints (agent trust / readiness / protocol schema)
# are deliberately left open: unauthenticated discovery is the premise of the
# agentic marketplace. These are not that — they return tenant- and
# agent-scoped state. See docs/anonymous-route-audit-2026-07-29.md.
router = APIRouter(prefix="/tokenomics", tags=["Tokenomics"], dependencies=[Depends(require_api_key)])

_svc = OutcomePricingService()


# ── Models ────────────────────────────────────────────────────────────────────

class MintRequest(BaseModel):
    agent_id: str
    amount:   float


class OutcomeListingCreate(BaseModel):
    community_id:    str
    seller_agent_id: str
    base_price_usd:  float
    kpi_definition:  dict
    target_value:    float
    oracle_address:  str = ""


class SettleRequest(BaseModel):
    buyer_agent_id: str
    achieved_value: float


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/mint")
def mint_tokens(body: MintRequest, request: Request):
    """Admin — mint WAT to an agent address."""
    key = request.headers.get("X-Admin-Key", "")
    # SR-9: previously skipped the check entirely on an unset ADMIN_KEY, which
    # was also snapshotted at import.
    require_admin_key(key)
    try:
        result = get_agent_token().mint(body.agent_id, body.amount)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/balance/{agent_id}")
def token_balance(agent_id: str):
    """Return current WAT balance for an agent."""
    try:
        balance = get_agent_token().balance_of(agent_id)
        return {"agent_id": agent_id, "balance_wat": balance}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/listings/outcome", status_code=201)
def create_outcome_listing(body: OutcomeListingCreate):
    """Create an outcome-based listing with KPI-gated settlement."""
    try:
        listing_id = _svc.create_listing(
            community_id=body.community_id,
            seller_agent_id=body.seller_agent_id,
            base_price_usd=body.base_price_usd,
            kpi_definition=body.kpi_definition,
            target_value=body.target_value,
            oracle_address=body.oracle_address,
        )
        return {"listing_id": listing_id, "status": "open"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/listings/outcome")
def list_outcome_listings(community_id: str = Query(""), limit: int = Query(50)):
    """List outcome-based listings."""
    return {"listings": _svc.list_listings(community_id=community_id, limit=limit)}


@router.post("/listings/{listing_id}/settle")
def settle_outcome(listing_id: str, body: SettleRequest):
    """Settle an outcome listing after KPI achievement is reported."""
    try:
        result = _svc.settle_outcome(
            listing_id=listing_id,
            buyer_agent_id=body.buyer_agent_id,
            achieved_value=body.achieved_value,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
