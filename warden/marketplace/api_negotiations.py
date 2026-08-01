"""warden/marketplace/api_negotiations.py — Agent-to-agent negotiation endpoints."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from warden.auth_guard import require_api_key
from warden.marketplace.rate_limit import marketplace_rate_limit

log = logging.getLogger("warden.marketplace.api_negotiations")

router = APIRouter(tags=["Marketplace Negotiations"], dependencies=[Depends(marketplace_rate_limit)])

# MP-1a: negotiation writes move money-adjacent state (a price agreement that
# clearing later settles) and were reachable with no credential at all —
# `marketplace_rate_limit` throttles, it does not identify. Same shape as
# api_listings.py's `_WRITE`.
#
# This proves *a tenant*, not *which agent* — MP-1b adds the Ed25519 offer
# signature that binds `from_agent_id` to the caller. Both are required; see
# rules #23/#24 in warden/marketplace/CLAUDE.md.
_WRITE = [Depends(require_api_key)]


class NegotiationStartRequest(BaseModel):
    buyer_agent_id:  str
    seller_agent_id: str
    listing_id:      str
    initial_price:   float


class OfferRequest(BaseModel):
    from_agent_id: str
    price:         float
    message:       str = ""


@router.post("/negotiations", status_code=201, dependencies=_WRITE)
async def start_negotiation(body: NegotiationStartRequest) -> dict:
    from warden.marketplace.listing import get_listing as _get_listing
    from warden.marketplace.negotiation import NegotiationEngine
    listing = _get_listing(body.listing_id)
    if listing is None:
        raise HTTPException(status_code=404, detail=f"Listing '{body.listing_id}' not found.")
    neg = NegotiationEngine().start_negotiation(
        buyer_agent_id=body.buyer_agent_id,
        seller_agent_id=body.seller_agent_id,
        listing_id=body.listing_id,
        initial_price=body.initial_price,
        asset_ueciid=listing.asset_id,
    )
    return neg.to_dict()


@router.post("/negotiations/{negotiation_id}/offer", status_code=201, dependencies=_WRITE)
async def send_offer(negotiation_id: str, body: OfferRequest) -> dict:
    from warden.marketplace.negotiation import NegotiationEngine
    try:
        offer = NegotiationEngine().send_offer(
            negotiation_id=negotiation_id,
            from_agent_id=body.from_agent_id,
            price=body.price,
            message=body.message,
        )
        return offer.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/negotiations/{negotiation_id}/accept", dependencies=_WRITE)
async def accept_offer(negotiation_id: str, body: OfferRequest) -> dict:
    from warden.marketplace.negotiation import NegotiationEngine
    try:
        offer = NegotiationEngine().accept_offer(
            negotiation_id=negotiation_id,
            from_agent_id=body.from_agent_id,
        )
        return {"accepted": True, "offer": offer.to_dict()}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/negotiations/{negotiation_id}")
async def get_negotiation(negotiation_id: str) -> dict:
    from warden.marketplace.negotiation import NegotiationEngine
    status = NegotiationEngine().get_negotiation_status(negotiation_id)
    if status is None:
        raise HTTPException(status_code=404, detail=f"Negotiation '{negotiation_id}' not found.")
    return status
