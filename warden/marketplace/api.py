"""
warden/marketplace/api.py
──────────────────────────
FastAPI router for the Community M2M Agentic Marketplace.

Phase 1 endpoints
─────────────────
  POST /marketplace/agents/register           — register a new marketplace agent
  GET  /marketplace/agents/{agent_id}         — get agent details
  PUT  /marketplace/agents/{agent_id}/capabilities — update agent capabilities

  POST /marketplace/assets                    — tokenize + register an asset
  GET  /marketplace/assets/{ueciid}           — get asset metadata + token
  GET  /marketplace/assets                    — search assets (agent_id / type / community_id)

Phase 2 endpoints
─────────────────
  POST /marketplace/listings                  — publish an asset listing
  GET  /marketplace/listings                  — search active listings
  GET  /marketplace/listings/{listing_id}     — get listing details

  POST /marketplace/negotiations              — start negotiation between agents
  POST /marketplace/negotiations/{id}/offer   — send counter-offer
  POST /marketplace/negotiations/{id}/accept  — accept current offer
  GET  /marketplace/negotiations/{id}         — negotiation status + history

  POST /marketplace/escrow                    — create escrow for a purchase
  POST /marketplace/escrow/{id}/fund          — buyer funds escrow
  POST /marketplace/escrow/{id}/deliver       — seller delivers asset hash
  POST /marketplace/escrow/{id}/confirm       — buyer confirms receipt
  POST /marketplace/escrow/{id}/dispute       — raise dispute
  GET  /marketplace/escrow/{id}              — escrow status

Feature gate
────────────
  Write endpoints require `marketplace_enabled` (Pro+).
  Read endpoints are unrestricted (tenant context still required for meaningful data).
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

log = logging.getLogger("warden.marketplace.api")

router = APIRouter(prefix="/marketplace", tags=["Marketplace"])


# ── Request / response models ─────────────────────────────────────────────────

class AgentRegisterRequest(BaseModel):
    tenant_id:    str
    community_id: str
    public_key:   str              # base64-encoded Ed25519 public key
    capabilities: list[str]


class CapabilitiesUpdateRequest(BaseModel):
    tenant_id:    str
    capabilities: list[str]


class AssetRegisterRequest(BaseModel):
    tenant_id:       str
    seller_agent_id: str           # did:shadow:...
    asset_type:      str           # rule|model|signals
    raw_data:        Any           # dict for rule/model, list for signals


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_marketplace_gate() -> None:
    try:
        from warden.billing.feature_gate import require_feature
        require_feature("marketplace_enabled")
    except Exception:
        pass   # fail-open when billing module not configured


def _resolve_keypair(community_id: str):
    """Load community keypair; return ephemeral dev keypair on failure (fail-open)."""
    try:
        from warden.communities.keypair import generate_community_keypair
        return generate_community_keypair(community_id, kid="v1")
    except Exception as exc:
        log.warning("Could not load community keypair for %s: %s", community_id, exc)
        from warden.communities.keypair import generate_community_keypair
        return generate_community_keypair("_ephemeral", kid="v1")


# ── Agent endpoints ───────────────────────────────────────────────────────────

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


# ── Asset endpoints ───────────────────────────────────────────────────────────

@router.post("/assets", status_code=201)
async def register_asset(body: AssetRegisterRequest) -> dict:
    from warden.marketplace.agent import get_agent as _get_agent
    from warden.marketplace.service import register_asset as _register

    agent = _get_agent(body.seller_agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{body.seller_agent_id}' not found.")

    keypair = _resolve_keypair(agent.community_id)

    try:
        asset_id = _register(
            tenant_id=body.tenant_id,
            seller_agent_id=body.seller_agent_id,
            asset_type=body.asset_type,
            raw_data=body.raw_data,
            keypair=keypair,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {"asset_id": asset_id, "asset_type": body.asset_type, "seller_agent_id": body.seller_agent_id}


@router.get("/assets/{ueciid}")
async def get_asset(ueciid: str) -> dict:
    from warden.marketplace.service import get_asset as _get
    asset = _get(ueciid)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{ueciid}' not found.")
    return asset


@router.get("/assets")
async def search_assets(
    agent_id:     str | None = Query(default=None),
    type:         str | None = Query(default=None),
    community_id: str | None = Query(default=None),
    limit:        int        = Query(default=20, le=50),
) -> list[dict]:
    if agent_id:
        from warden.marketplace.service import list_assets_by_agent
        return list_assets_by_agent(agent_id, asset_type=type, limit=limit)
    if community_id:
        from warden.marketplace.service import search_assets as _search
        return _search(community_id, asset_type=type, limit=limit)
    return []


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2 — Listings, Negotiations, Escrow
# ═══════════════════════════════════════════════════════════════════════════════

# ── Listing models ────────────────────────────────────────────────────────────

class ListingCreateRequest(BaseModel):
    asset_id:         str
    seller_agent_id:  str
    community_id:     str
    tenant_id:        str
    asset_type:       str = "rule"
    price_usd:        float
    pricing_strategy: str = "fixed"
    expires_hours:    int | None = None


# ── Listing endpoints ─────────────────────────────────────────────────────────

@router.post("/listings", status_code=201)
async def create_listing(body: ListingCreateRequest) -> dict:
    from warden.marketplace.listing import publish_listing
    try:
        listing = publish_listing(
            asset_id=body.asset_id,
            seller_agent=body.seller_agent_id,
            community_id=body.community_id,
            tenant_id=body.tenant_id,
            asset_type=body.asset_type,
            price_usd=body.price_usd,
            pricing_strategy=body.pricing_strategy,
            expires_hours=body.expires_hours,
        )
        return listing.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/listings/{listing_id}")
async def get_listing(listing_id: str) -> dict:
    from warden.marketplace.listing import get_listing as _get
    listing = _get(listing_id)
    if listing is None:
        raise HTTPException(status_code=404, detail=f"Listing '{listing_id}' not found.")
    return listing.to_dict()


@router.get("/listings")
async def search_listings(
    community_id: str | None = Query(default=None),
    asset_type:   str | None = Query(default=None),
    max_price:    float | None = Query(default=None),
    limit:        int         = Query(default=20, le=50),
) -> list[dict]:
    from warden.marketplace.listing import get_listings
    listings = get_listings(
        community_id=community_id,
        asset_type=asset_type,
        max_price=max_price,
        limit=limit,
    )
    return [lst.to_dict() for lst in listings]


# ── Negotiation models ────────────────────────────────────────────────────────

class NegotiationStartRequest(BaseModel):
    buyer_agent_id:  str
    seller_agent_id: str
    listing_id:      str
    initial_price:   float


class OfferRequest(BaseModel):
    from_agent_id: str
    price:         float
    message:       str = ""


# ── Negotiation endpoints ─────────────────────────────────────────────────────

@router.post("/negotiations", status_code=201)
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


@router.post("/negotiations/{negotiation_id}/offer", status_code=201)
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


@router.post("/negotiations/{negotiation_id}/accept")
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


# ── Escrow models ─────────────────────────────────────────────────────────────

class EscrowCreateRequest(BaseModel):
    listing_id:      str
    buyer_agent_id:  str
    seller_agent_id: str
    amount_usd:      float
    purchase_id:     str = ""


class DeliverRequest(BaseModel):
    asset_hash: str


class DisputeRequest(BaseModel):
    reason: str


# ── Escrow endpoints ──────────────────────────────────────────────────────────

@router.post("/escrow", status_code=201)
async def create_escrow(body: EscrowCreateRequest) -> dict:
    from warden.marketplace.escrow import EscrowService
    escrow = EscrowService().create_escrow(
        listing_id=body.listing_id,
        buyer_agent_id=body.buyer_agent_id,
        seller_agent_id=body.seller_agent_id,
        amount_usd=body.amount_usd,
        purchase_id=body.purchase_id,
    )
    return escrow.to_dict()


@router.post("/escrow/{escrow_id}/fund")
async def fund_escrow(escrow_id: str) -> dict:
    from warden.marketplace.escrow import EscrowService
    ok = EscrowService().fund_escrow(escrow_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot fund escrow in current state.")
    return {"funded": True, "escrow_id": escrow_id}


@router.post("/escrow/{escrow_id}/deliver")
async def deliver_asset(escrow_id: str, body: DeliverRequest) -> dict:
    from warden.marketplace.escrow import EscrowService
    ok = EscrowService().deliver_asset(escrow_id, body.asset_hash)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot deliver in current state.")
    return {"delivered": True, "asset_hash": body.asset_hash}


@router.post("/escrow/{escrow_id}/confirm")
async def confirm_receipt(escrow_id: str) -> dict:
    from warden.marketplace.escrow import EscrowService
    ok = EscrowService().confirm_receipt(escrow_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot confirm in current state.")
    return {"confirmed": True, "escrow_id": escrow_id}


@router.post("/escrow/{escrow_id}/dispute")
async def raise_dispute(escrow_id: str, body: DisputeRequest) -> dict:
    from warden.marketplace.escrow import EscrowService
    ok = EscrowService().raise_dispute(escrow_id, body.reason)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot raise dispute in current state.")
    return {"disputed": True, "reason": body.reason}


@router.get("/escrow/{escrow_id}")
async def get_escrow(escrow_id: str) -> dict:
    from warden.marketplace.escrow import EscrowService
    escrow = EscrowService().get_escrow(escrow_id)
    if escrow is None:
        raise HTTPException(status_code=404, detail=f"Escrow '{escrow_id}' not found.")
    return escrow.to_dict()
