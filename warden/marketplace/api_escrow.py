"""warden/marketplace/api_escrow.py — Escrow lifecycle endpoints."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

log = logging.getLogger("warden.marketplace.api_escrow")

try:
    from warden.metrics import MARKETPLACE_ESCROW_ACTIVE
except Exception:
    pass

router = APIRouter(tags=["Marketplace Escrow"])


class EscrowCreateRequest(BaseModel):
    listing_id:      str
    buyer_agent_id:  str
    seller_agent_id: str
    amount_usd:      float
    purchase_id:     str = ""
    chain:           str = "sepolia"


class DeliverRequest(BaseModel):
    asset_hash: str


class DisputeRequest(BaseModel):
    reason: str


@router.post("/escrow", status_code=201)
async def create_escrow(body: EscrowCreateRequest) -> dict:
    from warden.marketplace.escrow import EscrowDeploymentError, EscrowService
    try:
        escrow = EscrowService().create_escrow(
            listing_id=body.listing_id,
            buyer_agent_id=body.buyer_agent_id,
            seller_agent_id=body.seller_agent_id,
            amount_usd=body.amount_usd,
            purchase_id=body.purchase_id,
            chain=body.chain,
        )
    except EscrowDeploymentError as exc:
        raise HTTPException(
            status_code=502,
            detail={"message": "Blockchain network unavailable", "detail": str(exc)},
        ) from exc
    try:
        MARKETPLACE_ESCROW_ACTIVE.inc()
    except Exception:
        pass
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
    try:
        MARKETPLACE_ESCROW_ACTIVE.dec()
    except Exception:
        pass
    return {"confirmed": True, "escrow_id": escrow_id}


@router.post("/escrow/{escrow_id}/dispute")
async def raise_dispute(escrow_id: str, body: DisputeRequest) -> dict:
    from warden.marketplace.escrow import EscrowService
    ok = EscrowService().raise_dispute(escrow_id, body.reason)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot raise dispute in current state.")
    return {"disputed": True, "reason": body.reason}


@router.post("/escrow/{escrow_id}/resolve")
async def resolve_dispute(escrow_id: str, body: dict) -> dict:
    from warden.marketplace.escrow import EscrowService
    release_to_buyer = bool(body.get("release_to_buyer", True))
    ok = EscrowService().resolve_dispute(escrow_id, release_to_buyer)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot resolve dispute in current state.")
    verdict = "resolved_buyer" if release_to_buyer else "resolved_seller"
    return {"resolved": True, "verdict": verdict}


@router.get("/escrow/{escrow_id}")
async def get_escrow(escrow_id: str) -> dict:
    from warden.marketplace.escrow import EscrowService
    escrow = EscrowService().get_escrow(escrow_id)
    if escrow is None:
        raise HTTPException(status_code=404, detail=f"Escrow '{escrow_id}' not found.")
    return escrow.to_dict()


@router.get("/escrows")
async def list_escrows(
    agent_id: str | None = Query(default=None),
    role:     str        = Query(default="any"),
    status:   str | None = Query(default=None),
    limit:    int        = Query(default=50, le=100),
) -> list[dict]:
    from warden.marketplace.escrow import EscrowService
    svc = EscrowService()
    if agent_id:
        return [e.to_dict() for e in svc.list_escrows(agent_id, role=role, limit=limit)]
    return [e.to_dict() for e in svc.list_all_escrows(status=status, limit=limit)]
