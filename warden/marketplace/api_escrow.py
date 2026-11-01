"""warden/marketplace/api_escrow.py — Escrow lifecycle endpoints."""
from __future__ import annotations

import contextlib
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from warden.auth_guard import require_api_key
from warden.marketplace.rate_limit import marketplace_rate_limit

log = logging.getLogger("warden.marketplace.api_escrow")

with contextlib.suppress(Exception):
    from warden.metrics import MARKETPLACE_ESCROW_ACTIVE

router = APIRouter(tags=["Marketplace Escrow"], dependencies=[Depends(marketplace_rate_limit)])

# Reads stay open — unauthenticated agent-to-agent lookup is the premise of the
# marketplace, and docs/anonymous-route-audit-2026-07-29.md kept discovery public
# by decision. Writes are a different question: create/fund/deliver/confirm/
# dispute/resolve all name the buyer and seller in the body, so without a key any
# caller could open or advance an escrow between agents it does not control.
# A rate limit was the only router dependency here; it throttles an anonymous
# caller, it does not authenticate one.
_WRITE = [Depends(require_api_key)]


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


@router.post("/escrow", status_code=201, dependencies=_WRITE)
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
    with contextlib.suppress(Exception):
        MARKETPLACE_ESCROW_ACTIVE.inc()
    return escrow.to_dict()


def _require_escrow(svc, escrow_id: str):  # noqa: ANN001, ANN202
    """404 when the escrow doesn't exist — distinct from a 409 state conflict."""
    esc = svc.get_escrow(escrow_id)
    if esc is None:
        raise HTTPException(status_code=404, detail=f"Escrow '{escrow_id}' not found.")
    return esc


class FundRequest(BaseModel):
    """The buyer's EIP-712 consent, when the gateway relays the deposit.

    Get the typed data from ``GET /escrow/{id}/deposit-intent``, sign it with
    the buyer's wallet (``eth_signTypedData_v4``), and send the signature with
    the same ``intent_deadline``. Not needed when the gateway's signer is the
    buyer, or where settlement is not configured.
    """
    buyer_signature: str | None = Field(default=None, max_length=132)
    intent_deadline: int | None = Field(default=None, ge=0, le=2**63 - 1)  # SQLite INTEGER


_INTENT_MAX_SECONDS = 24 * 3600


@router.get("/escrow/{escrow_id}/deposit-intent", dependencies=_WRITE)
async def deposit_intent(
    escrow_id: str,
    valid_seconds: int = Query(default=900, ge=60, le=_INTENT_MAX_SECONDS),
) -> dict:
    """EIP-712 typed data the buyer signs to let the gateway relay its deposit."""
    from warden.marketplace.escrow import EscrowService
    svc = EscrowService()
    _require_escrow(svc, escrow_id)
    try:
        typed = svc.deposit_intent(escrow_id, int(time.time()) + valid_seconds)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"escrow_id": escrow_id, "typed_data": typed}


@router.post("/escrow/{escrow_id}/fund", dependencies=_WRITE)
async def fund_escrow(escrow_id: str, body: FundRequest | None = None) -> dict:
    from warden.marketplace.escrow import EscrowService
    svc = EscrowService()
    _require_escrow(svc, escrow_id)
    if body is not None and body.buyer_signature:
        if body.intent_deadline is None:
            raise HTTPException(status_code=422, detail="intent_deadline is required "
                                "with buyer_signature.")
        if not svc.record_deposit_intent(escrow_id, body.buyer_signature,
                                         body.intent_deadline):
            raise HTTPException(status_code=422, detail="buyer_signature must be a "
                                "65-byte hex signature on a pending escrow.")
    ok = svc.fund_escrow(escrow_id)
    if not ok:
        raise HTTPException(status_code=409, detail="Cannot fund escrow in current state.")
    return {"funded": True, "escrow_id": escrow_id}


@router.post("/escrow/{escrow_id}/deliver", dependencies=_WRITE)
async def deliver_asset(escrow_id: str, body: DeliverRequest) -> dict:
    from warden.marketplace.escrow import EscrowService
    svc = EscrowService()
    _require_escrow(svc, escrow_id)
    ok = svc.deliver_asset(escrow_id, body.asset_hash)
    if not ok:
        raise HTTPException(status_code=409, detail="Cannot deliver in current state.")
    return {"delivered": True, "asset_hash": body.asset_hash}


@router.post("/escrow/{escrow_id}/confirm", dependencies=_WRITE)
async def confirm_receipt(escrow_id: str) -> dict:
    from warden.marketplace.escrow import EscrowService
    svc = EscrowService()
    _require_escrow(svc, escrow_id)
    ok = svc.confirm_receipt(escrow_id)
    if not ok:
        raise HTTPException(status_code=409, detail="Cannot confirm in current state.")
    with contextlib.suppress(Exception):
        MARKETPLACE_ESCROW_ACTIVE.dec()
    return {"confirmed": True, "escrow_id": escrow_id}


@router.post("/escrow/{escrow_id}/dispute", dependencies=_WRITE)
async def raise_dispute(escrow_id: str, body: DisputeRequest) -> dict:
    from warden.marketplace.escrow import EscrowService
    svc = EscrowService()
    _require_escrow(svc, escrow_id)
    ok = svc.raise_dispute(escrow_id, body.reason)
    if not ok:
        raise HTTPException(status_code=409, detail="Cannot raise dispute in current state.")
    return {"disputed": True, "reason": body.reason}


@router.post("/escrow/{escrow_id}/resolve", dependencies=_WRITE)
async def resolve_dispute(escrow_id: str, body: dict) -> dict:
    from warden.marketplace.escrow import EscrowService
    svc = EscrowService()
    _require_escrow(svc, escrow_id)
    release_to_buyer = bool(body.get("release_to_buyer", True))
    ok = svc.resolve_dispute(escrow_id, release_to_buyer)
    if not ok:
        raise HTTPException(status_code=409, detail="Cannot resolve dispute in current state.")
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
