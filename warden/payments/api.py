"""
warden/payments/api.py
────────────────────────
FastAPI router for USDC stablecoin payments.

Endpoints:
  POST /payments/usdc/intent       — create USDC payment intent
  GET  /payments/usdc/intent/{id}  — check status / verify
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from warden.auth_guard import require_api_key
from warden.payments.usdc import get_usdc_service

log = logging.getLogger("warden.payments.api")
router = APIRouter(prefix="/payments", tags=["Payments"])

# The intent names merchant_wallet and amount in the body, so an unauthenticated
# POST created a USDC payment intent paying an address of the caller's choosing.
# The status read stays open — it discloses only an intent the caller must already
# know the id of.
_WRITE = [Depends(require_api_key)]


# ── Models ────────────────────────────────────────────────────────────────────

class IntentRequest(BaseModel):
    amount_usd:      float
    merchant_wallet: str
    chain:           str = "polygon_amoy"


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/usdc/intent", status_code=201, dependencies=_WRITE)
def create_usdc_intent(body: IntentRequest):
    """Create a USDC payment intent for a marketplace transaction."""
    try:
        svc    = get_usdc_service(chain=body.chain)
        intent = svc.create_payment_intent(body.amount_usd, body.merchant_wallet)
        return intent.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/usdc/intent/{intent_id}")
def get_usdc_intent(intent_id: str):
    """Check status of a USDC payment intent (auto-confirms in simulation mode)."""
    svc    = get_usdc_service()
    intent = svc.verify_payment(intent_id)
    if intent is None:
        raise HTTPException(status_code=404, detail=f"Intent {intent_id!r} not found.")
    return intent.to_dict()
