"""
warden/web3/api.py
FastAPI router for on-chain mandate management.
Prefix: /web3/mandates
Tier:   Pro+ (agentic_commerce_enabled)
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/web3/mandates", tags=["Web3 Commerce"])
_Gate  = require_feature("agentic_commerce_enabled")


class Web3MandateRequest(BaseModel):
    mandate_id: str
    tenant_id:  str
    max_amount_usd: float = Field(..., gt=0)
    valid_days: int = 30
    allowed_merchants: list[str] = Field(default_factory=list)


class Web3PaymentRequest(BaseModel):
    amount_usd: float = Field(..., gt=0)
    merchant:   str


@router.post("/create", summary="Create on-chain mandate", dependencies=[_Gate])
async def create_onchain_mandate(body: Web3MandateRequest) -> dict:
    from warden.web3.mandate_contract import MandateContract
    from warden.web3.ipfs_storage import IPFSStorage

    ipfs = IPFSStorage()
    cid = ipfs.store_mandate({
        "mandate_id":  body.mandate_id,
        "tenant_id":   body.tenant_id,
        "max_amount":  body.max_amount_usd,
        "created_at":  datetime.now(UTC).isoformat(),
        "merchants":   body.allowed_merchants,
    })

    valid_until_ts = int((datetime.now(UTC) + timedelta(days=body.valid_days)).timestamp())
    result = MandateContract().create(
        mandate_uuid=body.mandate_id,
        tenant_id=body.tenant_id,
        max_amount_cents=int(body.max_amount_usd * 100),
        valid_until_ts=valid_until_ts,
        merchants=body.allowed_merchants,
        ipfs_hash=cid,
    )
    return {"ipfs_cid": cid, "chain": result}


@router.get("/{mandate_id}", summary="Read on-chain mandate status", dependencies=[_Gate])
async def get_onchain_mandate(mandate_id: str) -> dict:
    from warden.web3.mandate_contract import MandateContract
    data = MandateContract().get(mandate_id)
    if not data:
        raise HTTPException(status_code=404, detail="Mandate not found on chain")
    return data


@router.post("/{mandate_id}/execute", summary="Execute payment on-chain", dependencies=[_Gate])
async def execute_onchain_payment(mandate_id: str, body: Web3PaymentRequest) -> dict:
    from warden.web3.mandate_contract import MandateContract
    result = MandateContract().execute_payment(
        mandate_uuid=mandate_id,
        amount_cents=int(body.amount_usd * 100),
        merchant=body.merchant,
    )
    if not result.get("success"):
        raise HTTPException(status_code=402, detail=result)
    return result


@router.delete("/{mandate_id}", summary="Revoke on-chain mandate", dependencies=[_Gate])
async def revoke_onchain_mandate(mandate_id: str) -> dict:
    from warden.web3.mandate_contract import MandateContract
    result = MandateContract().revoke(mandate_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result)
    return {"revoked": True, "mandate_id": mandate_id}
