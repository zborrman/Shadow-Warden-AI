"""
SAC preflight wallet REST API — two-phase (reserve → commit) billing.

Routes
──────
  GET    /wallet               — current wallet (balance / hold / net)
  POST   /wallet/deposit       — fund the wallet (admin: X-Admin-Key)
  POST   /wallet/reserve       — hold an estimate → hold_id (402 if insufficient)
  POST   /wallet/commit        — charge actual, release remainder
  POST   /wallet/release       — release a hold without charging

Auth: standard X-API-Key (tenant scoping); deposit additionally requires the
admin key. Reserve/commit/release are the two-phase mechanics used by agent-run
gating; every mutation is written to the tenant billing audit chain.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key

router = APIRouter(prefix="/wallet", tags=["SAC Wallet"])

AuthDep = Depends(require_api_key)


def _require_admin(x_admin_key: str | None) -> None:
    admin_key = os.getenv("ADMIN_KEY", "")
    if not admin_key or x_admin_key != admin_key:
        raise HTTPException(status_code=403, detail="X-Admin-Key required.")


class DepositRequest(BaseModel):
    amount_usd: float = Field(..., gt=0, le=1_000_000, description="Funds to add (USD)")


class ReserveRequest(BaseModel):
    est_cost_usd: float = Field(..., gt=0, le=1_000_000, description="Estimate to hold (USD)")
    reason: str = Field("", max_length=200)
    agent_id: str = Field("", max_length=128)


class CommitRequest(BaseModel):
    hold_id: str = Field(..., min_length=1)
    actual_cost_usd: float = Field(..., ge=0, le=1_000_000, description="Actual cost (USD)")
    agent_id: str = Field("", max_length=128)


class ReleaseRequest(BaseModel):
    hold_id: str = Field(..., min_length=1)
    reason: str = Field("", max_length=200)


@router.get("")
async def wallet(auth: AuthResult = AuthDep) -> dict:
    from warden.sac.preflight import get_wallet

    return get_wallet(auth.tenant_id)


@router.post("/deposit")
async def deposit(
    req: DepositRequest,
    auth: AuthResult = AuthDep,
    x_admin_key: str | None = Header(default=None),
) -> dict:
    _require_admin(x_admin_key)
    from warden.sac.preflight import deposit as _deposit

    return _deposit(auth.tenant_id, req.amount_usd)


@router.post("/reserve")
async def reserve(req: ReserveRequest, auth: AuthResult = AuthDep) -> dict:
    from warden.sac.preflight import InsufficientFundsError
    from warden.sac.preflight import reserve as _reserve

    try:
        hold_id = _reserve(auth.tenant_id, req.est_cost_usd, req.reason, req.agent_id)
    except InsufficientFundsError as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc
    return {"hold_id": hold_id, "reserved_usd": req.est_cost_usd}


@router.post("/commit")
async def commit(req: CommitRequest, auth: AuthResult = AuthDep) -> dict:
    from warden.sac.preflight import HoldError
    from warden.sac.preflight import commit as _commit

    try:
        return _commit(
            req.hold_id, req.actual_cost_usd, req.agent_id, expected_tenant_id=auth.tenant_id
        )
    except HoldError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/release")
async def release(req: ReleaseRequest, auth: AuthResult = AuthDep) -> dict:
    from warden.sac.preflight import HoldError
    from warden.sac.preflight import release as _release

    try:
        return _release(req.hold_id, req.reason, expected_tenant_id=auth.tenant_id)
    except HoldError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
