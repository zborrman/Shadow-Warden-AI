"""
GSAM REST API.

This slice exposes only the Hermes JIT credential lease endpoints. The read
surface (`/gsam/heatmap`, `/gsam/agents/{id}/stats`, `/gsam/compliance/score`)
is added in a later slice once the rollup/drift downstream is built.

Routes
──────
  POST   /gsam/lease               — issue a single-use JIT lease (metadata only)
  POST   /gsam/lease/{id}/redeem   — redeem a lease once → scope-bound capability
  DELETE /gsam/lease/{id}          — revoke an active lease
  GET    /gsam/lease/{id}          — lease metadata (never a credential)

Auth: standard X-API-Key. Leasing is fail-CLOSED: when no signing key can be
resolved the issue endpoint returns HTTP 503.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key
from warden.secret_keys import InsecureKeyError

router = APIRouter(prefix="/gsam", tags=["GSAM"])

AuthDep = Depends(require_api_key)


class LeaseRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, description="Agent the lease is bound to")
    scope: str = Field(..., min_length=1, description="Credential scope, e.g. 'github:repo:read'")
    ttl_s: int | None = Field(None, ge=1, le=86_400, description="Override lease TTL (seconds)")


class RedeemRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, description="Must match the lease's agent_id")


@router.post("/lease")
async def issue(req: LeaseRequest, auth: AuthResult = AuthDep) -> dict:
    from warden.gsam.jit_lease import LeaseError, issue_lease

    try:
        return issue_lease(req.agent_id, auth.tenant_id, req.scope, req.ttl_s)
    except InsecureKeyError as exc:
        raise HTTPException(status_code=503, detail=f"leasing unavailable: {exc}") from exc
    except LeaseError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/lease/{lease_id}/redeem")
async def redeem(lease_id: str, req: RedeemRequest, auth: AuthResult = AuthDep) -> dict:
    from warden.gsam.jit_lease import LeaseError, redeem_lease

    try:
        return redeem_lease(lease_id, req.agent_id)
    except InsecureKeyError as exc:
        raise HTTPException(status_code=503, detail=f"leasing unavailable: {exc}") from exc
    except LeaseError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.delete("/lease/{lease_id}")
async def revoke(lease_id: str, auth: AuthResult = AuthDep) -> dict:
    from warden.gsam.jit_lease import revoke_lease

    return {"lease_id": lease_id, "revoked": revoke_lease(lease_id)}


@router.get("/lease/{lease_id}")
async def get(lease_id: str, auth: AuthResult = AuthDep) -> dict:
    from warden.gsam.jit_lease import get_lease

    meta = get_lease(lease_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="lease not found")
    return meta


# ── Read API (rollup-backed — never ClickHouse) ─────────────────────────────

@router.get("/heatmap")
async def heatmap(hours: int = 24, auth: AuthResult = AuthDep) -> dict:
    from warden.gsam.rollup import read_heatmap

    return read_heatmap(auth.tenant_id, hours=max(1, min(720, hours)))


@router.get("/agents/{agent_id}/stats")
async def agent_stats(agent_id: str, hours: int = 24, auth: AuthResult = AuthDep) -> dict:
    from warden.gsam.quarantine import is_quarantined
    from warden.gsam.rollup import read_agent_stats

    out = read_agent_stats(agent_id, hours=max(1, min(720, hours)))
    out["quarantined"] = is_quarantined(agent_id)
    return out


@router.get("/compliance/score")
async def compliance(hours: int = 168, auth: AuthResult = AuthDep) -> dict:
    from warden.gsam.rollup import compliance_score

    return compliance_score(auth.tenant_id, hours=max(1, min(8760, hours)))
