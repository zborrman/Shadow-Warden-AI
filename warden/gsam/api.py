"""
GSAM REST API.

Routes
──────
  POST   /gsam/lease               — issue a single-use JIT lease (metadata only)
  POST   /gsam/lease/{id}/redeem   — redeem a lease once → scope-bound capability
  DELETE /gsam/lease/{id}          — revoke an active lease
  GET    /gsam/lease/{id}          — lease metadata (never a credential)
  GET    /gsam/heatmap             — rollup read surface (never ClickHouse directly)
  GET    /gsam/agents/{id}/stats   — per-agent rollup stats
  GET    /gsam/compliance/score    — rollup-derived compliance score
  GET    /gsam/health              — ingest health (see below)

Auth: standard X-API-Key. Leasing is fail-CLOSED: when no signing key can be
resolved the issue endpoint returns HTTP 503.

No endpoint here bypasses a guard. ``/gsam/health`` is purely an *observer*: the
collector degrades gracefully when ClickHouse is unreachable (it spools observations
to NDJSON and replays them on recovery, and counts the degradation), so this route
exposes the spool backlog and reachability that make that state visible instead of
silent. The degradation itself is counted at the collector, not here.
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


@router.get("/health")
async def health(auth: AuthResult = AuthDep) -> dict:
    """
    GSAM ingest health — the operator signal for the ClickHouse write path.

    The collector never blocks a request when ClickHouse is down: it spools
    observations to NDJSON and replays them on recovery. That is correct, but it
    means a broken OLAP store degrades *quietly*. This endpoint surfaces the signals
    that distinguish "healthy and draining" from "quietly spooling forever":

      clickhouse_enabled   — GSAM_CLICKHOUSE_ENABLED
      clickhouse_reachable — live ping
      spool_bytes          — backlog on disk; grows while ClickHouse is unreachable
      queue_depth/dropped  — in-memory backpressure

    ``degraded`` is True when ClickHouse is enabled but unreachable, when the spool
    has a backlog, or when observations were dropped — the condition worth alerting on.
    """
    from warden.gsam.collector import stats

    snap = stats()
    snap["degraded"] = bool(
        (snap.get("clickhouse_enabled") and not snap.get("clickhouse_reachable"))
        or snap.get("spool_bytes", 0) > 0
        or snap.get("dropped", 0) > 0
    )
    return snap
