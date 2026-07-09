"""
GSAM REST API — /gsam/* (GSAM-01).

PR 2 surface: external-sensor observation ingest + collector health.
Later PRs add heatmap, agent stats, quarantine, JIT leases, compliance score.

Tier gate: gsam_enabled (Pro/Enterprise) via the fail-open pattern used by
warden/api/compliance_report.py. /gsam/health is ungated — ops probe only,
returns queue counters, never observation data.
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from warden.gsam.collector import gsam_emit, stats
from warden.gsam.schema import Observation

try:
    from warden.billing.feature_gate import require_feature as _require_feature
    _GSAM_GATE = [_require_feature("gsam_enabled")]
except Exception:  # noqa: BLE001
    _GSAM_GATE = []

log = logging.getLogger("warden.gsam.api")

router = APIRouter(prefix="/gsam", tags=["gsam"])

# Register the hourly rollup as a collector sink at router-mount time so
# gsam_agent_stats stays fresh even when ClickHouse is disabled (fail-open).
try:
    from warden.gsam.rollup import install as _install_rollup

    _install_rollup()
except Exception:  # noqa: BLE001
    pass


class ExternalObservation(BaseModel):
    """Sensor-submitted observation (SAC adaptation — eBPF/network sensors).

    extra="forbid" rejects any field not listed here, so content-like fields
    (prompt/body/text/...) can never enter the analytics stream via this door.
    """

    model_config = {"extra": "forbid"}

    agent_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = ""
    session_id: str = ""
    trace_id: str = ""
    event: str = "sensor_report"
    payload_kind: str = ""
    latency_ms: float = 0.0
    syscalls_count: int = Field(default=0, ge=0)
    unauthorized_commands_flag: bool = False
    network_calls_count: int = Field(default=0, ge=0)
    resolved_domains: list[str] = Field(default_factory=list)
    scan_verdict: str = "CLEAN"


@router.post(
    "/observations",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=_GSAM_GATE,
)
async def ingest_observation(body: ExternalObservation) -> dict:
    """Accept one metadata-only observation from an external sensor."""
    obs = Observation(
        agent_id=body.agent_id,
        tenant_id=body.tenant_id,
        session_id=body.session_id,
        trace_id=body.trace_id,
        event=body.event[:64],
        payload_kind=body.payload_kind[:64],
        latency_ms=body.latency_ms,
        syscalls_count=body.syscalls_count,
        unauthorized_commands_flag=body.unauthorized_commands_flag,
        network_calls_count=body.network_calls_count,
        resolved_domains=body.resolved_domains,
        scan_verdict=body.scan_verdict,
    )
    gsam_emit(obs.to_row())
    return {"accepted": True, "agent_id": body.agent_id}


@router.get("/health")
async def gsam_health() -> dict:
    """Collector health — queue depth, spool size, ClickHouse reachability."""
    return stats()


def _require_admin(x_admin_key: str | None) -> None:
    admin_key = os.getenv("ADMIN_KEY", "")
    if not admin_key or x_admin_key != admin_key:
        raise HTTPException(status_code=403, detail="X-Admin-Key required.")


@router.get("/quarantine", dependencies=_GSAM_GATE)
async def list_quarantine() -> dict:
    """List agents currently under GSAM drift quarantine."""
    from warden.gsam.quarantine import list_active  # noqa: PLC0415
    active = list_active()
    return {"count": len(active), "agents": active}


@router.post("/quarantine/{agent_id}/release", dependencies=_GSAM_GATE)
async def release_quarantine(
    agent_id: str,
    x_admin_key: str | None = Header(default=None),
) -> dict:
    """Release an agent from quarantine (admin-only, X-Admin-Key)."""
    _require_admin(x_admin_key)
    from warden.gsam.quarantine import release  # noqa: PLC0415
    release(agent_id)
    return {"released": True, "agent_id": agent_id}


# ── JIT credential lease (fail-CLOSED — 503 when no signing secret) ───────────────

class LeaseRequestBody(BaseModel):
    model_config = {"extra": "forbid"}

    agent_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = ""
    scope: str = Field(min_length=1, max_length=256)


@router.post("/lease/request", status_code=status.HTTP_202_ACCEPTED, dependencies=_GSAM_GATE)
async def lease_request(body: LeaseRequestBody) -> dict:
    """Request a JIT credential lease. Approval token is delivered via Slack —
    never returned to the requester."""
    from warden.gsam.jit_lease import LeaseUnavailableError, request_lease  # noqa: PLC0415
    try:
        req = request_lease(body.agent_id, body.tenant_id, body.scope)
    except LeaseUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    # NB: req.approval_token is intentionally omitted from the response.
    return {"lease_id": req.lease_id, "status": req.status}


@router.post("/lease/approve/{token}", dependencies=_GSAM_GATE)
async def lease_approve(
    token: str,
    x_admin_key: str | None = Header(default=None),
) -> dict:
    """Approve a pending lease (admin-only). Returns the bearer signature."""
    _require_admin(x_admin_key)
    from warden.gsam.jit_lease import LeaseUnavailableError, approve  # noqa: PLC0415
    try:
        result = approve(token)
    except LeaseUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Unknown, expired, or already-resolved token.")
    return result


@router.get("/lease/{lease_id}/status", dependencies=_GSAM_GATE)
async def lease_status(lease_id: str) -> dict:
    """Return lease metadata (never the signature or secret)."""
    from warden.gsam.jit_lease import get_status  # noqa: PLC0415
    result = get_status(lease_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Lease not found.")
    return result
