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

from fastapi import APIRouter, status
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
