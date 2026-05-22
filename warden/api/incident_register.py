"""
warden/api/incident_register.py  (CM-35)
──────────────────────────────────────────
FastAPI router for AI Incident Register.

Prefix: /incidents
Tier:   Individual+ (incident_register_enabled)
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/incidents", tags=["Incident Register"])
_Gate  = require_feature("incident_register_enabled")


class IncidentCreateRequest(BaseModel):
    tenant_id:       str
    title:           str = Field(..., min_length=1, max_length=300)
    severity:        str = "MEDIUM"
    category:        str = "OTHER"
    description:     str = ""
    community_id:    str = ""
    affected_system: str = ""
    vendor_id:       str = ""
    request_id:      str = ""


class StatusUpdateRequest(BaseModel):
    status:      str
    resolved_at: str | None = None


@router.post("", summary="Log a new AI incident", dependencies=[_Gate])
async def create_incident(body: IncidentCreateRequest) -> dict:
    from warden.communities.incident_register import log_incident
    incident_id = log_incident(
        tenant_id=body.tenant_id,
        title=body.title,
        severity=body.severity,
        category=body.category,
        description=body.description,
        community_id=body.community_id,
        affected_system=body.affected_system,
        vendor_id=body.vendor_id,
        request_id=body.request_id,
    )
    return {"incident_id": incident_id, "status": "open"}


@router.get("", summary="List incidents for a tenant", dependencies=[_Gate])
async def list_incidents(
    tenant_id: str,
    severity:  str | None = None,
    status:    str | None = None,
    category:  str | None = None,
    limit:     int = 50,
) -> dict:
    from warden.communities.incident_register import list_incidents as _list
    items = _list(tenant_id, severity=severity, status=status, category=category, limit=limit)
    return {"incidents": items, "count": len(items)}


@router.get("/stats", summary="Incident stats for a tenant", dependencies=[_Gate])
async def get_stats(tenant_id: str) -> dict:
    from warden.communities.incident_register import get_incident_stats
    return get_incident_stats(tenant_id)


@router.get("/{incident_id}", summary="Get a specific incident", dependencies=[_Gate])
async def get_incident(incident_id: str) -> dict:
    from warden.communities.incident_register import get_incident as _get
    inc = _get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    return inc


@router.put("/{incident_id}/status", summary="Update incident status", dependencies=[_Gate])
async def update_status(incident_id: str, body: StatusUpdateRequest) -> dict:
    from warden.communities.incident_register import update_status as _upd
    ok = _upd(incident_id, body.status, resolved_at=body.resolved_at)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found or invalid status")
    return {"updated": True, "incident_id": incident_id, "status": body.status}
