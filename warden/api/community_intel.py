"""
warden/api/community_intel.py
───────────────────────────────
Community Intelligence & Governance REST API.

Endpoints
─────────
  GET  /community-intel/{community_id}           → full intelligence report
  GET  /community-intel/{community_id}/risk      → risk score only

  POST /community-intel/{community_id}/charter          → create DRAFT charter
  GET  /community-intel/{community_id}/charter          → active charter
  POST /community-intel/{community_id}/charter/publish  → publish DRAFT
  POST /community-intel/{community_id}/charter/accept   → member accepts
  GET  /community-intel/{community_id}/charter/pending  → pending acceptances

  GET  /community-intel/{community_id}/anomalies        → recent anomaly log
  POST /community-intel/{community_id}/anomalies/detect → on-demand detection

  GET  /community-intel/{community_id}/oauth            → OAuth grant list
  POST /community-intel/{community_id}/oauth            → register OAuth grant
  DELETE /community-intel/oauth/{grant_id}              → revoke grant
  GET  /community-intel/{community_id}/oauth/summary    → risk summary
  GET  /community-intel/oauth/catalog                   → provider catalog

Auth: X-Tenant-ID header required (Community Business tier).
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

log = logging.getLogger("warden.api.community_intel")

router = APIRouter(prefix="/community-intel", tags=["Community Intelligence"])


# ── Auth ──────────────────────────────────────────────────────────────────────

def _require_tenant(x_tenant_id: str | None = Header(default=None)) -> str:
    if not x_tenant_id:
        raise HTTPException(status_code=401, detail="X-Tenant-ID required")
    return x_tenant_id


# ── Pydantic models ───────────────────────────────────────────────────────────

class CharterCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    transparency: str = Field("REQUIRED", pattern="^(REQUIRED|ENCOURAGED|OPTIONAL)$")
    data_minimization: str = Field("STRICT", pattern="^(STRICT|STANDARD|RELAXED)$")
    accountability: str = Field("", max_length=100)
    sustainability: str = Field("STANDARD", pattern="^(STANDARD|ADVANCED|CERTIFIED)$")
    allowed_data_classes: list[str] = Field(default_factory=lambda: ["GENERAL", "PII", "FINANCIAL"])
    prohibited_actions: list[str] = Field(default_factory=list)
    auto_block_threshold: float = Field(0.70, ge=0.0, le=1.0)


class CharterAcceptRequest(BaseModel):
    member_id: str = Field(..., min_length=1)
    ip_fingerprint: str = Field("", max_length=64)


class AnomalyDetectRequest(BaseModel):
    event_type: str = Field(..., min_length=1)
    value: float = Field(...)


class OAuthGrantRequest(BaseModel):
    member_id: str = Field(..., min_length=1)
    provider: str = Field(..., min_length=1)
    scopes: list[str] = Field(default_factory=list)


# ── Intelligence report ───────────────────────────────────────────────────────

@router.get("/{community_id}")
def get_intel_report(
    community_id: str,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    try:
        from warden.communities.intelligence import generate_report
        return generate_report(community_id).to_dict()
    except Exception as exc:
        log.exception("generate_report failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/{community_id}/risk")
def get_risk_score(
    community_id: str,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    try:
        from warden.communities.intelligence import generate_report
        report = generate_report(community_id)
        return report.risk.__dict__  # type: ignore[attr-defined]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Charter ───────────────────────────────────────────────────────────────────

@router.post("/{community_id}/charter")
def create_charter(
    community_id: str,
    body: CharterCreateRequest,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    try:
        from warden.communities.charter import create_charter as _create
        rec = _create(
            community_id=community_id,
            title=body.title,
            created_by=x_tenant_id or "unknown",
            transparency=body.transparency,
            data_minimization=body.data_minimization,
            accountability=body.accountability,
            sustainability=body.sustainability,
            allowed_data_classes=body.allowed_data_classes,
            prohibited_actions=body.prohibited_actions,
            auto_block_threshold=body.auto_block_threshold,
        )
        return rec.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{community_id}/charter")
def get_active_charter(
    community_id: str,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    from warden.communities.charter import get_active_charter as _get
    rec = _get(community_id)
    if not rec:
        raise HTTPException(status_code=404, detail="No active charter")
    return rec.to_dict()


@router.get("/{community_id}/charter/history")
def list_charters(
    community_id: str,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    from warden.communities.charter import list_charters as _list
    return {"community_id": community_id, "charters": [c.to_dict() for c in _list(community_id)]}


@router.post("/{community_id}/charter/{charter_id}/publish")
def publish_charter(
    community_id: str,
    charter_id: str,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    try:
        from warden.communities.charter import publish_charter as _publish
        return _publish(charter_id).to_dict()
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/{community_id}/charter/{charter_id}/accept")
def accept_charter(
    community_id: str,
    charter_id: str,
    body: CharterAcceptRequest,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    try:
        from warden.communities.charter import accept_charter as _accept
        return _accept(charter_id, body.member_id, ip_fingerprint=body.ip_fingerprint)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{community_id}/charter/pending")
def pending_acceptances(
    community_id: str,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    from warden.communities.charter import list_pending_acceptances
    return {
        "community_id": community_id,
        "pending": list_pending_acceptances(community_id),
    }


# ── Behavioral anomalies ──────────────────────────────────────────────────────

@router.get("/{community_id}/anomalies")
def list_anomalies(
    community_id: str,
    limit: int = Query(50, ge=1, le=200),
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    try:
        from warden.communities.behavioral import list_recent_anomalies
        return {
            "community_id": community_id,
            "anomalies": list_recent_anomalies(community_id, limit=limit),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/{community_id}/anomalies/detect")
def detect_anomaly_endpoint(
    community_id: str,
    body: AnomalyDetectRequest,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    try:
        from warden.communities.behavioral import detect_anomaly, record_event
        record_event(community_id, body.event_type, body.value)
        result = detect_anomaly(community_id, body.event_type, body.value)
        return result.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── OAuth Discovery ───────────────────────────────────────────────────────────

@router.get("/{community_id}/oauth")
def list_oauth_grants(
    community_id: str,
    status: str = Query("ACTIVE", pattern="^(ACTIVE|REVOKED)$"),
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    from warden.communities.oauth_discovery import list_grants
    return {
        "community_id": community_id,
        "grants": [g.to_dict() for g in list_grants(community_id, status=status)],
    }


@router.post("/{community_id}/oauth")
def register_oauth_grant(
    community_id: str,
    body: OAuthGrantRequest,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    from warden.communities.oauth_discovery import register_oauth_grant as _reg
    grant = _reg(community_id, body.member_id, body.provider, body.scopes)
    return grant.to_dict()


@router.delete("/oauth/{grant_id}")
def revoke_oauth_grant(
    grant_id: str,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    from warden.communities.oauth_discovery import revoke_grant
    try:
        grant = revoke_grant(grant_id)
        return grant.to_dict() if grant else {"grant_id": grant_id, "status": "REVOKED"}
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{community_id}/oauth/summary")
def oauth_risk_summary(
    community_id: str,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    from warden.communities.oauth_discovery import get_risk_summary
    return get_risk_summary(community_id)


@router.get("/oauth/catalog")
def oauth_provider_catalog(
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id)
    from warden.communities.oauth_discovery import get_provider_catalog
    return {"providers": get_provider_catalog()}
