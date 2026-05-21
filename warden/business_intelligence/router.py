"""
warden/business_intelligence/router.py  (CM-39)
─────────────────────────────────────────────────
FastAPI router for the Business Intelligence module.

Prefix: /business-intelligence
Tier:   Community Business+ (communities_enabled)
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from warden.billing.feature_gate import require_feature
from warden.business_intelligence.models import ReportRequest
from warden.business_intelligence.repository import (
    cache_invalidate,
    cache_purge_expired,
    cache_stats,
)

router = APIRouter(prefix="/business-intelligence", tags=["Business Intelligence"])
_Gate  = require_feature("communities_enabled")


@router.get("/usage", summary="AI usage analytics for a tenant", dependencies=[_Gate])
async def usage_summary(tenant_id: str, period_month: str | None = None) -> dict:
    from warden.business_intelligence.service import get_usage_summary
    return get_usage_summary(tenant_id, period_month)


@router.get("/threats", summary="Threat intelligence dashboard", dependencies=[_Gate])
async def threat_summary(tenant_id: str, period_days: int = 30) -> dict:
    from warden.business_intelligence.service import get_threat_summary
    return get_threat_summary(tenant_id, period_days)


@router.get("/vendors", summary="Vendor performance scorecards", dependencies=[_Gate])
async def vendor_scorecards(tenant_id: str) -> dict:
    from warden.business_intelligence.service import get_vendor_scorecards
    return {"tenant_id": tenant_id, "scorecards": get_vendor_scorecards(tenant_id)}


@router.get("/costs", summary="Cost optimization insights", dependencies=[_Gate])
async def cost_insights(tenant_id: str, months: int = 3) -> dict:
    from warden.business_intelligence.service import get_cost_insights
    return get_cost_insights(tenant_id, months)


@router.get("/compliance", summary="Compliance posture score", dependencies=[_Gate])
async def compliance_score(tenant_id: str, community_id: str = "") -> dict:
    from warden.business_intelligence.service import get_compliance_score
    return get_compliance_score(tenant_id, community_id)


@router.get("/benchmarks", summary="Community benchmarking", dependencies=[_Gate])
async def benchmarks(tenant_id: str, community_id: str = "") -> dict:
    from warden.business_intelligence.service import get_benchmarks
    return {
        "tenant_id": tenant_id,
        "benchmarks": get_benchmarks(tenant_id, community_id),
    }


@router.get("/predictions", summary="Predictive incident analytics", dependencies=[_Gate])
async def incident_prediction(tenant_id: str, horizon_days: int = 30) -> dict:
    from warden.business_intelligence.service import get_incident_prediction
    return get_incident_prediction(tenant_id, horizon_days)


@router.post("/report", summary="Build a custom BI report", dependencies=[_Gate])
async def build_report(body: ReportRequest) -> dict:
    from warden.business_intelligence.service import build_report
    try:
        return build_report(
            tenant_id=body.tenant_id,
            community_id=body.community_id,
            report_type=body.report_type,
            period_months=body.period_months,
            include_sections=body.include_sections,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/summary", summary="Executive summary (all modules)", dependencies=[_Gate])
async def executive_summary(tenant_id: str, community_id: str = "") -> dict:
    from warden.business_intelligence.service import build_report
    return build_report(
        tenant_id=tenant_id,
        community_id=community_id,
        report_type="executive",
        period_months=1,
    )


# ── Cache management ───────────────────────────────────────────────────────────

@router.delete("/cache", summary="Invalidate BI cache for a tenant", dependencies=[_Gate])
async def invalidate_cache(tenant_id: str) -> dict:
    removed = cache_invalidate(tenant_id)
    return {"removed": removed, "tenant_id": tenant_id}


@router.post("/cache/purge", summary="Purge all expired cache entries", dependencies=[_Gate])
async def purge_cache() -> dict:
    removed = cache_purge_expired()
    return {"removed": removed}


@router.get("/cache/stats", summary="Cache statistics for a tenant", dependencies=[_Gate])
async def get_cache_stats(tenant_id: str) -> dict:
    return cache_stats(tenant_id)
