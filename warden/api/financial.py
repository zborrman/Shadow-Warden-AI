"""
warden/api/financial.py
━━━━━━━━━━━━━━━━━━━━━━
FastAPI router — Dollar Impact Calculator endpoints.

Endpoints
─────────
  GET  /financial/impact          Full ROI report (live data or traffic estimate)
  GET  /financial/cost-saved      Inference cost saved via shadow banning
  GET  /financial/roi             Quick ROI summary for a given tier + industry
  POST /financial/generate-proposal  Generate a customer-facing proposal dict

All endpoints require the standard Warden API key (require_api_key dependency).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from warden.auth_guard import require_api_key
from warden.financial.impact_calculator import PRICING, DollarImpactCalculator, Industry
from warden.financial.metrics_reader import MetricsReader

log = logging.getLogger("warden.api.financial")

router = APIRouter(prefix="/financial", tags=["Financial Impact"])


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _build_calculator(
    industry: str,
    requests: int | None,
    cost_per_req: float,
    use_live: bool,
) -> DollarImpactCalculator:
    try:
        ind = Industry(industry.lower())
    except ValueError:
        ind = Industry.SAAS

    calc = DollarImpactCalculator(
        industry=ind,
        monthly_requests=requests or 1_000_000,
        avg_inference_cost=cost_per_req,
    )

    if use_live:
        try:
            reader = MetricsReader()
            calc.load_live_metrics(reader)
            if calc.monthly_requests == 0:
                calc.estimate_from_traffic()
        except Exception as exc:
            log.warning("Live metrics unavailable, using traffic estimate: %s", exc)
            calc.estimate_from_traffic()
    else:
        calc.estimate_from_traffic()

    return calc


# ── GET /financial/impact ──────────────────────────────────────────────────────

@router.get("/impact")
async def get_impact(
    industry:     str   = Query("saas",  description="Industry sector (fintech, healthcare, ecommerce, saas, government, education, legal)"),
    requests:     int | None   = Query(None,  description="Monthly request volume (auto-detected from logs if omitted)"),
    cost_per_req: float = Query(0.002,   description="Average LLM cost per request (USD)"),
    live:         bool  = Query(True,    description="Use live data from logs/Redis (false = traffic estimate only)"),
    _auth: None = Depends(require_api_key),
):
    """
    Full dollar impact report — monthly breakdown, 3-year projection, ROI by tier.
    """
    calc   = _build_calculator(industry, requests, cost_per_req, live)
    impact = calc.calculate_total_impact(years=3)
    return JSONResponse(content=impact)


# ── GET /financial/cost-saved ──────────────────────────────────────────────────

@router.get("/cost-saved")
async def get_cost_saved(
    _auth: None = Depends(require_api_key),
):
    """
    Quick read of cumulative LLM inference cost saved via shadow banning.
    Reads directly from Prometheus counter — no calculation needed.
    """
    reader = MetricsReader()
    cost   = reader.shadow_ban_cost_saved_usd()
    return {
        "shadow_ban_cost_saved_usd": round(cost, 4),
        "shadow_banned_entities":    reader.shadow_banned_count(),
    }


# ── GET /financial/roi ─────────────────────────────────────────────────────────

@router.get("/roi")
async def get_roi(
    industry:     str   = Query("saas"),
    tier:         str   = Query("professional", description="Pricing tier: startup, professional, enterprise"),
    requests:     int | None   = Query(None),
    cost_per_req: float = Query(0.002),
    _auth: None = Depends(require_api_key),
):
    """
    Quick ROI summary for a single pricing tier.
    """
    calc   = _build_calculator(industry, requests, cost_per_req, use_live=False)
    impact = calc.calculate_total_impact(years=3)
    tier_data = impact["tier_roi"].get(tier)
    if tier_data is None:
        available = list(impact["tier_roi"].keys())
        return JSONResponse(
            status_code=400,
            content={"error": f"Unknown tier '{tier}'. Available: {available}"},
        )
    return {
        "industry":            impact["industry"],
        "monthly_requests":    impact["monthly_requests"],
        "annual_total_usd":    impact["annual_total_usd"],
        "tier":                tier_data,
        "cumulative_3y_usd":   impact["cumulative_3y_usd"],
    }


# ── POST /financial/generate-proposal ─────────────────────────────────────────

from pydantic import BaseModel  # noqa: E402


class ProposalRequest(BaseModel):
    industry:          str   = "saas"
    monthly_requests:  int   = 1_000_000
    avg_inference_cost: float = 0.002
    target_tier:       str   = "professional"
    customer_name:     str   = ""


@router.post("/generate-proposal")
async def generate_proposal(
    body:  ProposalRequest,
    _auth: None = Depends(require_api_key),
):
    """
    Generate a customer-facing ROI proposal with full impact breakdown,
    recommended pricing tier, and headline numbers suitable for a sales deck.
    """
    calc = _build_calculator(
        body.industry,
        body.monthly_requests,
        body.avg_inference_cost,
        use_live=False,
    )
    impact = calc.calculate_total_impact(years=3)

    tier_info = PRICING.get(body.target_tier, PRICING["professional"])
    tier_roi  = impact["tier_roi"].get(body.target_tier, {})

    proposal = {
        "customer":             body.customer_name or "Prospective Customer",
        "generated_at":         impact["generated_at"],
        "industry":             impact["industry"],
        "monthly_requests":     impact["monthly_requests"],
        "headline": {
            "annual_value_usd":  impact["annual_total_usd"],
            "3y_value_usd":      impact["cumulative_3y_usd"],
            "recommended_tier":  tier_info["label"],
            "annual_cost_usd":   tier_info["annual_usd"],
            "net_benefit_usd":   tier_roi.get("net_benefit_usd", 0),
            "roi_pct":           tier_roi.get("roi_pct", 0),
            "payback_months":    tier_roi.get("payback_months", 0),
        },
        "monthly_breakdown":    impact["monthly_breakdown"],
        "3y_projection":        impact["yearly_projection"],
        "all_tiers":            impact["tier_roi"],
        "key_stats": {
            "threats_blocked_monthly":  sum(calc.threats_blocked.values()),
            "shadow_banned_entities":   calc.shadow_banned_entities,
            "pii_redactions_monthly":   calc.pii_redactions,
            "detection_rate_pct":       int(calc.DETECTION_RATE * 100),
        },
    }
    return JSONResponse(content=proposal)
