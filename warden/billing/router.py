"""
warden/billing/router.py
─────────────────────────
Billing API router — tier catalog, quota status, and referral flywheel.

Endpoints
─────────
  GET  /billing/tiers              — public tier catalog (no auth)
  GET  /billing/status             — current plan + subscription details
  GET  /billing/quota              — monthly request usage for a tenant
  GET  /billing/upgrade            — redirect to Lemon Squeezy checkout
  POST /billing/referral/generate  — generate a referral code
  POST /billing/referral/redeem    — redeem a referral code
  GET  /billing/referral/stats     — referral statistics for a tenant

Auth
────
  All endpoints (except /billing/tiers) require the X-Tenant-ID header.
  Admin-only endpoints additionally require X-Admin-Key.

  Rate-limited at the slowapi application level — no extra limits here.
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

log = logging.getLogger("warden.billing.router")

router = APIRouter(prefix="/billing", tags=["billing"])

_PORTAL_BASE = os.getenv("PORTAL_BASE_URL", "https://app.shadowwarden.ai")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_tenant(x_tenant_id: str | None) -> str:
    if not x_tenant_id or not x_tenant_id.strip():
        raise HTTPException(status_code=401, detail="X-Tenant-ID header is required.")
    return x_tenant_id.strip()


# ── Pydantic models ───────────────────────────────────────────────────────────

class GenerateReferralRequest(BaseModel):
    tenant_id: str


class RedeemReferralRequest(BaseModel):
    code:          str
    new_tenant_id: str


# ── Tier catalog ──────────────────────────────────────────────────────────────

@router.get(
    "/tiers",
    summary="Tier catalog — all plans with features and pricing",
    response_model=None,
)
async def get_billing_tiers():
    """
    Returns the full feature matrix for all 4 plan tiers.
    No authentication required — used by the landing page pricing section.
    """
    from warden.billing.feature_gate import FeatureGate, OVERAGE_PRICES

    _PRICES = {
        "starter":    {"usd_per_month": 0,   "label": "Free"},
        "individual": {"usd_per_month": 5,   "label": "Individual"},
        "pro":        {"usd_per_month": 49,  "label": "Pro"},
        "enterprise": {"usd_per_month": 199, "label": "Enterprise"},
    }

    tiers = []
    for tier_name in ("starter", "individual", "pro", "enterprise"):
        gate = FeatureGate.for_tier(tier_name)
        d    = gate.as_dict()
        d["pricing"]        = _PRICES[tier_name]
        d["overage_prices"] = OVERAGE_PRICES.get(tier_name, {})
        tiers.append(d)

    return {"tiers": tiers}


# ── Subscription status ───────────────────────────────────────────────────────

@router.get(
    "/status",
    summary="Current subscription plan and billing details for a tenant",
)
async def get_billing_status(
    x_tenant_id: str | None = Header(default=None),
):
    tenant_id = _require_tenant(x_tenant_id)
    try:
        from warden.lemon_billing import get_lemon_billing
        status = get_lemon_billing().get_status(tenant_id)
    except Exception as exc:
        log.warning("billing/status: lemon_billing error: %s", exc)
        status = {
            "tenant_id": tenant_id,
            "plan":      "starter",
            "quota":     1000,
            "status":    "active",
            "renews_at": None,
            "customer_id": None,
        }

    # Enrich with feature gate details
    from warden.billing.feature_gate import FeatureGate
    gate = FeatureGate.for_tier(status.get("plan", "starter"))
    status["features"]      = gate.as_dict()
    status["billing_portal"] = f"https://app.lemonsqueezy.com/my-orders"
    return status


# ── Request quota ─────────────────────────────────────────────────────────────

@router.get(
    "/quota",
    summary="Current monthly request usage for a tenant",
)
async def get_billing_quota(
    x_tenant_id: str | None = Header(default=None),
):
    tenant_id = _require_tenant(x_tenant_id)
    from warden.billing.quota_middleware import get_quota_usage
    return get_quota_usage(tenant_id)


# ── Upgrade redirect ──────────────────────────────────────────────────────────

@router.get(
    "/upgrade",
    summary="Redirect to Lemon Squeezy checkout for plan upgrade",
    response_class=RedirectResponse,
    status_code=303,
)
async def billing_upgrade(
    plan:         str   = Query(..., description="Target plan: individual|pro|enterprise"),
    x_tenant_id:  str | None = Header(default=None),
    customer_email: str | None = Query(default=None),
    success_url:  str | None = Query(default=None),
    cancel_url:   str | None = Query(default=None),
):
    tenant_id  = _require_tenant(x_tenant_id)
    _success   = success_url  or f"{_PORTAL_BASE}/billing/success"
    _cancel    = cancel_url   or f"{_PORTAL_BASE}/billing/cancel"

    try:
        from warden.lemon_billing import get_lemon_billing
        url = get_lemon_billing().create_checkout_session(
            tenant_id      = tenant_id,
            plan           = plan,
            success_url    = _success,
            cancel_url     = _cancel,
            customer_email = customer_email,
        )
        return RedirectResponse(url=url, status_code=303)
    except RuntimeError as exc:
        # LS not configured — redirect to pricing page
        log.warning("billing/upgrade: checkout unavailable: %s", exc)
        return RedirectResponse(
            url=f"{_PORTAL_BASE}/pricing?plan={plan}",
            status_code=303,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ── Referral — generate ───────────────────────────────────────────────────────

@router.post(
    "/referral/generate",
    summary="Generate a referral code for the requesting tenant",
)
async def generate_referral(
    x_tenant_id: str | None = Header(default=None),
):
    tenant_id = _require_tenant(x_tenant_id)

    # Look up the tenant's current plan
    try:
        from warden.lemon_billing import get_lemon_billing
        plan = get_lemon_billing().get_plan(tenant_id)
    except Exception:
        plan = "starter"

    try:
        from warden.billing.referral import generate_referral_code
        code = generate_referral_code(tenant_id, plan)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    share_url = f"{_PORTAL_BASE}/signup?ref={code}"
    return {
        "code":      code,
        "share_url": share_url,
        "plan":      plan,
        "expires_in_days": 90,
    }


# ── Referral — redeem ─────────────────────────────────────────────────────────

@router.post(
    "/referral/redeem",
    summary="Redeem a referral code for a new tenant",
)
async def redeem_referral(body: RedeemReferralRequest):
    if not body.code or not body.new_tenant_id:
        raise HTTPException(status_code=400, detail="code and new_tenant_id are required.")

    try:
        from warden.billing.referral import redeem_referral_code
        result = redeem_referral_code(body.code, body.new_tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return result


# ── Referral — stats ──────────────────────────────────────────────────────────

@router.get(
    "/referral/stats",
    summary="Referral statistics for a tenant",
)
async def get_referral_stats(
    x_tenant_id: str | None = Header(default=None),
):
    tenant_id = _require_tenant(x_tenant_id)
    from warden.billing.referral import get_referral_stats
    stats = get_referral_stats(tenant_id)

    # Enrich with current plan's bonus-per-referral
    try:
        from warden.lemon_billing import get_lemon_billing
        plan = get_lemon_billing().get_plan(tenant_id)
    except Exception:
        plan = "starter"

    from warden.billing.feature_gate import TIER_LIMITS, _normalize_tier
    tier   = _normalize_tier(plan)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["starter"])
    stats["plan"]                  = tier
    stats["bonus_per_referral"]    = limits.get("referral_bonus_requests", 500)
    stats["referral_program"]      = limits.get("referral_program", True)
    return stats
