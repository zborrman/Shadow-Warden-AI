"""
warden/billing/router.py
─────────────────────────
Billing API router — tier catalog, quota status, and referral flywheel.

Endpoints
─────────
  GET  /billing/tiers                    — public tier catalog with annual pricing (no auth)
  GET  /billing/status                   — current plan + subscription details
  GET  /billing/quota                    — monthly request usage for a tenant
  GET  /billing/upgrade                  — redirect to Lemon Squeezy checkout
  POST /billing/trial/start              — activate 14-day Pro trial (Individual+ only)
  GET  /billing/trial/status             — trial status + days remaining
  GET  /billing/addons/bundles           — bundle catalog (Power User Bundle etc.)
  GET  /billing/addons/bundle/{key}/checkout  — redirect to bundle checkout
  POST /billing/addons/grant             — [Admin] grant add-on to tenant
  DELETE /billing/addons/revoke          — [Admin] revoke add-on from tenant
  POST /billing/community-seats/add      — add seat expansion units (stackable)
  GET  /billing/community-seats          — current extra seats for tenant
  POST /billing/referral/generate        — generate a referral code
  POST /billing/referral/redeem          — redeem a referral code
  GET  /billing/referral/stats           — referral statistics for a tenant

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


def _require_admin(x_admin_key: str | None) -> None:
    admin_key = os.getenv("ADMIN_KEY", "")
    if not admin_key or x_admin_key != admin_key:
        raise HTTPException(status_code=403, detail="X-Admin-Key required.")


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
    from warden.billing.feature_gate import ANNUAL_PRICING, OVERAGE_PRICES, FeatureGate  # noqa: PLC0415
    prices = {
        "starter":            {"usd_per_month": 0,   "label": "Free",               "annual": None},
        "individual":         {"usd_per_month": 5,   "label": "Individual",          "annual": ANNUAL_PRICING.get("individual")},
        "community_business": {"usd_per_month": 19,  "label": "Community Business",  "annual": ANNUAL_PRICING.get("community_business")},
        "pro":                {"usd_per_month": 69,  "label": "Pro",                 "annual": ANNUAL_PRICING.get("pro")},
        "enterprise":         {"usd_per_month": 249, "label": "Enterprise",          "annual": ANNUAL_PRICING.get("enterprise")},
    }

    tiers = []
    for tier_name in ("starter", "individual", "community_business", "pro", "enterprise"):
        gate = FeatureGate.for_tier(tier_name)
        d    = gate.as_dict()
        d["pricing"]        = prices[tier_name]
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
    status["billing_portal"] = "https://app.lemonsqueezy.com/my-orders"
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


# ── Add-on catalog ────────────────────────────────────────────────────────────

@router.get(
    "/addons",
    summary="Add-on SKU catalog",
    response_model=None,
)
async def list_addons():
    """
    Return all purchasable add-on SKUs with display names, prices, and minimum tiers.
    No authentication required — used by pricing pages and upgrade flows.
    """
    from warden.billing.addons import ADDON_CATALOG
    return {"addons": list(ADDON_CATALOG.values())}


@router.get(
    "/addons/tenant",
    summary="List add-ons purchased by a tenant",
)
async def get_tenant_addons(
    x_tenant_id: str | None = Header(default=None),
):
    """Return the set of active add-on keys for the requesting tenant."""
    tenant_id = _require_tenant(x_tenant_id)
    from warden.billing.addons import ADDON_CATALOG  # noqa: PLC0415
    from warden.billing.addons import get_tenant_addons as _get_addons
    active_keys = _get_addons(tenant_id)
    return {
        "tenant_id":  tenant_id,
        "addons":     list(active_keys),
        "details":    [ADDON_CATALOG[k] for k in active_keys if k in ADDON_CATALOG],
    }


@router.get(
    "/addons/{addon_key}/checkout",
    summary="Redirect to Lemon Squeezy checkout for an add-on",
    response_class=RedirectResponse,
    status_code=303,
)
async def addon_checkout(
    addon_key:   str,
    x_tenant_id: str | None = Header(default=None),
    success_url: str | None = Query(default=None),
    cancel_url:  str | None = Query(default=None),
):
    tenant_id = _require_tenant(x_tenant_id)
    from warden.billing.addons import ADDON_CATALOG
    addon = ADDON_CATALOG.get(addon_key)
    if not addon:
        raise HTTPException(status_code=404, detail=f"Unknown add-on: {addon_key!r}")

    variant_id = addon.get("ls_variant_id", "")
    if not variant_id:
        # LS not configured — redirect to pricing page
        return RedirectResponse(
            url=f"{_PORTAL_BASE}/pricing?addon={addon_key}",
            status_code=303,
        )

    _success = success_url or f"{_PORTAL_BASE}/billing/addons/{addon_key}/success"
    _cancel  = cancel_url  or f"{_PORTAL_BASE}/billing/addons"

    try:
        from warden.lemon_billing import get_lemon_billing
        url = get_lemon_billing().create_checkout_session(
            tenant_id   = tenant_id,
            plan        = addon_key,
            success_url = _success,
            cancel_url  = _cancel,
        )
        return RedirectResponse(url=url, status_code=303)
    except Exception as exc:
        log.warning("addon_checkout: lemon error addon=%s: %s", addon_key, exc)
        return RedirectResponse(
            url=f"{_PORTAL_BASE}/pricing?addon={addon_key}",
            status_code=303,
        )


# ── Add-on admin (grant / revoke) ─────────────────────────────────────────────

class AddonGrantRequest(BaseModel):
    tenant_id: str
    addon_key: str


@router.post(
    "/addons/grant",
    status_code=200,
    summary="[Admin] Grant an add-on to a tenant",
)
async def admin_grant_addon(
    body:        AddonGrantRequest,
    x_admin_key: str | None = Header(default=None),
):
    """
    Called by the Lemon Squeezy subscription webhook on successful payment.
    Requires X-Admin-Key header.
    """
    _require_admin(x_admin_key)
    from warden.billing.addons import grant_addon
    try:
        grant_addon(body.tenant_id, body.addon_key)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"status": "granted", "tenant_id": body.tenant_id, "addon_key": body.addon_key}


@router.delete(
    "/addons/revoke",
    status_code=200,
    summary="[Admin] Revoke an add-on from a tenant",
)
async def admin_revoke_addon(
    body:        AddonGrantRequest,
    x_admin_key: str | None = Header(default=None),
):
    """
    Called by the Lemon Squeezy subscription webhook on cancellation.
    Requires X-Admin-Key header.
    """
    _require_admin(x_admin_key)
    from warden.billing.addons import revoke_addon
    revoke_addon(body.tenant_id, body.addon_key)
    return {"status": "revoked", "tenant_id": body.tenant_id, "addon_key": body.addon_key}


# ── Trial ─────────────────────────────────────────────────────────────────────

class TrialStartRequest(BaseModel):
    current_tier: str = "starter"


@router.post(
    "/trial/start",
    summary="Activate 14-day Pro trial (Individual+ tenants only, one-time)",
)
async def start_trial(
    body:        TrialStartRequest,
    x_tenant_id: str | None = Header(default=None),
):
    """
    Activates a 14-day Pro trial capped at 10 000 requests.
    MasterAgent is excluded from the trial.
    One-time per tenant — raises 409 if already used.
    """
    tenant_id = _require_tenant(x_tenant_id)
    from warden.billing.trial import start_trial as _start  # noqa: PLC0415
    try:
        record = _start(tenant_id, current_tier=body.current_tier)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return record


@router.get(
    "/trial/status",
    summary="Get current trial status for a tenant",
)
async def trial_status(
    x_tenant_id: str | None = Header(default=None),
):
    tenant_id = _require_tenant(x_tenant_id)
    from warden.billing.trial import get_trial  # noqa: PLC0415
    trial = get_trial(tenant_id)
    if not trial:
        return {"tenant_id": tenant_id, "status": "none", "trial_available": True}
    return trial


# ── Bundles ───────────────────────────────────────────────────────────────────

@router.get(
    "/addons/bundles",
    summary="Bundle catalog — discounted add-on packs",
    response_model=None,
)
async def list_bundles():
    """Return all available bundle SKUs with savings information."""
    from warden.billing.addons import BUNDLE_CATALOG  # noqa: PLC0415
    return {"bundles": list(BUNDLE_CATALOG.values())}


@router.get(
    "/addons/bundle/{bundle_key}/checkout",
    summary="Redirect to Lemon Squeezy checkout for a bundle",
    response_class=RedirectResponse,
    status_code=303,
)
async def bundle_checkout(
    bundle_key:  str,
    x_tenant_id: str | None = Header(default=None),
    success_url: str | None = Query(default=None),
    cancel_url:  str | None = Query(default=None),
):
    tenant_id = _require_tenant(x_tenant_id)
    from warden.billing.addons import BUNDLE_CATALOG  # noqa: PLC0415
    bundle = BUNDLE_CATALOG.get(bundle_key)
    if not bundle:
        raise HTTPException(status_code=404, detail=f"Unknown bundle: {bundle_key!r}")

    variant_id = bundle.get("ls_variant_id", "")
    if not variant_id:
        return RedirectResponse(url=f"{_PORTAL_BASE}/pricing?bundle={bundle_key}", status_code=303)

    _success = success_url or f"{_PORTAL_BASE}/billing/bundle/{bundle_key}/success"
    _cancel  = cancel_url  or f"{_PORTAL_BASE}/billing/addons"
    try:
        from warden.lemon_billing import get_lemon_billing  # noqa: PLC0415
        url = get_lemon_billing().create_checkout_session(
            tenant_id=tenant_id, plan=bundle_key,
            success_url=_success, cancel_url=_cancel,
        )
        return RedirectResponse(url=url, status_code=303)
    except Exception as exc:
        log.warning("bundle_checkout: lemon error bundle=%s: %s", bundle_key, exc)
        return RedirectResponse(url=f"{_PORTAL_BASE}/pricing?bundle={bundle_key}", status_code=303)


# ── Community seat expansion ──────────────────────────────────────────────────

class SeatGrantRequest(BaseModel):
    tenant_id: str
    units:     int = 1    # each unit = +5 members


@router.post(
    "/community-seats/add",
    summary="[Admin] Add community seat expansion units to a tenant",
)
async def add_community_seats(
    body:        SeatGrantRequest,
    x_admin_key: str | None = Header(default=None),
):
    """
    Called by Lemon Squeezy webhook on community_seats purchase.
    Each unit adds 5 member slots. Stackable — purchase multiple times.
    """
    _require_admin(x_admin_key)
    from warden.billing.addons import increment_seat_units  # noqa: PLC0415
    total_extra = increment_seat_units(body.tenant_id, units=body.units)
    return {
        "tenant_id":   body.tenant_id,
        "units_added": body.units,
        "total_extra_seats": total_extra,
    }


@router.get(
    "/community-seats",
    summary="Get extra community member seats for a tenant",
)
async def get_community_seats(
    x_tenant_id: str | None = Header(default=None),
):
    tenant_id = _require_tenant(x_tenant_id)
    from warden.billing.addons import get_seat_expansion  # noqa: PLC0415
    extra = get_seat_expansion(tenant_id)
    return {
        "tenant_id":   tenant_id,
        "extra_seats": extra,
        "note":        "Added to your tier's base max_members_per_community",
    }


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
