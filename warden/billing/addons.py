"""
warden/billing/addons.py
──────────────────────────
Add-on SKU registry and per-tenant add-on entitlements.

Add-ons extend features beyond the base tier without a full plan upgrade.
They are purchased separately via Lemon Squeezy variant IDs and stored in
Redis as a set per tenant.

Add-on catalog
──────────────
  shadow_ai_discovery  +$15/mo  Pro+   Shadow AI subnet probe + DNS telemetry
  xai_audit            +$9/mo   Indiv+ Causal XAI HTML/PDF audit reports

  MasterAgent is included in the Pro base plan — not sold as an add-on.

Lemon Squeezy integration
──────────────────────────
  Webhooks call POST /billing/addons/grant or /billing/addons/revoke.
  Alternatively, `grant_addon()` / `revoke_addon()` can be called directly
  from the LS webhook handler in lemon_billing.py.

Storage
───────
  Redis set: `billing:addons:{tenant_id}` (no TTL — active subscription = present)
  Falls back to in-process set when Redis unavailable.

Usage in route handlers
────────────────────────
  from warden.billing.addons import require_addon_or_feature

  @router.post("/shadow-ai/scan", dependencies=[require_addon_or_feature(
      feature="shadow_ai_enabled",
      addon_key="shadow_ai_discovery",
      min_tier="pro",
  )])
  async def scan_subnet(body, auth): ...
"""
from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import Depends, HTTPException, Request

from warden.billing.feature_gate import (
    FeatureGate,
    _get_tenant_tier,
    _normalize_tier,
)

log = logging.getLogger("warden.billing.addons")

_MEMORY_ADDONS: dict[str, set[str]] = {}


# ── Add-on catalog ────────────────────────────────────────────────────────────

ADDON_CATALOG: dict[str, dict[str, Any]] = {

    "shadow_ai_discovery": {
        "display_name":   "Shadow AI Discovery",
        "description":    "Detect unauthorized AI tool usage: async subnet probe, DNS telemetry, 18-provider fingerprint DB.",
        "usd_per_month":  15,
        "min_tier":       "pro",
        "ls_variant_id":  os.getenv("LS_VARIANT_SHADOW_AI", ""),
        "unlocks":        ["shadow_ai_enabled"],
        "docs_url":       "/docs/addons/shadow-ai-discovery",
    },

    "xai_audit": {
        "display_name":   "Causal XAI Audit Reports",
        "description":    "HTML and PDF causal chain reports for every filter decision. SOC 2 / GDPR audit evidence.",
        "usd_per_month":  9,
        "min_tier":       "individual",
        "ls_variant_id":  os.getenv("LS_VARIANT_XAI_AUDIT", ""),
        "unlocks":        ["xai_reports_enabled"],
        "docs_url":       "/docs/addons/xai-audit",
    },

}



# ── Redis helpers ─────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


# ── Grant / revoke / check ────────────────────────────────────────────────────

def grant_addon(tenant_id: str, addon_key: str) -> None:
    """Grant *addon_key* to *tenant_id* (called on successful Lemon Squeezy webhook)."""
    if addon_key not in ADDON_CATALOG:
        raise ValueError(f"Unknown add-on: {addon_key!r}")
    _MEMORY_ADDONS.setdefault(tenant_id, set()).add(addon_key)
    r = _redis()
    if r:
        try:
            r.sadd(f"billing:addons:{tenant_id}", addon_key)
        except Exception as exc:
            log.warning("grant_addon redis error tenant=%s addon=%s: %s", tenant_id, addon_key, exc)
    log.info("Add-on granted tenant=%s addon=%s", tenant_id, addon_key)


def revoke_addon(tenant_id: str, addon_key: str) -> None:
    """Revoke *addon_key* from *tenant_id* (called on subscription cancellation)."""
    _MEMORY_ADDONS.get(tenant_id, set()).discard(addon_key)
    r = _redis()
    if r:
        try:
            r.srem(f"billing:addons:{tenant_id}", addon_key)
        except Exception as exc:
            log.warning("revoke_addon redis error tenant=%s addon=%s: %s", tenant_id, addon_key, exc)
    log.info("Add-on revoked tenant=%s addon=%s", tenant_id, addon_key)


def get_tenant_addons(tenant_id: str) -> set[str]:
    """Return the set of active add-on keys for *tenant_id*."""
    r = _redis()
    if r:
        try:
            return set(r.smembers(f"billing:addons:{tenant_id}"))
        except Exception as exc:
            log.debug("get_tenant_addons redis error: %s", exc)
    return set(_MEMORY_ADDONS.get(tenant_id, set()))


def has_addon(tenant_id: str, addon_key: str) -> bool:
    return addon_key in get_tenant_addons(tenant_id)


def _get_tenant_id_from_request(request: Request) -> str:
    """Extract tenant_id from request state or headers."""
    state  = getattr(request, "state", None)
    tenant = getattr(state, "tenant", None)
    if isinstance(tenant, dict):
        return tenant.get("tenant_id") or tenant.get("id") or "unknown"
    return request.headers.get("X-Tenant-ID", "unknown")


# ── FastAPI dependency factory ────────────────────────────────────────────────

def require_addon_or_feature(
    feature:   str,
    addon_key: str,
    min_tier:  str = "pro",
):
    """
    FastAPI dependency (use as a `dependencies=[...]` entry or `Depends()`).

    Passes when ANY of the following is true:
      1. The tenant's tier has *feature* natively enabled (e.g. enterprise).
      2. The tenant's tier ≥ *min_tier* AND they have purchased *addon_key*.

    Raises:
      HTTP 403  — tier too low (below min_tier)
      HTTP 402  — eligible tier but add-on not purchased
    """
    def _dep(request: Request) -> FeatureGate:
        tier = _normalize_tier(_get_tenant_tier(request))
        gate = FeatureGate.for_tier(tier)

        # Case 1: feature is natively enabled at this tier (Enterprise)
        try:
            if gate.is_enabled(feature):
                return gate
        except (KeyError, TypeError):
            pass

        # Case 2: tier eligible for add-on?
        if not gate.meets_minimum(min_tier):
            addon = ADDON_CATALOG.get(addon_key, {})
            raise HTTPException(
                status_code=403,
                detail={
                    "error":       "tier_required",
                    "message":     f"'{addon.get('display_name', addon_key)}' requires {min_tier.upper()} plan or higher.",
                    "current_plan": tier,
                    "upgrade_url": f"/billing/upgrade?plan={min_tier}",
                    "addon_url":   f"/billing/addons/{addon_key}/checkout",
                },
            )

        # Case 3: eligible tier but add-on not purchased?
        tenant_id = _get_tenant_id_from_request(request)
        if not has_addon(tenant_id, addon_key):
            addon = ADDON_CATALOG.get(addon_key, {})
            raise HTTPException(
                status_code=402,
                detail={
                    "error":         "addon_required",
                    "message":       f"'{addon.get('display_name', addon_key)}' add-on is required.",
                    "addon_key":     addon_key,
                    "price_usd_mo":  addon.get("usd_per_month"),
                    "checkout_url":  f"/billing/addons/{addon_key}/checkout",
                    "docs_url":      addon.get("docs_url"),
                },
            )

        return gate

    return Depends(_dep)
