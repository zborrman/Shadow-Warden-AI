"""
warden/billing/addons.py
──────────────────────────
Add-on SKU registry and per-tenant add-on entitlements.

Add-ons extend features beyond the base tier without a full plan upgrade.
They are purchased separately via Lemon Squeezy variant IDs and stored in
Redis as a set per tenant.

Add-on catalog
──────────────
  shadow_ai_discovery  +$15/mo  Pro+           Shadow AI subnet probe + DNS telemetry
  xai_audit            +$9/mo   Individual+    Causal XAI HTML/PDF audit reports
  secrets_vault        +$12/mo  Individual+    Secrets governance (AWS SM / Azure KV / etc.)
  on_prem_pack         +$29/mo  Pro+           Self-hosted license + Helm chart support
  community_seats      +$9/mo   Community Biz+ +5 member slots per unit (stackable)

Bundle catalog
──────────────
  power_user_bundle    $29/mo   Pro+           Secrets Vault + XAI Audit + Shadow AI ($36 separately → save $7)

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

    "secrets_vault": {
        "display_name":   "Secrets Vault Governance",
        "description":    "Centralize secrets discovery, lifecycle automation, and policy enforcement across AWS SM, Azure KV, HashiCorp Vault, GCP SM, and env.",
        "usd_per_month":  12,
        "min_tier":       "individual",
        "ls_variant_id":  os.getenv("LS_VARIANT_SECRETS_VAULT", ""),
        "unlocks":        ["secrets_governance"],
        "docs_url":       "/docs/addons/secrets-vault",
    },

    "on_prem_pack": {
        "display_name":   "On-Prem Deployment Pack",
        "description":    "Self-hosted license + Helm chart support + hardening runbook. Run Shadow Warden entirely inside your own infrastructure with no cloud dependency.",
        "usd_per_month":  29,
        "min_tier":       "pro",
        "ls_variant_id":  os.getenv("LS_VARIANT_ON_PREM", ""),
        "unlocks":        ["on_prem_deployment"],
        "docs_url":       "/docs/addons/on-prem",
    },

    "community_seats": {
        "display_name":   "Community Seat Expansion (+5 members)",
        "description":    "Add 5 additional member slots to every community on your account. Stack multiple purchases for larger teams.",
        "usd_per_month":  9,
        "min_tier":       "community_business",
        "ls_variant_id":  os.getenv("LS_VARIANT_COMMUNITY_SEATS", ""),
        "unlocks":        [],        # handled via seat counter, not feature flag
        "stackable":      True,      # can be purchased multiple times
        "seats_per_unit": 5,
        "docs_url":       "/docs/addons/community-seats",
    },

}

# ── Bundle catalog ─────────────────────────────────────────────────────────────
# Virtual bundles — not sold individually via LS; resolved to component add-ons on checkout.

BUNDLE_CATALOG: dict[str, dict[str, Any]] = {

    "power_user_bundle": {
        "display_name":     "Power User Bundle",
        "description":      "Secrets Vault + XAI Audit Reports + Shadow AI Discovery in one package. Save $7/mo vs purchasing separately.",
        "usd_per_month":    29,      # vs $12 + $9 + $15 = $36 separately
        "savings_usd":      7,
        "min_tier":         "pro",
        "includes_addons":  ["secrets_vault", "xai_audit", "shadow_ai_discovery"],
        "ls_variant_id":    os.getenv("LS_VARIANT_POWER_BUNDLE", ""),
        "docs_url":         "/docs/addons/power-user-bundle",
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


def grant_bundle(tenant_id: str, bundle_key: str) -> list[str]:
    """Grant all component add-ons for *bundle_key* to *tenant_id*."""
    bundle = BUNDLE_CATALOG.get(bundle_key)
    if not bundle:
        raise ValueError(f"Unknown bundle: {bundle_key!r}")
    granted: list[str] = []
    for addon_key in bundle["includes_addons"]:
        grant_addon(tenant_id, addon_key)
        granted.append(addon_key)
    log.info("Bundle granted tenant=%s bundle=%s addons=%s", tenant_id, bundle_key, granted)
    return granted


def get_seat_expansion(tenant_id: str) -> int:
    """Return total extra community member slots purchased via community_seats add-on (stackable)."""
    r = _redis()
    key = f"billing:seat_units:{tenant_id}"
    try:
        units = int(r.get(key) or 0) if r else 0
    except Exception:
        units = 0
    seats_per_unit = ADDON_CATALOG["community_seats"]["seats_per_unit"]
    return units * seats_per_unit


def increment_seat_units(tenant_id: str, units: int = 1) -> int:
    """Add *units* seat expansion packs for *tenant_id*. Returns new total extra seats."""
    r = _redis()
    key = f"billing:seat_units:{tenant_id}"
    if r:
        try:
            r.incrby(key, units)
        except Exception as exc:
            log.warning("increment_seat_units redis error: %s", exc)
    new_seats = get_seat_expansion(tenant_id)
    log.info("Seat units added tenant=%s units=%d total_extra_seats=%d", tenant_id, units, new_seats)
    return new_seats


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
