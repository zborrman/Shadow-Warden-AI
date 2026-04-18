"""
warden/billing/feature_gate.py
────────────────────────────────
Tier-based Feature Gating for Shadow Warden AI.

Tiers (aligned with Lemon Squeezy monetization)
────────────────────────────────────────────────
  starter    $0/mo   — Developers / Testing        1 000 req/mo
  individual $5/mo   — Solo Devs / Hobbyists       5 000 req/mo  (+$9/mo XAI add-on)
  pro        $69/mo  — Mid-market / SMBs           50 000 req/mo, SIEM, Master Agent (+$15/mo Shadow AI add-on)
  enterprise $249/mo — MSPs / Corporations         Unlimited, PQC, Sovereign AI Cloud, all add-ons included

Add-on SKUs (Lemon Squeezy variant IDs)
────────────────────────────────────────
  shadow_ai_discovery  +$15/mo  Pro+Enterprise   Shadow AI subnet scan + DNS telemetry
  xai_audit            +$9/mo   Individual+      Causal XAI HTML/PDF audit reports
  master_agent         +$20/mo  Pro only         MasterAgent multi-agent SOC (Enterprise: included)

Feature matrix
──────────────
  Feature                    starter   individual  pro       enterprise
  ─────────────────────────────────────────────────────────────────────────
  req_per_month              1 000     5 000       50 000    unlimited
  prompt_shield              ✓         ✓           ✓         ✓
  audit_trail                ✗         ✓           ✓         ✓
  secret_redactor            ✓         ✓           ✓         ✓
  multi_tenant               ✗         ✗           ✓ (≤50)   unlimited
  siem_integration           ✗         ✗           ✓         ✓
  prometheus_grafana         ✗         ✗           ✓         ✓
  gdpr_purge_api             ✗         ✗           ✓         ✓
  slack_pagerduty            ✗         ✗           ✓         ✓
  on_prem_deployment         ✗         ✗           ✗         ✓
  custom_ml_training         ✗         ✗           ✗         ✓
  white_label                ✗         ✗           ✗         ✓
  dedicated_support          ✗         ✗           ✗         ✓
  break_glass                ✗         ✗           ✗         ✓
  byok_enabled               ✗         ✗           ✗         ✓
  pqc_enabled                ✗         ✗           ✗         ✓
  master_agent_enabled       ✗         ✗           ✓         ✓
  shadow_ai_enabled          ✗         ✗           add-on    ✓
  xai_reports_enabled        ✗         add-on      ✓         ✓
  sovereign_enabled          ✗         ✗           ✗         ✓
  overage_enabled            ✗         ✗           ✓         ✓
  referral_program           ✓         ✓           ✓         ✗
  communities_enabled        ✗         ✗           ✓         ✓
  max_communities            0         0           10        unlimited
  max_members_per_community  0         0           25        unlimited

Overage pricing (cents per 1 000 excess requests)
───────────────────────────────────────────────────
  pro:        $0.50 per 1k requests over 50k
  enterprise: $0.10 per 1k requests over limit (custom SLA)

Usage
─────
  from warden.billing.feature_gate import FeatureGate, require_plan

  # In a route handler:
  gate = FeatureGate.for_tier("pro")
  gate.require("siem_integration")           # raises HTTP 403 if missing
  gate.require_capacity("max_communities", 3)

  # FastAPI Depends:
  @router.get("/siem/export")
  async def export(gate=Depends(require_plan("pro"))):
      ...
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, HTTPException, Request

log = logging.getLogger("warden.billing.feature_gate")

# ── Constants ─────────────────────────────────────────────────────────────────

_UNLIMITED = 2 ** 63
_K         = 1_000
_GB        = 1024 ** 3
_TB        = 1024 ** 4

# ── Overage pricing ───────────────────────────────────────────────────────────

OVERAGE_PRICES: dict[str, dict[str, Any]] = {
    "pro": {
        "cents_per_1k_requests":      50,   # $0.50 per 1k over limit
        "storage_cents_per_gb":        10,   # $0.10/GB
        "bandwidth_cents_per_gb":      10,
    },
    "enterprise": {
        "cents_per_1k_requests":      10,   # $0.10 per 1k (custom SLA)
        "storage_cents_per_gb":        4,
        "bandwidth_cents_per_gb":      4,
    },
    # Legacy aliases
    "business": {
        "cents_per_1k_requests":      50,
        "storage_cents_per_gb":       10,
        "bandwidth_cents_per_gb":     10,
        "pack_cents":                 500,
        "pack_bytes":                 50 * _GB,
    },
    "mcp": {
        "cents_per_1k_requests":      10,
        "storage_cents_per_gb":       4,
        "bandwidth_cents_per_gb":     4,
        "pack_cents":                 4000,
        "pack_bytes":                 1 * _TB,
    },
}

# ── Tier feature matrix ───────────────────────────────────────────────────────

TIER_LIMITS: dict[str, dict[str, Any]] = {

    "starter": {
        # ── Request quota ──────────────────────────────────────────────────────
        "req_per_month":               1_000,
        "overage_enabled":             False,
        # ── Core detection (always-on) ─────────────────────────────────────────
        "prompt_shield":               True,
        "secret_redactor":             True,
        "threat_vault":                True,
        "docker_self_host":            True,
        "totp_2fa":                    True,
        "openai_proxy":                True,
        # ── Gated features ─────────────────────────────────────────────────────
        "audit_trail":                 False,
        "multi_tenant":                False,
        "max_tenants":                 0,
        "siem_integration":            False,
        "prometheus_grafana":          False,
        "gdpr_purge_api":              False,
        "slack_pagerduty":             False,
        "on_prem_deployment":          False,
        "custom_ml_training":          False,
        "white_label":                 False,
        "dedicated_support":           False,
        "break_glass_enabled":         False,
        "byok_enabled":                False,
        "pqc_enabled":                 False,
        "master_agent_enabled":        False,
        "shadow_ai_enabled":           False,  # add-on only; not available at starter
        "xai_reports_enabled":         False,  # add-on only; not available at starter
        "sovereign_enabled":           False,
        "communities_enabled":         False,
        "max_communities":             0,
        "max_members_per_community":   0,
        # ── Referral ───────────────────────────────────────────────────────────
        "referral_program":            True,
        "referral_bonus_requests":     500,   # +500 req per referred signup
        "referral_bonus_bytes":        0,     # no storage bonus on starter
        # ── Storage (tunnel) ───────────────────────────────────────────────────
        "storage_bytes":               0,
        "bandwidth_bytes_per_month":   0,
        "max_entity_bytes":            0,
        "retention_days":              30,
        "ratchet_interval":            None,
    },

    "individual": {
        "req_per_month":               5_000,
        "overage_enabled":             False,
        "prompt_shield":               True,
        "secret_redactor":             True,
        "threat_vault":                True,
        "docker_self_host":            True,
        "totp_2fa":                    True,
        "openai_proxy":                True,
        "audit_trail":                 True,    # ← unlocked at Individual
        "multi_tenant":                False,
        "max_tenants":                 1,
        "siem_integration":            False,
        "prometheus_grafana":          False,
        "gdpr_purge_api":              False,
        "slack_pagerduty":             False,
        "on_prem_deployment":          False,
        "custom_ml_training":          False,
        "white_label":                 False,
        "dedicated_support":           False,
        "break_glass_enabled":         False,
        "byok_enabled":                False,
        "pqc_enabled":                 False,
        "master_agent_enabled":        False,
        "shadow_ai_enabled":           False,  # add-on only at individual tier
        "xai_reports_enabled":         False,  # add-on ($9/mo) unlocks at individual
        "sovereign_enabled":           False,
        "communities_enabled":         False,
        "max_communities":             0,
        "max_members_per_community":   0,
        "referral_program":            True,
        "referral_bonus_requests":     500,
        "referral_bonus_bytes":        1 * _GB,   # +1 GB per referred signup
        "storage_bytes":               10 * _GB,
        "bandwidth_bytes_per_month":   50 * _GB,
        "max_entity_bytes":            100 * 1024 * 1024,
        "retention_days":              90,
        "ratchet_interval":            None,
    },

    "pro": {
        "req_per_month":               50_000,
        "overage_enabled":             True,    # soft stop + charge
        "prompt_shield":               True,
        "secret_redactor":             True,
        "threat_vault":                True,
        "docker_self_host":            True,
        "totp_2fa":                    True,
        "openai_proxy":                True,
        "audit_trail":                 True,
        "multi_tenant":                True,    # ← unlocked at Pro
        "max_tenants":                 50,
        "siem_integration":            True,    # ← Splunk + Elastic
        "prometheus_grafana":          True,    # ← /metrics + Grafana dashboards
        "gdpr_purge_api":              True,    # ← DELETE /gdpr/purge
        "slack_pagerduty":             True,    # ← alert webhooks
        "on_prem_deployment":          False,
        "custom_ml_training":          False,
        "white_label":                 False,
        "dedicated_support":           False,
        "break_glass_enabled":         False,
        "byok_enabled":                False,
        "pqc_enabled":                 False,
        "master_agent_enabled":        True,    # ← MasterAgent SOC (+$20/mo, included in $69 Pro)
        "shadow_ai_enabled":           False,   # ← add-on: +$15/mo Shadow AI Discovery
        "xai_reports_enabled":         True,    # ← Causal XAI + PDF reports included at Pro
        "sovereign_enabled":           False,
        "communities_enabled":         True,    # ← Secure Communities
        "max_communities":             10,
        "max_members_per_community":   25,
        "referral_program":            True,
        "referral_bonus_requests":     2_000,
        "referral_bonus_bytes":        5 * _GB,   # +5 GB per referred signup
        "storage_bytes":               100 * _GB,
        "bandwidth_bytes_per_month":   500 * _GB,
        "max_entity_bytes":            1 * _GB,
        "retention_days":              365,
        "ratchet_interval":            10,
    },

    "enterprise": {
        "req_per_month":               None,    # unlimited
        "overage_enabled":             True,
        "prompt_shield":               True,
        "secret_redactor":             True,
        "threat_vault":                True,
        "docker_self_host":            True,
        "totp_2fa":                    True,
        "openai_proxy":                True,
        "audit_trail":                 True,
        "multi_tenant":                True,
        "max_tenants":                 _UNLIMITED,
        "siem_integration":            True,
        "prometheus_grafana":          True,
        "gdpr_purge_api":              True,
        "slack_pagerduty":             True,
        "on_prem_deployment":          True,    # ← Enterprise-only
        "custom_ml_training":          True,    # ← fine-tune threat corpus
        "white_label":                 True,    # ← rebrand + custom domain
        "dedicated_support":           True,    # ← SLA + named engineer
        "break_glass_enabled":         True,
        "byok_enabled":                True,    # ← Bring Your Own Key
        "pqc_enabled":                 True,    # ← Post-Quantum Cryptography (ML-DSA-65 + ML-KEM-768)
        "master_agent_enabled":        True,    # ← MasterAgent SOC (included at $249/mo)
        "shadow_ai_enabled":           True,    # ← Shadow AI Discovery (included at Enterprise)
        "xai_reports_enabled":         True,    # ← Causal XAI + PDF reports (included)
        "sovereign_enabled":           True,    # ← MASQUE Jurisdictional Tunnels (included)
        "communities_enabled":         True,
        "max_communities":             _UNLIMITED,
        "max_members_per_community":   _UNLIMITED,
        "referral_program":            False,   # Enterprise pays full price
        "referral_bonus_requests":     0,
        "referral_bonus_bytes":        0,
        "storage_bytes":               1 * _TB,
        "bandwidth_bytes_per_month":   5 * _TB,
        "max_entity_bytes":            5 * _GB,
        "retention_days":              -1,      # unlimited
        "ratchet_interval":            50,
    },
}

# ── Legacy aliases ─────────────────────────────────────────────────────────────
TIER_LIMITS["free"]     = TIER_LIMITS["starter"]
TIER_LIMITS["business"] = TIER_LIMITS["pro"]
TIER_LIMITS["msp"]      = TIER_LIMITS["enterprise"]
TIER_LIMITS["mcp"]      = TIER_LIMITS["enterprise"]   # legacy alias used in tests/quota

_TIER_ORDER: dict[str, int] = {
    "starter": 0, "free": 0,
    "individual": 1,
    "pro": 2, "business": 2,
    "enterprise": 3, "msp": 3, "mcp": 3,
}


def _normalize_tier(tier: str) -> str:
    t = tier.lower().strip()
    # Resolve legacy names to canonical names
    aliases = {"free": "starter", "business": "pro", "msp": "enterprise", "mcp": "enterprise"}
    t = aliases.get(t, t)
    return t if t in TIER_LIMITS else "starter"


# ── FeatureGate ───────────────────────────────────────────────────────────────

class FeatureGate:
    """
    Thin wrapper around TIER_LIMITS for a specific tenant tier.

    All guard methods raise PermissionError on failure — use them as
    guard clauses in route handlers or as FastAPI dependencies.
    """

    def __init__(self, tier: str) -> None:
        self.tier   = _normalize_tier(tier)
        self.limits = TIER_LIMITS[self.tier]

    @classmethod
    def for_tier(cls, tier: str) -> FeatureGate:
        return cls(tier)

    def get(self, feature: str) -> Any:
        """Return the raw limit value for *feature*."""
        if feature not in self.limits:
            raise KeyError(f"Unknown feature gate: {feature!r}")
        return self.limits[feature]

    def is_enabled(self, feature: str) -> bool:
        """Return True if boolean *feature* is enabled for this tier."""
        val = self.get(feature)
        if not isinstance(val, bool):
            raise TypeError(f"Feature {feature!r} is not boolean (value={val!r}).")
        return val

    def require(self, feature: str) -> None:
        """
        Assert boolean *feature* is enabled for this tier.
        Raises PermissionError with upgrade hint if not.
        """
        if not self.is_enabled(feature):
            min_tier = _min_tier_for(feature)
            raise PermissionError(
                f"Feature '{feature}' requires {min_tier.upper()} plan or higher. "
                f"Current plan: {self.tier.upper()}. "
                f"Upgrade at: /subscription/checkout?plan={min_tier}"
            )

    def require_capacity(self, feature: str, current_count: int) -> None:
        """
        Assert current_count < limit for *feature*.
        Raises PermissionError at capacity or when feature is disabled.
        """
        limit = self.get(feature)
        if limit == 0:
            min_tier = _min_tier_for_capacity(feature)
            raise PermissionError(
                f"Feature '{feature}' is not available on {self.tier.upper()} plan. "
                f"Upgrade to {min_tier.upper()} or higher."
            )
        if limit is not None and limit != _UNLIMITED and current_count >= limit:
            raise PermissionError(
                f"Capacity limit reached for '{feature}': "
                f"{current_count}/{limit} on {self.tier.upper()} plan. "
                f"Upgrade to Enterprise for unlimited capacity."
            )

    def meets_minimum(self, minimum_tier: str) -> bool:
        """Return True if this tier >= *minimum_tier*."""
        return _TIER_ORDER.get(self.tier, 0) >= _TIER_ORDER.get(
            _normalize_tier(minimum_tier), 0
        )

    def quota_req_per_month(self) -> int | None:
        """Return monthly request quota (None = unlimited)."""
        return self.limits.get("req_per_month")

    def as_dict(self) -> dict[str, Any]:
        """Return all limits as a serializable dict (for /billing/tiers endpoint)."""
        d = dict(self.limits)
        d["tier"] = self.tier
        d["overage_prices"] = OVERAGE_PRICES.get(self.tier, {})
        return d


def _min_tier_for(feature: str) -> str:
    """Return canonical tier name that first enables a boolean feature."""
    for tier in ("starter", "individual", "pro", "enterprise"):
        val = TIER_LIMITS[tier].get(feature)
        if isinstance(val, bool) and val:
            return tier
    return "enterprise"


def _min_tier_for_capacity(feature: str) -> str:
    """Return canonical tier that has non-zero capacity for *feature*."""
    for tier in ("starter", "individual", "pro", "enterprise"):
        val = TIER_LIMITS[tier].get(feature, 0)
        if val and val > 0:
            return tier
    return "enterprise"


# ── FastAPI dependencies ───────────────────────────────────────────────────────

def _get_tenant_tier(request: Request) -> str:
    """Extract plan tier from request state (set by auth middleware) or header."""
    state  = getattr(request, "state", None)
    tenant = getattr(state, "tenant", None)
    if isinstance(tenant, dict) and "tier" in tenant:
        return tenant["tier"]
    if isinstance(tenant, dict) and "plan" in tenant:
        return tenant["plan"]
    return request.headers.get("X-Tenant-Tier", "starter")


def require_plan(*plans: str):
    """
    FastAPI Depends factory: raise HTTP 403 if tenant plan is not in *plans*.

    Usage:
        @router.get("/siem/export", dependencies=[Depends(require_plan("pro", "enterprise"))])
    """
    canonical = {_normalize_tier(p) for p in plans}

    def dependency(request: Request) -> FeatureGate:
        tier = _normalize_tier(_get_tenant_tier(request))
        gate = FeatureGate.for_tier(tier)
        # Accept if tier meets any specified plan level
        if not any(gate.meets_minimum(p) for p in canonical):
            required = " or ".join(p.upper() for p in sorted(canonical))
            raise HTTPException(
                status_code=403,
                detail={
                    "error":        "plan_required",
                    "message":      f"This feature requires {required} plan.",
                    "current_plan": tier,
                    "upgrade_url":  f"/subscription/checkout?plan={min(canonical, key=lambda p: _TIER_ORDER.get(p, 0))}",
                },
            )
        return gate

    return Depends(dependency)


def require_feature(feature: str):
    """
    FastAPI Depends factory: raise HTTP 403 if *feature* is not enabled for tenant.

    Usage:
        @router.get("/gdpr/purge", dependencies=[Depends(require_feature("gdpr_purge_api"))])
    """
    def dependency(request: Request) -> FeatureGate:
        tier = _normalize_tier(_get_tenant_tier(request))
        gate = FeatureGate.for_tier(tier)
        try:
            gate.require(feature)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail={"error": "feature_gated", "message": str(exc)}) from exc
        return gate

    return Depends(dependency)


# ── FastAPI Middleware ─────────────────────────────────────────────────────────

_PLAN_ROUTES: dict[str, str] = {
    # route prefix → minimum plan required
    "/communities":       "pro",
    "/bots":              "pro",
    "/siem":              "pro",
    "/gdpr/purge":        "pro",
    "/communities/break": "enterprise",
    "/byok":              "enterprise",
    "/admin/ml-train":    "enterprise",
}


class FeatureGateMiddleware:
    """
    Starlette ASGI middleware enforcing plan gates on gated routes.
    Mount before route handlers: app.add_middleware(FeatureGateMiddleware)
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            path    = scope.get("path", "")
            headers = dict(scope.get("headers", []))
            tier    = _extract_tier_from_scope(scope, headers)
            gate    = FeatureGate.for_tier(tier)

            for prefix, min_plan in _PLAN_ROUTES.items():
                if path.startswith(prefix) and not gate.meets_minimum(min_plan):
                    await _send_403(
                        send,
                        f"Route {path!r} requires {min_plan.upper()} plan. "
                        f"Current plan: {tier.upper()}.",
                    )
                    return

        await self.app(scope, receive, send)


def _extract_tier_from_scope(scope: dict, headers: dict) -> str:
    state  = scope.get("state", {})
    tenant = getattr(state, "tenant", None) or (state if isinstance(state, dict) else None)
    if isinstance(tenant, dict) and (tenant.get("tier") or tenant.get("plan")):
        return tenant.get("tier") or tenant.get("plan")
    raw = headers.get(b"x-tenant-tier", b"starter").decode("utf-8", errors="ignore")
    return raw or "starter"


async def _send_403(send, detail: str) -> None:
    import json as _json
    body = _json.dumps({"detail": detail, "error": "plan_required"}).encode()
    await send({
        "type":    "http.response.start",
        "status":  403,
        "headers": [
            (b"content-type",   b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})
