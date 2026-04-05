"""
warden/billing/feature_gate.py
────────────────────────────────
Tier-based Feature Gating for v2.8 Business Communities.

Tiers
─────
  individual  $5/mo   — personal use; no Communities, no Multi-Sig
  business    $49/mo  — teams; Communities, Rotation, Multi-Sig (M=2)
  mcp         $199/mo — enterprise; everything + Break Glass, Bot_ID, BYOK

TIER_LIMITS
──────────────────────────────────────────────────────────────────
  Feature                     individual  business    mcp
  ─────────────────────────────────────────────────────────────────
  max_communities             0           5           unlimited
  max_members_per_community   0           100         unlimited
  max_bots_per_community      0           5           25
  communities_enabled         false       true        true
  multisig_enabled            false       true        true
  break_glass_enabled         false       false       true
  signal_ratchet_enabled      false       true        true
  ratchet_interval            N/A         10          50
  key_rotation_enabled        false       true        true
  byok_enabled                false       false       true

FeatureGate FastAPI Middleware
──────────────────────────────
  Intercepts requests to tier-gated routes (/communities/*, /bots/*) and
  returns HTTP 403 if the tenant's tier is insufficient.

  Tier is extracted from:
    1. request.state.tenant["tier"] (set by portal auth middleware)
    2. X-Tenant-Tier header (fallback for direct API calls)
    3. Default: "individual" (most restrictive)

Usage
─────
  # Direct gate check (in route handlers)
  from warden.billing.feature_gate import FeatureGate, TierLimit
  gate = FeatureGate.for_tier("business")
  gate.require("communities_enabled")           # raises PermissionError if False
  gate.require_capacity("max_communities", 3)   # raises PermissionError if 3 >= limit

  # Middleware (in app factory)
  from warden.billing.feature_gate import FeatureGateMiddleware
  app.add_middleware(FeatureGateMiddleware)
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

log = logging.getLogger("warden.billing.feature_gate")

# ── Tier limits definition ────────────────────────────────────────────────────

_UNLIMITED = 2 ** 31  # sentinel for "no hard cap"

TIER_LIMITS: dict[str, dict[str, Any]] = {
    "individual": {
        "max_communities":            0,
        "max_members_per_community":  0,
        "max_bots_per_community":     0,
        "communities_enabled":        False,
        "multisig_enabled":           False,
        "break_glass_enabled":        False,
        "signal_ratchet_enabled":     False,
        "ratchet_interval":           None,
        "key_rotation_enabled":       False,
        "byok_enabled":               False,
    },
    "business": {
        "max_communities":            5,
        "max_members_per_community":  100,
        "max_bots_per_community":     5,
        "communities_enabled":        True,
        "multisig_enabled":           True,
        "break_glass_enabled":        False,
        "signal_ratchet_enabled":     True,
        "ratchet_interval":           10,
        "key_rotation_enabled":       True,
        "byok_enabled":               False,
    },
    "mcp": {
        "max_communities":            _UNLIMITED,
        "max_members_per_community":  _UNLIMITED,
        "max_bots_per_community":     25,
        "communities_enabled":        True,
        "multisig_enabled":           True,
        "break_glass_enabled":        True,
        "signal_ratchet_enabled":     True,
        "ratchet_interval":           50,
        "key_rotation_enabled":       True,
        "byok_enabled":               True,
    },
}

# Tier ordering for inequality comparisons
_TIER_ORDER: dict[str, int] = {"individual": 0, "business": 1, "mcp": 2}


def _normalize_tier(tier: str) -> str:
    t = tier.lower().strip()
    return t if t in TIER_LIMITS else "individual"


# ── FeatureGate ────────────────────────────────────────────────────────────────

class FeatureGate:
    """
    Thin wrapper around TIER_LIMITS for a specific tenant tier.

    All methods raise PermissionError when a gate fails, so they can be
    used as guard clauses in route handlers without extra boilerplate.
    """

    def __init__(self, tier: str) -> None:
        self.tier   = _normalize_tier(tier)
        self.limits = TIER_LIMITS[self.tier]

    @classmethod
    def for_tier(cls, tier: str) -> "FeatureGate":
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
        Assert boolean *feature* is enabled.

        Raises PermissionError with a descriptive message if disabled.
        """
        if not self.is_enabled(feature):
            # Determine minimum tier that enables this feature
            min_tier = _min_tier_for(feature)
            raise PermissionError(
                f"Feature '{feature}' requires at least {min_tier.upper()} tier. "
                f"Current tier: {self.tier.upper()}."
            )

    def require_capacity(self, feature: str, current_count: int) -> None:
        """
        Assert that *current_count* < limit for *feature*.

        Raises PermissionError when the limit is reached (>= limit) or the
        feature is disabled (limit == 0).
        """
        limit = self.get(feature)
        if limit == 0:
            min_tier = _min_tier_for_capacity(feature)
            raise PermissionError(
                f"Feature '{feature}' is not available on {self.tier.upper()} tier. "
                f"Upgrade to {min_tier.upper()} or higher."
            )
        if limit != _UNLIMITED and current_count >= limit:
            raise PermissionError(
                f"Capacity limit reached for '{feature}': "
                f"{current_count}/{limit} on {self.tier.upper()} tier."
            )

    def meets_minimum(self, minimum_tier: str) -> bool:
        """Return True if this tier is >= *minimum_tier*."""
        return _TIER_ORDER.get(self.tier, 0) >= _TIER_ORDER.get(
            _normalize_tier(minimum_tier), 0
        )


def _min_tier_for(feature: str) -> str:
    """Return the minimum tier string that enables a boolean feature."""
    for tier in ("individual", "business", "mcp"):
        limits = TIER_LIMITS[tier]
        val = limits.get(feature)
        if isinstance(val, bool) and val:
            return tier
    return "mcp"


def _min_tier_for_capacity(feature: str) -> str:
    """Return the minimum tier that has non-zero capacity for *feature*."""
    for tier in ("individual", "business", "mcp"):
        if TIER_LIMITS[tier].get(feature, 0) > 0:
            return tier
    return "mcp"


# ── FastAPI Middleware ─────────────────────────────────────────────────────────

# Routes that require at minimum BUSINESS tier
_BUSINESS_ROUTES = (
    "/communities",
    "/bots",
)

# Routes that require MCP tier
_MCP_ROUTES = (
    "/communities/break-glass",
    "/communities/break_glass",
    "/byok",
)


class FeatureGateMiddleware:
    """
    Starlette/FastAPI ASGI middleware that enforces tier gates on
    Business Communities routes.

    Mount before route handlers:
        app.add_middleware(FeatureGateMiddleware)
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            path = scope.get("path", "")
            headers = dict(scope.get("headers", []))

            # Determine tier from request state or headers
            tier = _extract_tier_from_scope(scope, headers)
            gate = FeatureGate.for_tier(tier)

            # Check MCP-gated routes
            for mcp_route in _MCP_ROUTES:
                if path.startswith(mcp_route):
                    if not gate.meets_minimum("mcp"):
                        await _send_403(send, f"Route {path} requires MCP tier.")
                        return

            # Check Business-gated routes
            for biz_route in _BUSINESS_ROUTES:
                if path.startswith(biz_route):
                    if not gate.meets_minimum("business"):
                        await _send_403(send, f"Route {path} requires Business tier.")
                        return

        await self.app(scope, receive, send)


def _extract_tier_from_scope(scope: dict, headers: dict) -> str:
    """Extract tier from request.state or X-Tenant-Tier header."""
    # FastAPI sets state as an object in scope["state"]
    state = scope.get("state", {})
    tenant = getattr(state, "tenant", None) or (state if isinstance(state, dict) else {})
    if isinstance(tenant, dict) and "tier" in tenant:
        return tenant["tier"]
    # Fallback to raw header
    tier_header = headers.get(b"x-tenant-tier", b"individual").decode("utf-8", errors="ignore")
    return tier_header or "individual"


async def _send_403(send, detail: str) -> None:
    """Send a minimal HTTP 403 JSON response."""
    import json as _json
    body = _json.dumps({"detail": detail}).encode()
    await send({
        "type":    "http.response.start",
        "status":  403,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})
