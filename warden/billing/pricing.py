"""
warden/billing/pricing.py
──────────────────────────
The canonical price list. One table, every surface derives from it.

Why this module exists
──────────────────────
List prices used to live in three places that silently drifted apart:

  * ``billing/router.py``      — what ``GET /billing/tiers`` serves the site
  * ``billing/feature_gate.py``— ``ANNUAL_PRICING``, the yearly checkout price
  * ``finops/margin.py``       — the revenue side of every margin decision

By 2026-08 they disagreed: Pro was $99.99/mo on the API and $69/mo in the
annual table, so the "15% off" annual plan actually sold a year of Pro for
$703 against a $1 199.88 list — a 41% discount nobody priced. The margin
engine, meanwhile, rated requests against whichever number its own copy held.

Rules
─────
  * ``TIER_PRICE_USD_MONTH`` is the ONLY place a list price is written down.
  * Annual prices are **derived** (``monthly × 12 × (1 − ANNUAL_DISCOUNT)``),
    never typed in — a hand-written annual price is how the drift started.
  * This module is pure data + arithmetic: no imports from the rest of warden,
    so any module (including ``finops``) can import it without a cycle.

Guarded by ``warden/tests/test_pricing_coherence.py``.
"""
from __future__ import annotations

from typing import Any

# ── Canonical monthly list price (USD) ────────────────────────────────────────
# 0.0 = free tier. A tier absent from this table has no list price (custom deal).

TIER_PRICE_USD_MONTH: dict[str, float] = {
    "trial":              0.0,
    "starter":            0.0,
    "individual":         5.0,
    "community_business": 39.99,
    "pro":                99.99,
    "enterprise":         249.0,
}

# Legacy tier names still accepted from stored subscriptions and old clients.
# Owned here so the price lookup and ``feature_gate._normalize_tier`` cannot
# disagree about what "business" means — a mismatch would price a tenant on one
# plan and gate them on another.
TIER_ALIASES: dict[str, str] = {
    "free":     "starter",
    "smb":      "community_business",
    "business": "pro",
    "msp":      "enterprise",
    "mcp":      "enterprise",
}


def canonical_tier(tier: str) -> str:
    """Resolve a tier name through the alias table (unknown names pass through)."""
    t = (tier or "").strip().lower()
    return TIER_ALIASES.get(t, t)


# Annual billing discount applied to 12 × the monthly list price.
ANNUAL_DISCOUNT: float = 0.15

# Gross-margin floor used to size the LLM cost allowance of a tier
# (see warden/finops/llm_budget.py). Kept here so "what we charge" and
# "what we may spend serving it" are one decision, not two.
TARGET_GROSS_MARGIN: float = 0.75


def monthly_price_usd(tier: str) -> float | None:
    """List price per month, or None for an unpriced/custom tier."""
    return TIER_PRICE_USD_MONTH.get(canonical_tier(tier))


def annual_price_usd(tier: str) -> float | None:
    """Derived yearly price. None for free or unpriced tiers."""
    monthly = monthly_price_usd(tier)
    if not monthly:
        return None
    return round(monthly * 12.0 * (1.0 - ANNUAL_DISCOUNT), 2)


def annual_plan(tier: str) -> dict[str, Any] | None:
    """Yearly plan as served to checkout and the pricing page."""
    yearly = annual_price_usd(tier)
    if yearly is None:
        return None
    return {
        "usd_per_year":             yearly,
        "usd_per_month_effective":  round(yearly / 12.0, 2),
        "discount":                 ANNUAL_DISCOUNT,
    }


# Prebuilt map for the paid tiers — what `feature_gate.ANNUAL_PRICING` exposes.
ANNUAL_PRICING: dict[str, dict[str, Any]] = {
    tier: plan
    for tier in TIER_PRICE_USD_MONTH
    if (plan := annual_plan(tier)) is not None
}
