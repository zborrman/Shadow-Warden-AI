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

# ── Metered marketplace pricing ───────────────────────────────────────────────
# One marketplace search costs one credit. There are two ways to pay for it —
# a prepaid credit (no wallet needed) and an x402 nanopayment — and they must
# quote the SAME number. They did not: the x402 gate defaulted to $0.000001
# while a credit cost $0.001, a 1000x gap for identical work, so which rail an
# agent happened to use decided what the search was worth.
CREDIT_USD: float = 0.001
MARKETPLACE_SEARCH_FEE_USD: float = CREDIT_USD

# Metered price of one agent turn beyond a plan's included allowance
# (see AGENT_TURN_ALLOWANCE below). An Opus turn costs us about $0.12.
AGENT_TURN_OVERAGE_USD: float = 0.15

# Included agent turns per month, by tier. Sized from the tier's own LLM budget
# at Opus rates and rounded to a number a customer can reason about: "MasterAgent
# included" really means "this many Opus turns included", and leaving that
# implicit is how an unbounded cost gets sold as a feature.
#
# 0 means the agent surface is not sold on that tier at all. These must line up
# with `master_agent_enabled` in the feature gate — an allowance published for a
# tier that cannot call the agent is a promise the product does not keep.
AGENT_TURN_ALLOWANCE: dict[str, int | None] = {
    "trial":              0,      # the Pro trial explicitly excludes MasterAgent
    "starter":            0,
    "individual":         0,
    "community_business": 0,
    "pro":                200,
    "enterprise":         None,   # None = unlimited (negotiated)
}


def agent_turn_allowance(tier: str) -> int | None:
    """Included agent turns per month. None = unlimited; 0 = feature not sold."""
    return AGENT_TURN_ALLOWANCE.get(canonical_tier(tier), 0)


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


# ── M2M Store plans ───────────────────────────────────────────────────────────
# The shop is the primary product (owner decision, 2026-11-12) and until now it
# had no price, no limits and no row in this file: the whole ladder above sells
# gateway requests. These are the seller plans.
#
# STATUS: a pricing *hypothesis*, not a published price. Nothing can be charged
# (the capability matrix row "paid plans purchasable" is SIMULATED), no surface
# serves these numbers, and they are expected to move after the seller pilot.
# What is real today is the limit table: it is enforced on every store write.
#
# Same rules as the gateway ladder: one table, annual derived, never typed in.

STORE_PLAN_PRICE_USD_MONTH: dict[str, float] = {
    "store_free":     0.0,
    "store_seller":   15.0,
    "store_business": 39.0,
}

# What a plan may hold. Every key must appear on every plan, and the ladder must
# be monotone - a higher plan never allows less (test_store_plans.py asserts both).
#
# Deliberately NOT limited on any plan:
#   * order requests - a cap on orders punishes a seller for succeeding, and the
#     platform moves no money, so there is nothing to meter;
#   * photos per product - 8 everywhere (media.MAX_IMAGES_PER_PRODUCT); a thin
#     storefront sells nothing and makes the free plan a bad advertisement.
STORE_PLAN_LIMITS: dict[str, dict[str, int]] = {
    "store_free":     {"stores": 1, "products": 25,    "locales": 2},
    "store_seller":   {"stores": 1, "products": 500,   "locales": 5},
    "store_business": {"stores": 5, "products": 5_000, "locales": 5},
}

STORE_DEFAULT_PLAN: str = "store_free"

# One trial per tenant, ever: the paid plan, for a fixed window, no card.
STORE_TRIAL_PLAN: str = "store_seller"
STORE_TRIAL_DAYS: int = 14

# The free plan has no revenue to derive an allowance from, so its inference
# budget is a flat acquisition cost rather than a share of price.
STORE_FREE_AI_BUDGET_USD: float = 0.50


def store_plan_limits(plan: str) -> dict[str, int]:
    """A copy of the plan's limit table. Unknown plans get the default plan's."""
    return dict(STORE_PLAN_LIMITS.get(plan, STORE_PLAN_LIMITS[STORE_DEFAULT_PLAN]))


def store_annual_price_usd(plan: str) -> float | None:
    """Derived yearly price of a store plan. None for free or unknown plans."""
    monthly = STORE_PLAN_PRICE_USD_MONTH.get(plan)
    if not monthly:
        return None
    return round(monthly * 12.0 * (1.0 - ANNUAL_DISCOUNT), 2)


def store_ai_budget_usd(plan: str) -> float:
    """Monthly inference allowance of a store plan, in USD.

    Paid plans: ``price x (1 - TARGET_GROSS_MARGIN)`` - the same formula that
    sizes the gateway tiers, so "what we charge" and "what we may spend serving
    it" stay one decision. Free: a flat ``STORE_FREE_AI_BUDGET_USD``.
    """
    monthly = STORE_PLAN_PRICE_USD_MONTH.get(plan, 0.0)
    if not monthly:
        return STORE_FREE_AI_BUDGET_USD
    return round(monthly * (1.0 - TARGET_GROSS_MARGIN), 2)
