"""
FinOps margin-aware routing + pricing floor (FM-3).

Turns the per-call cost from `warden.finops.rating` into a margin decision:

  * `margin_fraction(revenue, cost)` — gross margin of one served request.
  * `pricing_floor_usd(revenue, floor)` — the most a request may cost and still
    clear the tier's margin floor. This is the "per-tier pricing floor".
  * `evaluate_margin(...)` — proceed / throttle / block verdict for a given cost.
  * `pick_model_within_margin(...)` — of the models a caller is ALLOWED to use
    (already floored to the minimum capability the task needs), choose the most
    capable one that still clears the margin floor; downgrade only within that
    allowed set, never below it.

**Security invariant (Track C rule):** margin logic is additive and advisory —
it runs AFTER the fail-closed security gates and never selects a model the
caller did not already offer, never blocks a security-mandated action, and never
upgrades past a required capability. A thin margin never weakens a boundary.

Pure math (no I/O) except `tier_revenue_per_request`, an error-swallowing
adapter that reads the tier price + request quota from the billing layer.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass

from warden.finops.rating import rate_usage

log = logging.getLogger(__name__)

# Default gross-margin floor. Below this a request is "throttle" (still served,
# but flagged for routing/pricing review); at/below zero it is loss-making.
DEFAULT_FLOOR_MARGIN: float = 0.50

# Monthly list price per tier (USD). Canonical source is warden/billing/router.py;
# duplicated here as pure data so the margin math has no import cycle. Unlisted or
# unlimited-quota tiers resolve to "no floor" (custom / metered pricing).
_TIER_PRICE_USD_MONTH: dict[str, float] = {
    "trial": 0.0,
    "starter": 0.0,
    "individual": 5.0,
    "community_business": 39.99,
    "pro": 99.99,
    "enterprise": 249.0,
}

_ACTION_PROCEED = "proceed"
_ACTION_THROTTLE = "throttle"
_ACTION_BLOCK = "block"


def margin_fraction(revenue_per_request: float, cost_usd: float) -> float:
    """
    Gross margin of one request = (revenue - cost) / revenue.

    Free/zero-revenue requests: any positive cost is fully unfunded → -inf;
    zero cost → 0.0 (break-even, nothing earned, nothing spent).
    """
    if revenue_per_request <= 0.0:
        return -math.inf if cost_usd > 0.0 else 0.0
    return (revenue_per_request - cost_usd) / revenue_per_request


def pricing_floor_usd(revenue_per_request: float, floor_margin: float = DEFAULT_FLOOR_MARGIN) -> float:
    """Max per-request cost that still clears `floor_margin`. 0.0 for free tiers."""
    if revenue_per_request <= 0.0:
        return 0.0
    return revenue_per_request * (1.0 - floor_margin)


@dataclass(frozen=True)
class MarginVerdict:
    tier: str
    cost_usd: float
    revenue_per_request: float | None  # None = unlimited/custom-priced → no floor
    margin: float
    floor_margin: float
    action: str  # proceed | throttle | block


def evaluate_margin(
    tier: str,
    cost_usd: float,
    revenue_per_request: float | None,
    floor_margin: float = DEFAULT_FLOOR_MARGIN,
) -> MarginVerdict:
    """Classify one request's economics. `revenue_per_request=None` (unlimited /
    custom-priced, e.g. Enterprise) always proceeds — the floor does not apply."""
    if revenue_per_request is None:
        return MarginVerdict(tier, cost_usd, None, math.inf, floor_margin, _ACTION_PROCEED)

    margin = margin_fraction(revenue_per_request, cost_usd)
    if margin < 0.0:
        action = _ACTION_BLOCK
    elif margin < floor_margin:
        action = _ACTION_THROTTLE
    else:
        action = _ACTION_PROCEED
    return MarginVerdict(tier, cost_usd, revenue_per_request, margin, floor_margin, action)


@dataclass(frozen=True)
class RoutingDecision:
    model: str
    action: str          # proceed | throttle | block
    margin: float
    cost_usd: float
    downgraded: bool      # True if a cheaper-than-most-capable candidate was chosen


def pick_model_within_margin(
    candidates: list[str],
    input_tokens: int,
    output_tokens: int,
    revenue_per_request: float | None,
    cached_tokens: int = 0,
    floor_margin: float = DEFAULT_FLOOR_MARGIN,
) -> RoutingDecision | None:
    """
    `candidates` is the ALLOWED model set for this task, ordered least→most
    capable (typically also least→most expensive). The task's minimum capability
    is the caller's responsibility — this function never routes below it.

    Returns the MOST capable candidate whose margin clears `floor_margin`
    (best quality within budget). If none clears it, returns the cheapest
    candidate with the honest `evaluate_margin` action (throttle/block) so the
    caller can decide — we never silently serve a loss as "proceed".

    Returns None only for an empty candidate list.
    """
    if not candidates:
        return None

    costs = {m: rate_usage(m, input_tokens, output_tokens, cached_tokens).total_usd for m in candidates}
    most_capable = candidates[-1]

    # Unlimited / custom-priced: no floor — give the best model.
    if revenue_per_request is None:
        return RoutingDecision(most_capable, _ACTION_PROCEED, math.inf, costs[most_capable], downgraded=False)

    # Most capable downward: first that clears the floor.
    for model in reversed(candidates):
        v = evaluate_margin("", costs[model], revenue_per_request, floor_margin)
        if v.action == _ACTION_PROCEED:
            return RoutingDecision(model, _ACTION_PROCEED, v.margin, costs[model], downgraded=(model != most_capable))

    # None clears the floor → cheapest candidate, honest action.
    cheapest = min(candidates, key=lambda m: costs[m])
    v = evaluate_margin("", costs[cheapest], revenue_per_request, floor_margin)
    return RoutingDecision(cheapest, v.action, v.margin, costs[cheapest], downgraded=(cheapest != most_capable))


def tier_revenue_per_request(tier: str) -> float | None:
    """
    Authoritative revenue-per-request for a tier = monthly price / included
    request quota. Returns None for unlimited-quota / unpriced tiers (no floor).

    Resilient: any lookup error resolves to None (no floor) rather than raising.
    """
    try:
        price = _TIER_PRICE_USD_MONTH.get((tier or "").strip().lower())
        if price is None or price <= 0.0:
            return None  # free tier — no revenue to protect a margin against

        from warden.billing.feature_gate import FeatureGate  # noqa: PLC0415

        quota = FeatureGate.for_tier(tier).quota_req_per_month()
        if not quota or quota <= 0:
            return None  # unlimited or unknown quota → custom pricing, no floor
        return price / quota
    except Exception as exc:  # noqa: BLE001
        log.debug("tier_revenue_per_request lookup failed (no floor): %s", exc)
        return None
