"""
FinOps (Track C / FM-*) — cost rating + margin math.

Pure, deterministic pricing primitives shared by the Digital-Staff economics
tracker, the GSAM billing ledger, and the billing/overage subsystem. No I/O.
"""
from __future__ import annotations

from warden.finops.margin import (
    DEFAULT_FLOOR_MARGIN,
    MarginVerdict,
    RoutingDecision,
    evaluate_margin,
    margin_fraction,
    pick_model_within_margin,
    pricing_floor_usd,
    tier_revenue_per_request,
)
from warden.finops.rating import (
    CACHE_READ_DISCOUNT,
    PRICE_BOOK,
    CostBreakdown,
    blended_input_rate,
    price_for,
    rate_usage,
)
from warden.finops.wallet import (
    WalletComponents,
    available_usd,
    resolve_available_usd,
    resolve_wallet,
    spend_breakdown,
)

__all__ = [
    "CACHE_READ_DISCOUNT",
    "DEFAULT_FLOOR_MARGIN",
    "PRICE_BOOK",
    "CostBreakdown",
    "MarginVerdict",
    "RoutingDecision",
    "WalletComponents",
    "available_usd",
    "blended_input_rate",
    "evaluate_margin",
    "margin_fraction",
    "pick_model_within_margin",
    "price_for",
    "pricing_floor_usd",
    "rate_usage",
    "resolve_available_usd",
    "resolve_wallet",
    "spend_breakdown",
    "tier_revenue_per_request",
]
