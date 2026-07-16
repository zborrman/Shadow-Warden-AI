"""
FinOps (Track C / FM-*) — cost rating + margin math.

Pure, deterministic pricing primitives shared by the Digital-Staff economics
tracker, the GSAM billing ledger, and the billing/overage subsystem. No I/O.
"""
from __future__ import annotations

from warden.finops.capacity import (
    CapacityCeiling,
    MemAudit,
    audit_mem_limits,
    capacity_ceiling,
    max_rps_for_latency,
    max_rps_for_utilization,
    mg1_response_seconds,
    mg1_wait_seconds,
    utilization,
)
from warden.finops.growth import (
    Funnel,
    FunnelStage,
    UnitEconomics,
    ViralCoefficient,
    arpa,
    build_funnel,
    logo_churn,
    ltv,
    ltv_cac_ratio,
    net_revenue_retention,
    payback_months,
    resolve_referral_k,
    unit_economics,
    viral_coefficient,
)
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
    "CapacityCeiling",
    "CostBreakdown",
    "Funnel",
    "FunnelStage",
    "MarginVerdict",
    "MemAudit",
    "RoutingDecision",
    "UnitEconomics",
    "ViralCoefficient",
    "WalletComponents",
    "arpa",
    "audit_mem_limits",
    "available_usd",
    "blended_input_rate",
    "build_funnel",
    "capacity_ceiling",
    "evaluate_margin",
    "logo_churn",
    "ltv",
    "ltv_cac_ratio",
    "margin_fraction",
    "max_rps_for_latency",
    "max_rps_for_utilization",
    "mg1_response_seconds",
    "mg1_wait_seconds",
    "net_revenue_retention",
    "payback_months",
    "pick_model_within_margin",
    "price_for",
    "pricing_floor_usd",
    "rate_usage",
    "resolve_available_usd",
    "resolve_referral_k",
    "resolve_wallet",
    "spend_breakdown",
    "tier_revenue_per_request",
    "unit_economics",
    "utilization",
    "viral_coefficient",
]
