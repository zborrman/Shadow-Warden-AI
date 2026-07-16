"""
FinOps (Track C / FM-*) — cost rating + margin math.

Pure, deterministic pricing primitives shared by the Digital-Staff economics
tracker, the GSAM billing ledger, and the billing/overage subsystem. No I/O.
"""
from __future__ import annotations

from warden.finops.rating import (
    CACHE_READ_DISCOUNT,
    PRICE_BOOK,
    CostBreakdown,
    blended_input_rate,
    price_for,
    rate_usage,
)

__all__ = [
    "CACHE_READ_DISCOUNT",
    "PRICE_BOOK",
    "CostBreakdown",
    "blended_input_rate",
    "price_for",
    "rate_usage",
]
