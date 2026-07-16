"""
FinOps cost rating (FM-2) — the single source of truth for LLM token pricing.

The key correction over the old flat `input*rate + output*rate` model: prompt-
cache **read** hits are billed at a fraction of the base input rate. Anthropic's
usage object reports `input_tokens` (fresh) and `cache_read_input_tokens`
(cached) as **separate, additive** buckets — cached tokens are NOT included in
input_tokens — so we rate them as three independent buckets:

    total = input_tokens   * input_rate
          + output_tokens  * output_rate
          + cached_tokens  * input_rate * CACHE_READ_DISCOUNT

CACHE_READ_DISCOUNT = 0.10 → a cache read costs 10% of a fresh input token,
i.e. a 90% saving. All rates are USD per **million** tokens.

This module is pure (no DB, no clock, no env): the same inputs always rate to
the same cost, which is what makes billing auditable. Storage sums raw token
counts (see the GSAM billing ledger); rating is applied here at read time so the
price book lives in exactly one place.
"""
from __future__ import annotations

from dataclasses import dataclass

# Fraction of the base input rate charged for a prompt-cache read hit.
CACHE_READ_DISCOUNT: float = 0.10

# USD per million tokens, as of 2026-06. `input`/`output` only — the cache-read
# rate is derived (input * CACHE_READ_DISCOUNT) so it can never drift out of sync.
PRICE_BOOK: dict[str, dict[str, float]] = {
    "claude-haiku-4-5-20251001": {"input": 0.80,  "output": 4.00},
    "claude-sonnet-4-6":         {"input": 3.00,  "output": 15.00},
    "claude-opus-4-8":           {"input": 15.00, "output": 75.00},
}

# Fallback when a model id is unknown — Sonnet-tier, the middle of the range.
DEFAULT_RATES: dict[str, float] = {"input": 3.00, "output": 15.00}


def price_for(model: str) -> dict[str, float]:
    """Return {'input','output'} USD/MTok rates for a model (never raises)."""
    return PRICE_BOOK.get(model, DEFAULT_RATES)


def blended_input_rate(model: str, input_tokens: int, cached_tokens: int) -> float:
    """
    Effective USD/MTok paid across fresh + cached input for one call.

    Answers "given this cache hit ratio, what did an input token really cost?" —
    the number margin-aware routing (FM-3) compares against a pricing floor.
    Returns the full input rate when there are no input tokens at all.
    """
    rate = price_for(model)["input"]
    total = input_tokens + cached_tokens
    if total <= 0:
        return rate
    fresh = input_tokens * rate
    cached = cached_tokens * rate * CACHE_READ_DISCOUNT
    return (fresh + cached) / total


@dataclass(frozen=True)
class CostBreakdown:
    """Rated cost of one usage record, split by bucket (all USD)."""

    model: str
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    input_usd: float
    output_usd: float
    cache_usd: float
    total_usd: float
    cache_savings_usd: float  # what the cached tokens would have cost at full input rate, minus what they did


def rate_usage(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int = 0,
) -> CostBreakdown:
    """
    Rate one usage record. Negative token counts are clamped to zero so a
    malformed upstream usage object can never produce a negative bill.
    """
    input_tokens = max(0, int(input_tokens))
    output_tokens = max(0, int(output_tokens))
    cached_tokens = max(0, int(cached_tokens))

    rates = price_for(model)
    in_rate = rates["input"]
    out_rate = rates["output"]

    input_usd = input_tokens * in_rate / 1_000_000
    output_usd = output_tokens * out_rate / 1_000_000
    cache_usd = cached_tokens * in_rate * CACHE_READ_DISCOUNT / 1_000_000
    full_cache_usd = cached_tokens * in_rate / 1_000_000

    return CostBreakdown(
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached_tokens,
        input_usd=input_usd,
        output_usd=output_usd,
        cache_usd=cache_usd,
        total_usd=input_usd + output_usd + cache_usd,
        cache_savings_usd=full_cache_usd - cache_usd,
    )
