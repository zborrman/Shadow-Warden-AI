"""
warden/tests/test_finops_rating.py  (FM-2)
Pure-math tests for the FinOps cost-rating engine. No I/O — billing must be
deterministic and auditable.
"""
from __future__ import annotations

import pytest

from warden.finops.rating import (
    CACHE_READ_DISCOUNT,
    DEFAULT_RATES,
    PRICE_BOOK,
    blended_input_rate,
    price_for,
    rate_usage,
)

# ── price_for ─────────────────────────────────────────────────────────────────

class TestPriceFor:
    def test_known_model(self):
        assert price_for("claude-opus-4-8") == {"input": 15.0, "output": 75.0}

    def test_unknown_falls_back_to_default(self):
        assert price_for("who-dis") == DEFAULT_RATES

    def test_output_costs_more_than_input_everywhere(self):
        for model, rates in PRICE_BOOK.items():
            assert rates["output"] > rates["input"], model


# ── rate_usage: cache discount is the whole point ─────────────────────────────

class TestRateUsage:
    def test_no_cache_matches_flat_model(self):
        # cached_tokens defaults to 0 → old behaviour exactly.
        b = rate_usage("claude-opus-4-8", 1000, 500)
        assert b.total_usd == pytest.approx((1000 * 15.0 + 500 * 75.0) / 1e6)
        assert b.cache_usd == 0.0
        assert b.cache_savings_usd == 0.0

    def test_cache_read_billed_at_ten_percent(self):
        b = rate_usage("claude-opus-4-8", 0, 0, cached_tokens=1_000_000)
        # 1M cached tokens at 10% of $15/MTok = $1.50
        assert b.cache_usd == pytest.approx(1.50)
        assert b.total_usd == pytest.approx(1.50)

    def test_cache_savings_is_ninety_percent(self):
        b = rate_usage("claude-opus-4-8", 0, 0, cached_tokens=1_000_000)
        # would have paid $15 at full input rate; paid $1.50 → saved $13.50
        assert b.cache_savings_usd == pytest.approx(13.50)

    def test_buckets_are_additive(self):
        b = rate_usage("claude-sonnet-4-6", 1000, 500, cached_tokens=2000)
        expected = (
            1000 * 3.0
            + 500 * 15.0
            + 2000 * 3.0 * CACHE_READ_DISCOUNT
        ) / 1e6
        assert b.total_usd == pytest.approx(expected)
        assert b.input_usd + b.output_usd + b.cache_usd == pytest.approx(b.total_usd)

    def test_cache_is_cheaper_than_fresh_input(self):
        fresh = rate_usage("claude-opus-4-8", 1000, 0).total_usd
        cached = rate_usage("claude-opus-4-8", 0, 0, cached_tokens=1000).total_usd
        assert cached == pytest.approx(fresh * CACHE_READ_DISCOUNT)

    def test_zero_tokens_zero_cost(self):
        b = rate_usage("claude-opus-4-8", 0, 0, 0)
        assert b.total_usd == 0.0

    def test_negative_tokens_clamped(self):
        b = rate_usage("claude-opus-4-8", -100, -50, -10)
        assert b.total_usd == 0.0
        assert b.input_tokens == 0 and b.output_tokens == 0 and b.cached_tokens == 0

    def test_unknown_model_uses_default_rate(self):
        known = rate_usage("claude-sonnet-4-6", 1000, 500).total_usd
        unknown = rate_usage("mystery-model", 1000, 500).total_usd
        assert known == unknown


# ── blended_input_rate: the number FM-3 routing compares to a floor ───────────

class TestBlendedInputRate:
    def test_no_cache_is_full_rate(self):
        assert blended_input_rate("claude-opus-4-8", 1000, 0) == pytest.approx(15.0)

    def test_all_cache_is_discounted_rate(self):
        assert blended_input_rate("claude-opus-4-8", 0, 1000) == pytest.approx(1.5)

    def test_half_cache_is_midpoint(self):
        # 50% cache hit → (1.0 + 0.1)/2 * base = 0.55 * 15
        assert blended_input_rate("claude-opus-4-8", 500, 500) == pytest.approx(8.25)

    def test_no_tokens_returns_full_rate(self):
        assert blended_input_rate("claude-opus-4-8", 0, 0) == pytest.approx(15.0)


# ── economics delegates to rating (single price book) ─────────────────────────

class TestEconomicsDelegation:
    def test_compute_cost_usd_is_cache_aware(self):
        from warden.staff.economics import compute_cost_usd

        no_cache = compute_cost_usd("claude-opus-4-8", 1000, 500)
        with_cache = compute_cost_usd("claude-opus-4-8", 1000, 500, cached_tokens=1000)
        # adding cached tokens adds a small (discounted) cost, not zero
        assert with_cache > no_cache
        assert with_cache == pytest.approx(
            rate_usage("claude-opus-4-8", 1000, 500, 1000).total_usd
        )

    def test_two_arg_call_unchanged(self):
        from warden.staff.economics import compute_cost_usd

        assert compute_cost_usd("claude-opus-4-8", 1000, 500) == pytest.approx(
            (1000 * 15.0 + 500 * 75.0) / 1e6
        )
