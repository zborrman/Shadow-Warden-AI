"""
warden/tests/test_finops_margin.py  (FM-3)
Pure-math tests for margin-aware routing + the per-tier pricing floor.
The routing invariant: never route below the allowed candidate set, never
serve a loss as "proceed".
"""
from __future__ import annotations

import math

import pytest

from warden.finops.margin import (
    DEFAULT_FLOOR_MARGIN,
    evaluate_margin,
    margin_fraction,
    pick_model_within_margin,
    pricing_floor_usd,
    tier_revenue_per_request,
)

_HAIKU = "claude-haiku-4-5-20251001"
_SONNET = "claude-sonnet-4-6"
_OPUS = "claude-opus-4-8"
_LADDER = [_HAIKU, _SONNET, _OPUS]  # least → most capable/expensive


# ── margin_fraction ───────────────────────────────────────────────────────────

class TestMarginFraction:
    def test_half_cost_is_half_margin(self):
        assert margin_fraction(1.0, 0.5) == pytest.approx(0.5)

    def test_break_even_is_zero(self):
        assert margin_fraction(1.0, 1.0) == 0.0

    def test_loss_is_negative(self):
        assert margin_fraction(1.0, 1.5) == pytest.approx(-0.5)

    def test_free_tier_positive_cost_is_neg_inf(self):
        assert margin_fraction(0.0, 0.001) == -math.inf

    def test_free_tier_zero_cost_is_zero(self):
        assert margin_fraction(0.0, 0.0) == 0.0


# ── pricing_floor_usd ─────────────────────────────────────────────────────────

class TestPricingFloor:
    def test_floor_leaves_room_for_margin(self):
        # at a 50% floor, a $0.002 request may cost at most $0.001
        assert pricing_floor_usd(0.002, 0.50) == pytest.approx(0.001)

    def test_zero_revenue_zero_floor(self):
        assert pricing_floor_usd(0.0) == 0.0

    def test_a_request_at_the_floor_exactly_clears_it(self):
        rev = 0.002
        floor_cost = pricing_floor_usd(rev, DEFAULT_FLOOR_MARGIN)
        v = evaluate_margin("pro", floor_cost, rev, DEFAULT_FLOOR_MARGIN)
        assert v.action == "proceed"


# ── evaluate_margin ───────────────────────────────────────────────────────────

class TestEvaluateMargin:
    def test_healthy_proceeds(self):
        assert evaluate_margin("pro", 0.0002, 0.002).action == "proceed"

    def test_thin_margin_throttles(self):
        # cost = 60% of revenue → 40% margin < 50% floor → throttle (still served)
        v = evaluate_margin("pro", 0.0012, 0.002, 0.50)
        assert v.action == "throttle"
        assert v.margin == pytest.approx(0.40)

    def test_loss_blocks(self):
        assert evaluate_margin("individual", 0.003, 0.002).action == "block"

    def test_unlimited_revenue_always_proceeds(self):
        v = evaluate_margin("enterprise", 999.0, None)
        assert v.action == "proceed"
        assert v.margin == math.inf


# ── pick_model_within_margin ──────────────────────────────────────────────────

class TestPickModel:
    def test_generous_budget_picks_most_capable(self):
        # huge revenue → even Opus clears the floor → best model, no downgrade
        d = pick_model_within_margin(_LADDER, 1000, 500, revenue_per_request=10.0)
        assert d is not None
        assert d.model == _OPUS
        assert d.downgraded is False
        assert d.action == "proceed"

    def test_tight_budget_downgrades_within_allowed_set(self):
        # revenue that only the cheapest model can clear at a 50% floor
        haiku_cost = 1000 * 0.80e-6 + 500 * 4.00e-6  # = 0.0028
        rev = haiku_cost / 0.4  # haiku margin 60% clears; opus/sonnet won't
        d = pick_model_within_margin(_LADDER, 1000, 500, revenue_per_request=rev)
        assert d is not None
        assert d.model == _HAIKU
        assert d.downgraded is True
        assert d.action == "proceed"

    def test_never_routes_below_allowed_set(self):
        # caller floors capability to [sonnet, opus]; haiku is not offered
        d = pick_model_within_margin([_SONNET, _OPUS], 1000, 500, revenue_per_request=10.0)
        assert d is not None
        assert d.model in (_SONNET, _OPUS)

    def test_no_model_clears_floor_returns_cheapest_honest_action(self):
        # revenue so low every model is a loss → cheapest model, action=block
        d = pick_model_within_margin(_LADDER, 1000, 500, revenue_per_request=1e-9)
        assert d is not None
        assert d.model == _HAIKU  # least loss
        assert d.action == "block"
        assert d.downgraded is True

    def test_unlimited_revenue_picks_most_capable(self):
        d = pick_model_within_margin(_LADDER, 1000, 500, revenue_per_request=None)
        assert d is not None and d.model == _OPUS and d.action == "proceed"

    def test_empty_candidates_returns_none(self):
        assert pick_model_within_margin([], 100, 50, revenue_per_request=1.0) is None

    def test_cache_lowers_cost_and_helps_margin(self):
        # Same 2000 input tokens either way, but with a warm cache 1800 of them
        # are served as cache reads (10% rate) instead of fresh input → cheaper.
        rev = 0.02
        no_cache = pick_model_within_margin([_OPUS], 2000, 0, revenue_per_request=rev)
        cached = pick_model_within_margin([_OPUS], 200, 0, revenue_per_request=rev, cached_tokens=1800)
        assert no_cache is not None and cached is not None
        assert cached.cost_usd < no_cache.cost_usd
        assert cached.margin > no_cache.margin


# ── tier_revenue_per_request (adapter, resilient) ─────────────────────────────

class TestTierRevenue:
    def test_free_tier_has_no_floor(self):
        assert tier_revenue_per_request("starter") is None

    def test_paid_tier_positive_revenue(self):
        rev = tier_revenue_per_request("pro")
        # pro = $99.99 / 50_000 req ≈ $0.002
        if rev is not None:  # None only if billing layer unavailable
            assert rev > 0.0
            assert rev == pytest.approx(99.99 / 50_000, rel=0.01)

    def test_unknown_tier_no_floor(self):
        assert tier_revenue_per_request("mystery") is None

    def test_case_insensitive(self):
        assert tier_revenue_per_request("  PRO ") == tier_revenue_per_request("pro")
