"""
warden/tests/test_error_budget.py  (FM-5)
Pure-math tests for the SLA error-budget + multiwindow burn-rate module.
No I/O, no DB — the whole point is that the reliability signal is deterministic.
"""
from __future__ import annotations

import math

import pytest

import warden.reliability.budget as eb

# ── sla_for_tier ──────────────────────────────────────────────────────────────

class TestSlaForTier:
    def test_known_tiers(self):
        assert eb.sla_for_tier("pro") == 0.999
        assert eb.sla_for_tier("enterprise") == 0.9995

    def test_case_and_whitespace_insensitive(self):
        assert eb.sla_for_tier("  PRO ") == 0.999
        assert eb.sla_for_tier("Enterprise") == 0.9995

    def test_unknown_falls_back_to_default(self):
        assert eb.sla_for_tier("starter") == eb.DEFAULT_SLA
        assert eb.sla_for_tier("") == eb.DEFAULT_SLA
        assert eb.sla_for_tier(None) == eb.DEFAULT_SLA  # type: ignore[arg-type]


# ── error_budget ──────────────────────────────────────────────────────────────

class TestErrorBudget:
    def test_pro_allowed_downtime_is_43_8_min(self):
        b = eb.error_budget(100.0, sla_target=0.999, window_days=30)
        # (1 - 0.999) * 30 * 1440 = 43.2 min  (30-day month convention)
        assert b.allowed_downtime_min == pytest.approx(43.2, abs=0.01)
        assert b.observed_downtime_min == 0.0
        assert b.consumed_fraction == 0.0
        assert b.exhausted is False
        assert b.remaining_minutes == pytest.approx(43.2, abs=0.01)

    def test_enterprise_tighter_budget(self):
        b = eb.error_budget(100.0, sla_target=0.9995, window_days=30)
        assert b.allowed_downtime_min == pytest.approx(21.6, abs=0.01)

    def test_exactly_on_sla_spends_full_budget(self):
        b = eb.error_budget(99.9, sla_target=0.999, window_days=30)
        assert b.consumed_fraction == pytest.approx(1.0, abs=1e-6)
        assert b.remaining_minutes == pytest.approx(0.0, abs=0.01)
        assert b.exhausted is True

    def test_breach_goes_negative_and_over_100pct(self):
        b = eb.error_budget(99.0, sla_target=0.999, window_days=30)
        assert b.consumed_fraction > 1.0
        assert b.remaining_minutes < 0
        assert b.exhausted is True

    def test_half_budget_spent(self):
        # 99.95% uptime against a 99.9% SLA = half the error rate = half the budget
        b = eb.error_budget(99.95, sla_target=0.999, window_days=30)
        assert b.consumed_fraction == pytest.approx(0.5, abs=1e-3)

    def test_uptime_clamped_above_100(self):
        b = eb.error_budget(150.0, sla_target=0.999)
        assert b.observed_downtime_min == 0.0

    def test_nan_uptime_treated_as_zero(self):
        b = eb.error_budget(math.nan, sla_target=0.999)
        assert b.exhausted is True
        assert b.observed_downtime_min > 0

    def test_100pct_sla_leaves_no_budget(self):
        # A 100% target: any downtime is an infinite-consumption breach.
        b = eb.error_budget(99.9, sla_target=1.0, window_days=30)
        assert b.allowed_downtime_min == 0.0
        assert b.consumed_fraction == math.inf
        assert b.exhausted is True

    def test_100pct_sla_perfect_uptime_is_fine(self):
        b = eb.error_budget(100.0, sla_target=1.0)
        assert b.consumed_fraction == 0.0
        assert b.exhausted is True  # zero allowed, zero observed → boundary


# ── burn_rate ─────────────────────────────────────────────────────────────────

class TestBurnRate:
    def test_on_budget_is_one(self):
        # error rate exactly == budget rate → burn 1.0
        assert eb.burn_rate(99.9, sla_target=0.999) == pytest.approx(1.0, abs=1e-6)

    def test_perfect_uptime_is_zero(self):
        assert eb.burn_rate(100.0, sla_target=0.999) == 0.0

    def test_fast_burn_14_4(self):
        # 14.4x burn = error_rate 0.0144 → uptime 98.56%
        assert eb.burn_rate(98.56, sla_target=0.999) == pytest.approx(14.4, abs=0.05)

    def test_double_error_rate_double_burn(self):
        assert eb.burn_rate(99.8, sla_target=0.999) == pytest.approx(2.0, abs=1e-6)

    def test_zero_budget_sla_infinite_burn_on_error(self):
        assert eb.burn_rate(99.0, sla_target=1.0) == math.inf

    def test_zero_budget_sla_zero_burn_when_perfect(self):
        assert eb.burn_rate(100.0, sla_target=1.0) == 0.0


# ── evaluate_burn_alert ───────────────────────────────────────────────────────

class TestEvaluateBurnAlert:
    def test_fast_burn_pages(self):
        # Both 1h and 5m windows deep in fast-burn territory → page.
        alert = eb.evaluate_burn_alert({"1h": 90.0, "5m": 90.0}, sla_target=0.999)
        assert alert is not None
        assert alert.severity == "page"
        assert alert.burn_threshold == 14.4

    def test_single_window_burning_does_not_alert(self):
        # 5m is bad but 1h is healthy → a blip, not a sustained burn → no page.
        alert = eb.evaluate_burn_alert({"1h": 100.0, "5m": 90.0}, sla_target=0.999)
        assert alert is None

    def test_most_severe_tier_wins(self):
        # All windows fully down: the page tier (14.4) is returned, not ticket.
        windows = {"1h": 0.0, "5m": 0.0, "6h": 0.0, "30m": 0.0,
                   "1d": 0.0, "2h": 0.0, "3d": 0.0, "6h_": 0.0}
        alert = eb.evaluate_burn_alert(windows, sla_target=0.999)
        assert alert is not None
        assert alert.severity == "page"
        assert alert.long_window == "1h"

    def test_slow_burn_tickets(self):
        # ~4x burn: clears the 3.0 ticket threshold (1d/2h) but not the 6.0 page.
        # error_rate 0.004 → uptime 99.6%
        alert = eb.evaluate_burn_alert(
            {"1d": 99.6, "2h": 99.6}, sla_target=0.999
        )
        assert alert is not None
        assert alert.severity == "ticket"
        assert alert.burn_threshold == 3.0

    def test_missing_windows_skip_tier(self):
        # Only the 1d/2h pair present and healthy → nothing fires.
        alert = eb.evaluate_burn_alert({"1d": 100.0, "2h": 100.0}, sla_target=0.999)
        assert alert is None

    def test_healthy_returns_none(self):
        windows = {"1h": 100.0, "5m": 100.0, "6h": 99.999, "30m": 100.0}
        assert eb.evaluate_burn_alert(windows, sla_target=0.999) is None

    def test_empty_windows_returns_none(self):
        assert eb.evaluate_burn_alert({}, sla_target=0.999) is None
