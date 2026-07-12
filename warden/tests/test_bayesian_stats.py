"""Tests for warden/marketplace/bayesian_stats.py — Bayesian correlation test."""
from __future__ import annotations

import math

import pytest

from warden.marketplace.bayesian_stats import (
    correlation_credible_interval_95,
    fisher_z,
    posterior_p_correlation_exceeds,
)


class TestFisherZ:
    def test_zero_correlation(self):
        assert fisher_z(0.0) == pytest.approx(0.0)

    def test_monotonic_increasing(self):
        assert fisher_z(-0.5) < fisher_z(0.0) < fisher_z(0.5) < fisher_z(0.9)

    def test_clamps_near_singularity(self):
        # Should not raise or return inf for r at/beyond +-1
        assert math.isfinite(fisher_z(1.0))
        assert math.isfinite(fisher_z(-1.0))
        assert math.isfinite(fisher_z(1.5))
        assert math.isfinite(fisher_z(-1.5))


class TestPosteriorPCorrelationExceeds:
    def test_too_few_samples_returns_zero(self):
        assert posterior_p_correlation_exceeds(0.99, 3, 0.80) == 0.0
        assert posterior_p_correlation_exceeds(0.99, 0, 0.80) == 0.0

    def test_r_equals_rho0_gives_half(self):
        p = posterior_p_correlation_exceeds(0.80, 20, 0.80)
        assert p == pytest.approx(0.5, abs=1e-9)

    def test_r_above_rho0_exceeds_half(self):
        p = posterior_p_correlation_exceeds(0.95, 20, 0.80)
        assert p > 0.5

    def test_r_below_rho0_is_below_half(self):
        p = posterior_p_correlation_exceeds(0.50, 20, 0.80)
        assert p < 0.5

    def test_output_bounded_in_unit_interval(self):
        for r in (-0.99, -0.5, 0.0, 0.5, 0.8, 0.99):
            for n in (4, 5, 10, 50, 500):
                p = posterior_p_correlation_exceeds(r, n, 0.80)
                assert 0.0 <= p <= 1.0

    def test_more_data_increases_confidence_when_r_exceeds_rho0(self):
        """Same sample r above rho0: more observations -> higher posterior confidence."""
        p_thin = posterior_p_correlation_exceeds(0.90, 4, 0.80)
        p_thick = posterior_p_correlation_exceeds(0.90, 100, 0.80)
        assert p_thick > p_thin

    def test_thin_data_needs_higher_r_for_same_confidence(self):
        """A high sample r on n=4 should NOT reach the same confidence a lower r
        reaches on n=100 -- this is the core false-positive-reduction property."""
        p_thin_high_r = posterior_p_correlation_exceeds(0.85, 4, 0.80)
        p_thick_lower_r = posterior_p_correlation_exceeds(0.82, 100, 0.80)
        assert p_thick_lower_r > p_thin_high_r

    def test_matches_original_raw_threshold_direction_at_scale(self):
        """With ample data, high sample correlation confidently exceeds 0.80,
        recovering the old behavior's intent at scale."""
        p = posterior_p_correlation_exceeds(0.95, 200, 0.80)
        assert p > 0.99


class TestCredibleInterval95:
    def test_too_few_samples_returns_full_range(self):
        assert correlation_credible_interval_95(0.9, 3) == (-1.0, 1.0)

    def test_interval_contains_point_estimate(self):
        lo, hi = correlation_credible_interval_95(0.7, 30)
        assert lo <= 0.7 <= hi

    def test_interval_bounded_within_valid_correlation_range(self):
        lo, hi = correlation_credible_interval_95(0.99, 10)
        assert -1.0 <= lo <= hi <= 1.0

    def test_more_data_narrows_interval(self):
        lo_thin, hi_thin = correlation_credible_interval_95(0.7, 5)
        lo_thick, hi_thick = correlation_credible_interval_95(0.7, 500)
        assert (hi_thick - lo_thick) < (hi_thin - lo_thin)
