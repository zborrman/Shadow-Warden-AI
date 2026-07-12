"""Tests for warden/brain/conformal.py — split-conformal threshold calibration."""
from __future__ import annotations

import math
import random

import pytest

from warden.brain.conformal import (
    empirical_false_positive_rate,
    split_conformal_threshold,
)


class TestSplitConformalThreshold:
    def test_empty_calibration_set_raises(self):
        with pytest.raises(ValueError):
            split_conformal_threshold([], 0.05)

    @pytest.mark.parametrize("epsilon", [0.0, 1.0, -0.1, 1.5])
    def test_epsilon_out_of_range_raises(self, epsilon):
        with pytest.raises(ValueError):
            split_conformal_threshold([0.1, 0.2, 0.3], epsilon)

    def test_threshold_is_one_of_calibration_scores_or_inf(self):
        scores = [0.1, 0.3, 0.5, 0.7, 0.9]
        t = split_conformal_threshold(scores, 0.2)
        assert t in scores or t == math.inf

    def test_stricter_epsilon_never_lowers_threshold(self):
        random.seed(42)
        scores = [random.random() for _ in range(200)]
        t_loose = split_conformal_threshold(scores, 0.20)
        t_strict = split_conformal_threshold(scores, 0.01)
        assert t_strict >= t_loose

    def test_realized_fpr_bounded_by_epsilon_on_large_sample(self):
        random.seed(7)
        scores = [random.random() for _ in range(1000)]
        epsilon = 0.05
        t = split_conformal_threshold(scores, epsilon)
        fpr = empirical_false_positive_rate(scores, t)
        assert fpr <= epsilon + 1e-9

    def test_too_few_samples_returns_inf(self):
        # n=1, epsilon=0.05: rank = ceil(2*0.95) = 2 > n=1 -> inf
        assert split_conformal_threshold([0.5], 0.05) == math.inf

    def test_single_sample_loose_epsilon(self):
        # n=1, epsilon=0.6: rank = ceil(2*0.4) = 1 <= n=1
        t = split_conformal_threshold([0.42], 0.6)
        assert t == 0.42

    def test_all_identical_scores(self):
        t = split_conformal_threshold([0.5] * 50, 0.1)
        assert t == 0.5

    def test_unsorted_input_same_result_as_sorted(self):
        scores = [0.9, 0.1, 0.5, 0.3, 0.7]
        assert split_conformal_threshold(scores, 0.3) == split_conformal_threshold(
            sorted(scores), 0.3
        )


class TestEmpiricalFalsePositiveRate:
    def test_empty_scores_returns_zero(self):
        assert empirical_false_positive_rate([], 0.5) == 0.0

    def test_all_below_threshold(self):
        assert empirical_false_positive_rate([0.1, 0.2, 0.3], 0.5) == 0.0

    def test_all_at_or_above_threshold(self):
        assert empirical_false_positive_rate([0.5, 0.6, 0.7], 0.5) == 1.0

    def test_half_above_threshold(self):
        assert empirical_false_positive_rate([0.1, 0.2, 0.6, 0.7], 0.5) == 0.5
