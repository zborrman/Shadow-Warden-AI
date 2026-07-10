"""
GSAM drift math tests — pure functions, deterministic property checks.

Invariants: TV ∈ [0,1]; identical vectors → 0; disjoint → 1; EWMA bounded and
monotonic toward the target under a constant signal; baseline frozen while
drift ≥ threshold (poisoning resistance); anti-inflation clamp.
"""
from __future__ import annotations

from warden.gsam import drift as d


def test_total_variation_bounds_and_endpoints():
    assert d.total_variation({}, {}) == 0.0
    assert d.total_variation({"a": 1}, {"a": 1}) == 0.0
    assert abs(d.total_variation({"a": 1}, {"b": 1}) - 1.0) < 1e-9
    tv = d.total_variation({"a": 3, "b": 1}, {"a": 1, "b": 3})
    assert 0.0 <= tv <= 1.0


def test_total_variation_normalizes_raw_counts():
    # Scaling counts must not change the distance (it operates on distributions).
    a = d.total_variation({"a": 1, "b": 1}, {"a": 3, "b": 1})
    b = d.total_variation({"a": 10, "b": 10}, {"a": 30, "b": 10})
    assert abs(a - b) < 1e-9


def test_ewma_bounded_and_converges_upward():
    prev = 0.0
    for _ in range(200):
        prev = d.ewma_drift(prev, 1.0, 0.2)
        assert 0.0 <= prev <= 1.0
    assert prev > 0.99  # constant max signal drives EWMA toward 1


def test_ewma_converges_downward():
    prev = 1.0
    for _ in range(200):
        prev = d.ewma_drift(prev, 0.0, 0.2)
    assert prev < 0.01


def test_baseline_frozen_while_over_threshold():
    mu = {"get_health": 1.0}
    # drift above threshold → baseline must not move toward the anomalous vector.
    out = d.update_baseline(mu, {"exfiltrate": 1.0}, lam=0.5, drift=0.9, quarantine_threshold=0.85)
    assert out == d.normalize(mu)


def test_baseline_moves_when_healthy():
    mu = {"a": 1.0}
    out = d.update_baseline(mu, {"b": 1.0}, lam=0.5, drift=0.1, quarantine_threshold=0.85)
    assert out.get("b", 0.0) > 0.0  # baseline shifted toward new behaviour
    assert abs(sum(out.values()) - 1.0) < 1e-9  # stays a distribution


def test_first_observation_seeds_baseline():
    out = d.update_baseline({}, {"a": 2, "b": 2}, lam=0.2, drift=0.0, quarantine_threshold=0.85)
    assert out == {"a": 0.5, "b": 0.5}


def test_anti_inflation_clamp():
    assert d.anti_inflation_clamp(0.5, 1) == 0.0   # single counterpart → no gain
    assert d.anti_inflation_clamp(0.5, 2) == 0.5   # ≥2 distinct → allowed
    assert d.anti_inflation_clamp(-0.3, 0) == -0.3  # losses always apply
