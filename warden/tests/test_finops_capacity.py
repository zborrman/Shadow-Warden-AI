"""
warden/tests/test_finops_capacity.py  (FM-4)
Pure-math tests for M/G/1 capacity ceilings + the container mem-limit audit.
"""
from __future__ import annotations

import math

import pytest

from warden.finops.capacity import (
    audit_mem_limits,
    capacity_ceiling,
    max_rps_for_latency,
    max_rps_for_utilization,
    mg1_response_seconds,
    mg1_wait_seconds,
    utilization,
)

# ── utilization ───────────────────────────────────────────────────────────────

class TestUtilization:
    def test_rho_is_lambda_times_service(self):
        assert utilization(50, 0.01) == pytest.approx(0.5)

    def test_negative_inputs_floored(self):
        assert utilization(-5, 0.01) == 0.0


# ── M/G/1 wait / response ─────────────────────────────────────────────────────

class TestMg1:
    def test_zero_load_no_wait(self):
        assert mg1_wait_seconds(0, 0.01) == 0.0
        assert mg1_response_seconds(0, 0.01) == pytest.approx(0.01)

    def test_unstable_queue_is_infinite(self):
        # ρ = 1.0 exactly → unstable
        assert mg1_wait_seconds(100, 0.01) == math.inf
        assert mg1_response_seconds(100, 0.01) == math.inf

    def test_mm1_matches_closed_form(self):
        # Cv²=1 (exponential) → M/M/1: Wq = ρ·E[S]/(1−ρ)
        lam, es = 50.0, 0.01  # ρ = 0.5
        expected_wq = 0.5 * es / (1 - 0.5)
        assert mg1_wait_seconds(lam, es, service_cv2=1.0) == pytest.approx(expected_wq)

    def test_deterministic_service_halves_mm1_wait(self):
        # Cv²=0 (M/D/1) → half the M/M/1 queue wait (P-K: (1+Cv²)/2 factor)
        lam, es = 50.0, 0.01
        wq_det = mg1_wait_seconds(lam, es, service_cv2=0.0)
        wq_exp = mg1_wait_seconds(lam, es, service_cv2=1.0)
        assert wq_det == pytest.approx(wq_exp / 2.0)

    def test_burstier_service_raises_wait(self):
        base = mg1_wait_seconds(50, 0.01, service_cv2=1.0)
        bursty = mg1_wait_seconds(50, 0.01, service_cv2=4.0)
        assert bursty > base

    def test_wait_grows_as_load_approaches_capacity(self):
        w_low = mg1_wait_seconds(50, 0.01)   # ρ=0.5
        w_high = mg1_wait_seconds(95, 0.01)  # ρ=0.95
        assert w_high > w_low * 5  # non-linear blow-up near ρ=1


# ── capacity ceilings ─────────────────────────────────────────────────────────

class TestMaxRps:
    def test_utilization_ceiling(self):
        # E[S]=0.01s, ρ_cap=0.8 → 80 rps
        assert max_rps_for_utilization(0.01, 0.80) == pytest.approx(80.0)

    def test_latency_ceiling_below_service_is_zero(self):
        # target below one service time → unachievable
        assert max_rps_for_latency(0.01, 0.005) == 0.0

    def test_latency_ceiling_solves_response_target(self):
        es, cv2, target = 0.01, 1.0, 0.05
        lam = max_rps_for_latency(es, target, cv2)
        # plugging λ* back in reproduces the target response
        assert mg1_response_seconds(lam, es, cv2) == pytest.approx(target, rel=1e-6)

    def test_latency_ceiling_never_exceeds_stability(self):
        # very loose target → bounded by 1/E[S]
        lam = max_rps_for_latency(0.01, 1000.0)
        assert lam < 1.0 / 0.01


class TestCapacityCeiling:
    def test_binding_ceiling_is_the_smaller(self):
        c = capacity_ceiling(mean_service_s=0.01, target_response_s=0.05, service_cv2=1.0, rho_cap=0.80)
        assert c.max_rps == min(c.max_rps_utilization, c.max_rps_latency)
        assert c.max_rps > 0

    def test_tight_latency_binds_before_utilization(self):
        # a strict latency target should bind below the 80% util ceiling
        c = capacity_ceiling(0.01, target_response_s=0.012, service_cv2=1.0, rho_cap=0.80)
        assert c.max_rps == c.max_rps_latency
        assert c.max_rps_latency < c.max_rps_utilization


# ── memory-limit audit ────────────────────────────────────────────────────────

class TestMemAudit:
    def test_within_budget_has_headroom(self):
        a = audit_mem_limits({"warden": 1024, "redis": 256, "postgres": 512},
                             node_ram_mb=4096, os_reserve_mb=512)
        # committed 1792 vs available 3584 → headroom 1792, not over
        assert a.committed_mb == pytest.approx(1792)
        assert a.available_mb == pytest.approx(3584)
        assert a.headroom_mb == pytest.approx(1792)
        assert a.over_committed is False

    def test_over_commit_flagged(self):
        a = audit_mem_limits({"a": 2048, "b": 2048, "c": 1024}, node_ram_mb=4096, os_reserve_mb=512)
        # committed 5120 > available 3584 → over-committed, negative headroom
        assert a.over_committed is True
        assert a.headroom_mb < 0

    def test_negative_limit_floored(self):
        a = audit_mem_limits({"a": -100, "b": 500}, node_ram_mb=4096)
        assert a.committed_mb == pytest.approx(500)
