"""
warden/tests/test_finops_growth.py  (FM-6)
Pure-math tests for growth accounting: funnel, viral coefficient K, unit economics.
"""
from __future__ import annotations

import math

import pytest

from warden.finops.growth import (
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

# ── funnel ────────────────────────────────────────────────────────────────────

class TestFunnel:
    def test_empty_funnel(self):
        f = build_funnel([])
        assert f.stages == ()
        assert f.overall_conversion == 0.0
        assert f.worst_leak is None

    def test_conversion_rates(self):
        f = build_funnel([("signup", 1000), ("first_filter", 600), ("trial", 300), ("paid", 90)])
        # first stage is the reference
        assert f.stages[0].conversion_from_prev == 1.0
        assert f.stages[0].conversion_from_top == 1.0
        assert f.stages[1].conversion_from_prev == pytest.approx(0.6)
        assert f.stages[2].conversion_from_prev == pytest.approx(0.5)
        assert f.stages[2].conversion_from_top == pytest.approx(0.3)
        assert f.overall_conversion == pytest.approx(0.09)

    def test_worst_leak_identified(self):
        # biggest drop is trial→paid (70% lost)
        f = build_funnel([("signup", 1000), ("first_filter", 900), ("trial", 800), ("paid", 240)])
        assert f.worst_leak == "paid"
        assert f.stages[-1].dropoff_from_prev == pytest.approx(0.70)

    def test_zero_upstream_no_blowup(self):
        f = build_funnel([("signup", 0), ("trial", 0), ("paid", 0)])
        assert f.overall_conversion == 0.0
        assert all(s.conversion_from_prev in (1.0, 0.0) for s in f.stages)

    def test_negative_counts_clamped(self):
        f = build_funnel([("signup", 100), ("trial", -5)])
        assert f.stages[1].count == 0

    def test_worst_leak_skips_first_stage(self):
        # single stage → no transition → no leak
        f = build_funnel([("signup", 500)])
        assert f.worst_leak is None
        assert f.overall_conversion == 1.0


# ── viral coefficient ─────────────────────────────────────────────────────────

class TestViralCoefficient:
    def test_factored_k(self):
        # 1000 users send 2000 invites (2/user), 50% accepted, 40% of those activate
        vc = viral_coefficient(cohort_size=1000, invites_sent=2000, accepted=1000, activated=400)
        assert vc.invites_per_user == pytest.approx(2.0)
        assert vc.acceptance_rate == pytest.approx(0.5)
        assert vc.activation_rate == pytest.approx(0.4)
        assert vc.k == pytest.approx(0.4)  # 2 * 0.5 * 0.4
        assert vc.verdict == "weak"

    def test_self_sustaining(self):
        vc = viral_coefficient(100, 200, 200, 150)
        assert vc.k >= 1.0
        assert vc.verdict == "self_sustaining"
        assert vc.amplification == math.inf

    def test_healthy_amplification(self):
        # K=0.5 → amplification 1/(1-0.5)=2.0
        vc = viral_coefficient(1000, 1000, 1000, 500)
        assert vc.k == pytest.approx(0.5)
        assert vc.verdict == "healthy"
        assert vc.amplification == pytest.approx(2.0)

    def test_dead_loop(self):
        vc = viral_coefficient(1000, 1000, 500, 50)
        assert vc.k < 0.2
        assert vc.verdict == "dead"
        assert vc.amplification == pytest.approx(1.0 / (1.0 - vc.k))

    def test_zero_cohort_no_blowup(self):
        vc = viral_coefficient(0, 0, 0, 0)
        assert vc.k == 0.0
        assert vc.verdict == "dead"
        assert vc.amplification == 1.0

    def test_negative_inputs_clamped(self):
        vc = viral_coefficient(-10, -5, -5, -5)
        assert vc.cohort_size == 0
        assert vc.k == 0.0


# ── unit economics primitives ─────────────────────────────────────────────────

class TestArpaChurn:
    def test_arpa(self):
        assert arpa(10000.0, 200) == pytest.approx(50.0)

    def test_arpa_zero_accounts(self):
        assert arpa(10000.0, 0) == 0.0

    def test_logo_churn(self):
        assert logo_churn(15, 300) == pytest.approx(0.05)

    def test_logo_churn_empty_base(self):
        assert logo_churn(5, 0) == 0.0


class TestNrr:
    def test_expansion_beats_churn(self):
        # 10000 start, +2000 expansion, -500 contraction, -1000 churn → 10500/10000
        assert net_revenue_retention(10000, 2000, 500, 1000) == pytest.approx(1.05)

    def test_pure_churn_below_one(self):
        assert net_revenue_retention(10000, 0, 0, 2000) == pytest.approx(0.8)

    def test_zero_start(self):
        assert net_revenue_retention(0, 100, 0, 0) == 0.0


class TestLtv:
    def test_ltv_formula(self):
        # ARPA 50, margin 0.8, churn 0.05 → 50*0.8/0.05 = 800
        assert ltv(50.0, 0.8, 0.05) == pytest.approx(800.0)

    def test_zero_churn_infinite(self):
        assert ltv(50.0, 0.8, 0.0) == math.inf

    def test_nonpositive_margin_zero(self):
        assert ltv(50.0, 0.0, 0.05) == 0.0
        assert ltv(50.0, -0.2, 0.05) == 0.0

    def test_ltv_cac_ratio(self):
        assert ltv_cac_ratio(800.0, 200.0) == pytest.approx(4.0)

    def test_ltv_cac_unknown_cac(self):
        assert ltv_cac_ratio(800.0, 0.0) is None

    def test_ltv_cac_infinite_ltv(self):
        assert ltv_cac_ratio(math.inf, 200.0) == math.inf


class TestPayback:
    def test_payback_months(self):
        # CAC 200, ARPA 50, margin 0.8 → monthly gross 40 → 5 months
        assert payback_months(200.0, 50.0, 0.8) == pytest.approx(5.0)

    def test_payback_unknown_cac(self):
        assert payback_months(0.0, 50.0, 0.8) is None

    def test_payback_no_gross_profit(self):
        assert payback_months(200.0, 50.0, 0.0) == math.inf


# ── unit economics bundle ─────────────────────────────────────────────────────

class TestUnitEconomics:
    def test_healthy_smb(self):
        ue = unit_economics(
            mrr_total=10000.0, active_accounts=200, gross_margin=0.8,
            starting_accounts=200, churned_accounts=10,
            starting_mrr=10000.0, expansion_mrr=1500.0, contraction_mrr=300.0, churned_mrr=500.0,
            cac_usd=150.0,
        )
        assert ue.arpa == pytest.approx(50.0)
        assert ue.monthly_logo_churn == pytest.approx(0.05)
        # LTV = 50*0.8/0.05 = 800; LTV:CAC = 800/150 ≈ 5.33; payback = 150/40 = 3.75mo
        assert ue.ltv == pytest.approx(800.0)
        assert ue.ltv_cac == pytest.approx(800.0 / 150.0)
        assert ue.payback_months == pytest.approx(3.75)
        assert ue.healthy is True

    def test_unknown_cac_not_healthy(self):
        ue = unit_economics(
            mrr_total=10000.0, active_accounts=200, gross_margin=0.8,
            starting_accounts=200, churned_accounts=10,
            starting_mrr=10000.0, expansion_mrr=1500.0, contraction_mrr=300.0, churned_mrr=500.0,
            cac_usd=None,
        )
        assert ue.cac is None
        assert ue.ltv_cac is None
        assert ue.payback_months is None
        assert ue.healthy is False

    def test_slow_payback_not_healthy(self):
        # high CAC → payback > 6 months even with good ratio-less economics
        ue = unit_economics(
            mrr_total=10000.0, active_accounts=200, gross_margin=0.8,
            starting_accounts=200, churned_accounts=10,
            starting_mrr=10000.0, expansion_mrr=0.0, contraction_mrr=0.0, churned_mrr=500.0,
            cac_usd=400.0,
        )
        # payback = 400/40 = 10 months > 6 → not healthy despite LTV:CAC=2
        assert ue.payback_months == pytest.approx(10.0)
        assert ue.healthy is False


# ── resilient adapter ─────────────────────────────────────────────────────────

class TestResolveReferralK:
    def test_reads_redemption_counters(self, monkeypatch):
        stats = {"t1": 30, "t2": 20}
        monkeypatch.setattr(
            "warden.billing.referral.get_referral_stats",
            lambda tid: {"total_referrals": stats.get(tid, 0)},
        )
        vc = resolve_referral_k(["t1", "t2"], cohort_size=100)
        # 50 redemptions / 100 cohort → reduced K = 0.5
        assert vc.activated == 50
        assert vc.k == pytest.approx(0.5)
        assert vc.verdict == "healthy"

    def test_bad_tenant_does_not_sink_read(self, monkeypatch):
        def flaky(tid):
            if tid == "bad":
                raise RuntimeError("redis down")
            return {"total_referrals": 10}
        monkeypatch.setattr("warden.billing.referral.get_referral_stats", flaky)
        vc = resolve_referral_k(["good", "bad", "good2"], cohort_size=100)
        assert vc.activated == 20  # two good tenants, bad one swallowed
        assert vc.k == pytest.approx(0.2)

    def test_empty_resolves_to_dead(self, monkeypatch):
        monkeypatch.setattr(
            "warden.billing.referral.get_referral_stats",
            lambda tid: {"total_referrals": 0},
        )
        vc = resolve_referral_k([], cohort_size=100)
        assert vc.k == 0.0
        assert vc.verdict == "dead"
