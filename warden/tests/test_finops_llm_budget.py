"""
Per-tenant LLM budget + soft model gate (FM-7).

The invariants that matter are the ones that protect the customer, not the
margin: the gate never blocks, never routes below the caller's declared floor,
never returns a model the caller did not offer, and fails open to the most
capable model on any internal fault.
"""
from __future__ import annotations

import pytest

from warden.billing.pricing import TARGET_GROSS_MARGIN, TIER_PRICE_USD_MONTH
from warden.finops import llm_budget as lb

_HAIKU  = "claude-haiku-4-5-20251001"
_SONNET = "claude-sonnet-4-6"
_OPUS   = "claude-opus-4-8"
_LADDER = [_HAIKU, _SONNET, _OPUS]


@pytest.fixture(autouse=True)
def _clear_cache():
    lb.invalidate_cache()
    yield
    lb.invalidate_cache()


def _spend(monkeypatch, usd: float) -> None:
    """Pin a tenant's month-to-date spend."""
    monkeypatch.setattr(lb, "mtd_spend_usd", lambda *_a, **_k: usd)


# ── Allowance derivation ──────────────────────────────────────────────────────

class TestTierBudget:
    def test_derived_from_price_and_target_margin(self):
        expected = round(TIER_PRICE_USD_MONTH["pro"] * (1.0 - TARGET_GROSS_MARGIN), 2)
        assert lb.tier_llm_budget_usd("pro") == expected

    def test_free_tier_gets_the_fixed_allowance(self):
        assert lb.tier_llm_budget_usd("starter") == lb.FREE_TIER_LLM_BUDGET_USD

    def test_enterprise_is_uncapped(self):
        assert lb.tier_llm_budget_usd("enterprise") is None

    def test_unknown_tier_is_uncapped_not_zero(self):
        """An unresolvable plan must not be throttled on a guess."""
        assert lb.tier_llm_budget_usd("") is None
        assert lb.tier_llm_budget_usd("mystery") is None

    def test_a_repricing_moves_the_allowance_with_it(self, monkeypatch):
        monkeypatch.setitem(TIER_PRICE_USD_MONTH, "pro", 200.0)
        assert lb.tier_llm_budget_usd("pro") == round(200.0 * (1.0 - TARGET_GROSS_MARGIN), 2)


# ── Budget status ─────────────────────────────────────────────────────────────

class TestBudgetStatus:
    def test_states_track_the_warn_line(self, monkeypatch):
        budget = lb.tier_llm_budget_usd("pro")
        assert budget is not None

        _spend(monkeypatch, budget * 0.10)
        assert lb.budget_status("t1", "pro").state == "ok"

        _spend(monkeypatch, budget * (lb.WARN_AT + 0.05))
        assert lb.budget_status("t1", "pro").state == "warn"

        _spend(monkeypatch, budget * 1.5)
        assert lb.budget_status("t1", "pro").state == "over"

    def test_remaining_never_goes_negative(self, monkeypatch):
        _spend(monkeypatch, 999.0)
        assert lb.budget_status("t1", "pro").remaining_usd == 0.0

    def test_uncapped_tier_reports_uncapped(self, monkeypatch):
        _spend(monkeypatch, 500.0)
        st = lb.budget_status("t1", "enterprise")
        assert st.state == "uncapped"
        assert st.budget_usd is None and st.pct_used is None


# ── The soft gate ─────────────────────────────────────────────────────────────

class TestChooseModel:
    def test_within_budget_serves_the_most_capable(self, monkeypatch):
        _spend(monkeypatch, 0.0)
        choice = lb.choose_model("t1", "pro", _LADDER)
        assert choice.model == _OPUS
        assert choice.downgraded is False
        assert choice.reason == "within_budget"

    def test_exhausted_budget_falls_to_the_caller_floor(self, monkeypatch):
        _spend(monkeypatch, 10_000.0)
        choice = lb.choose_model("t1", "pro", _LADDER)
        assert choice.model == _HAIKU
        assert choice.downgraded is True
        assert choice.reason == "budget_exhausted"

    def test_never_routes_below_the_declared_floor(self, monkeypatch):
        """candidates[0] is a capability floor, not a suggestion."""
        _spend(monkeypatch, 10_000.0)
        choice = lb.choose_model("t1", "pro", [_SONNET, _OPUS])
        assert choice.model == _SONNET

    def test_never_returns_a_model_outside_the_candidate_set(self, monkeypatch):
        for spent in (0.0, 5.0, 10_000.0):
            _spend(monkeypatch, spent)
            assert lb.choose_model("t1", "pro", _LADDER).model in _LADDER

    def test_warn_band_keeps_what_still_fits(self, monkeypatch):
        budget = lb.tier_llm_budget_usd("pro")
        assert budget is not None
        # 1% of the allowance left — enough for a Haiku call, not an Opus one.
        _spend(monkeypatch, budget * 0.99)
        choice = lb.choose_model("t1", "pro", _LADDER, 100_000, 20_000)
        assert choice.reason == "budget_warn"
        assert choice.model == _HAIKU

    def test_uncapped_tier_is_never_downgraded(self, monkeypatch):
        _spend(monkeypatch, 10_000.0)
        choice = lb.choose_model("t1", "enterprise", _LADDER)
        assert choice.model == _OPUS
        assert choice.reason == "uncapped"

    def test_resolves_to_the_most_capable_model_on_fault(self, monkeypatch):
        def _boom(*_a, **_k):
            raise RuntimeError("cost database is down")
        monkeypatch.setattr(lb, "budget_status", _boom)
        choice = lb.choose_model("t1", "pro", _LADDER)
        assert choice.model == _OPUS
        assert choice.reason == "budget_unavailable"

    def test_empty_candidates_is_a_programming_error(self):
        with pytest.raises(ValueError):
            lb.choose_model("t1", "pro", [])

    def test_cache_reads_lower_the_estimated_cost(self, monkeypatch):
        _spend(monkeypatch, 0.0)
        fresh  = lb.choose_model("t1", "pro", [_OPUS], 10_000, 0)
        cached = lb.choose_model("t1", "pro", [_OPUS], 1_000, 0, cached_tokens=9_000)
        assert cached.est_cost_usd < fresh.est_cost_usd


# ── Spend read + margin report ────────────────────────────────────────────────

class TestSpendAndReport:
    def test_spend_reads_as_zero_when_the_tracker_is_unavailable(self, monkeypatch):
        import warden.staff.economics as econ

        def _boom():
            raise RuntimeError("no db")
        monkeypatch.setattr(econ, "get_tracker", _boom)
        lb.invalidate_cache()
        assert lb.mtd_spend_usd("t-unavailable") == 0.0

    def test_margin_report_is_revenue_minus_inference(self, monkeypatch):
        _spend(monkeypatch, 10.0)
        rep = lb.margin_report("t1", "pro")
        assert rep["mrr_usd"] == TIER_PRICE_USD_MONTH["pro"]
        assert rep["llm_cost_mtd_usd"] == 10.0
        assert rep["gross_profit_usd"] == pytest.approx(TIER_PRICE_USD_MONTH["pro"] - 10.0)
        assert rep["gross_margin"] == pytest.approx(
            (TIER_PRICE_USD_MONTH["pro"] - 10.0) / TIER_PRICE_USD_MONTH["pro"],
            abs=1e-4,   # report values are rounded for display
        )

    def test_margin_report_handles_a_free_tenant(self, monkeypatch):
        _spend(monkeypatch, 0.25)
        rep = lb.margin_report("t1", "starter")
        assert rep["mrr_usd"] == 0.0
        assert rep["gross_margin"] is None       # no revenue to divide by

    def test_resolve_tier_is_uncapped_when_billing_is_unreachable(self, monkeypatch):
        monkeypatch.setattr(
            "warden.lemon_billing.get_lemon_billing",
            lambda: (_ for _ in ()).throw(RuntimeError("billing down")),
        )
        assert lb.resolve_tier("t1") == ""
        assert lb.tier_llm_budget_usd(lb.resolve_tier("t1")) is None
