"""
warden/tests/test_finops_wallet.py  (FM-1)
Pure-math tests for the unified wallet availability formula + spend ordering.
"""
from __future__ import annotations

import pytest

from warden.finops.wallet import (
    WalletComponents,
    available_usd,
    spend_breakdown,
)

# ── available_usd ─────────────────────────────────────────────────────────────

class TestAvailableUsd:
    def test_all_components_sum_minus_hold(self):
        # 10 prepaid + 5 trial + 2 bonus − 3 hold = 14
        assert available_usd(10, 5, 2, 3) == pytest.approx(14.0)

    def test_hold_exceeding_funding_floors_to_zero(self):
        assert available_usd(1, 0, 0, 5) == 0.0

    def test_negative_grant_cannot_eat_prepaid(self):
        # a malformed −100 bonus must not reduce the real 10 prepaid
        assert available_usd(10, 0, -100, 0) == pytest.approx(10.0)

    def test_negative_hold_treated_as_zero(self):
        assert available_usd(10, 0, 0, -5) == pytest.approx(10.0)

    def test_micro_precision(self):
        assert available_usd(0.0000015, 0, 0, 0) == pytest.approx(round(0.0000015, 6))

    def test_empty_wallet_is_zero(self):
        assert available_usd(0, 0, 0, 0) == 0.0


# ── WalletComponents ──────────────────────────────────────────────────────────

class TestWalletComponents:
    def test_available_matches_formula(self):
        c = WalletComponents(prepaid_usd=10, trial_usd=5, bonus_usd=2, hold_usd=3)
        assert c.available_usd == pytest.approx(14.0)
        assert c.funding_usd == pytest.approx(17.0)
        assert c.is_funded is True

    def test_fully_held_is_not_funded(self):
        c = WalletComponents(prepaid_usd=5, trial_usd=0, bonus_usd=0, hold_usd=5)
        assert c.available_usd == 0.0
        assert c.is_funded is False

    def test_as_dict_shape(self):
        c = WalletComponents(1, 2, 3, 0)
        d = c.as_dict()
        assert set(d) == {
            "prepaid_usd", "trial_usd", "bonus_usd", "hold_usd",
            "funding_usd", "available_usd", "is_funded",
        }
        assert d["available_usd"] == pytest.approx(6.0)


# ── spend_breakdown: free money first ─────────────────────────────────────────

class TestSpendBreakdown:
    def test_draws_bonus_then_trial_then_prepaid(self):
        c = WalletComponents(prepaid_usd=10, trial_usd=5, bonus_usd=2, hold_usd=0)
        b = spend_breakdown(c, 8)
        # 2 bonus + 5 trial + 1 prepaid = 8; prepaid mostly preserved
        assert b["from_bonus_usd"] == pytest.approx(2.0)
        assert b["from_trial_usd"] == pytest.approx(5.0)
        assert b["from_prepaid_usd"] == pytest.approx(1.0)
        assert b["uncovered_usd"] == 0.0
        assert b["fully_covered"] is True

    def test_charge_within_bonus_leaves_prepaid_untouched(self):
        c = WalletComponents(prepaid_usd=10, trial_usd=5, bonus_usd=20, hold_usd=0)
        b = spend_breakdown(c, 3)
        assert b["from_bonus_usd"] == pytest.approx(3.0)
        assert b["from_trial_usd"] == 0.0
        assert b["from_prepaid_usd"] == 0.0

    def test_overcharge_reports_uncovered(self):
        c = WalletComponents(prepaid_usd=1, trial_usd=1, bonus_usd=1, hold_usd=0)
        b = spend_breakdown(c, 5)
        assert b["from_bonus_usd"] == pytest.approx(1.0)
        assert b["from_trial_usd"] == pytest.approx(1.0)
        assert b["from_prepaid_usd"] == pytest.approx(1.0)
        assert b["uncovered_usd"] == pytest.approx(2.0)
        assert b["fully_covered"] is False

    def test_zero_charge_covered_and_draws_nothing(self):
        c = WalletComponents(prepaid_usd=10, trial_usd=0, bonus_usd=0, hold_usd=0)
        b = spend_breakdown(c, 0)
        assert b["fully_covered"] is True
        assert b["from_prepaid_usd"] == 0.0


# ── resolve adapters: resilient to missing stores ─────────────────────────────

class TestResolveResilient:
    def test_resolve_wallet_never_raises(self, monkeypatch):
        # Force the preflight import to blow up → components resolve to zeros.
        import warden.finops.wallet as w

        def _boom(*a, **k):
            raise RuntimeError("no db")

        monkeypatch.setattr(w, "_grant_usd", lambda *a, **k: 0.0)
        # patch get_wallet lookup by making the import target raise
        import warden.sac.preflight as pf
        monkeypatch.setattr(pf, "get_wallet", _boom)

        c = w.resolve_wallet("tenant-x")
        assert c.available_usd == 0.0
        assert c.is_funded is False

    def test_resolve_composes_prepaid_and_grants(self, monkeypatch):
        import warden.finops.wallet as w
        import warden.sac.preflight as pf

        monkeypatch.setattr(pf, "get_wallet", lambda t: {"balance_usd": 12.0, "hold_usd": 2.0})
        monkeypatch.setattr(w, "_grant_usd", lambda tid, kind: {"trial": 3.0, "bonus": 1.0}[kind])

        c = w.resolve_wallet("tenant-y")
        # 12 prepaid + 3 trial + 1 bonus − 2 hold = 14
        assert c.available_usd == pytest.approx(14.0)
        assert w.resolve_available_usd("tenant-y") == pytest.approx(14.0)
