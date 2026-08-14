"""
FT-2 slice 2d — dual-run reconciliation (`warden/finops/ledger_recon.py`).

End-to-end: with dual-write on, mirrored credit grants leave the ledger in exact
agreement with the counter (zero drift); an unmirrored change (dual-write off)
creates drift the job reports; and the job fail-softs rather than raising when a
source is unavailable — it observes, never blocks.

Fail-soft is not the same as clean, and the `evidence` assertions below are the
part that keeps those apart. The FT-2 read-cutover gate reads this report; a
report that cannot say whether it verified anything is a gate that can be
walked through backwards.
"""
from __future__ import annotations

import pytest

from warden.config import settings
from warden.finops import ledger_recon
from warden.ledger import journal
from warden.marketplace import credits
from warden.sac import preflight


@pytest.fixture
def wired(tmp_path, monkeypatch):
    # Isolate both the credits SQLite and the (frozen) ledger DB to tmp files, so
    # the mirror write and the recon read share one consistent ledger.
    monkeypatch.setattr(credits, "_DB_PATH", str(tmp_path / "mkt.db"))
    monkeypatch.setattr(journal, "_DB_PATH", str(tmp_path / "ledger.db"))
    monkeypatch.setattr(preflight.settings, "sac_wallet_db_path", str(tmp_path / "wallet.db"))
    monkeypatch.setattr(settings, "ledger_dual_write", True)


def test_no_drift_after_mirrored_grants(wired):
    credits.purchase_credits("t1", "credits_100")   # +100 credits, mirrored
    credits.purchase_credits("t2", "credits_500")   # +500 credits, mirrored
    rep = ledger_recon.credit_drift()
    assert rep["tenants_checked"] == 2
    assert rep["drifted"] == 0
    assert rep["ok"] is True
    assert rep["total_abs_drift_micros"] == 0


def test_detects_unmirrored_drift(wired, monkeypatch):
    credits.purchase_credits("t1", "credits_100")   # ledger + counter both 100
    # Deduct with dual-write OFF → counter drops to 95, ledger stays at 100.
    monkeypatch.setattr(settings, "ledger_dual_write", False)
    assert credits.deduct_credits("t1", 5) is True
    monkeypatch.setattr(settings, "ledger_dual_write", True)

    rep = ledger_recon.credit_drift()
    assert rep["drifted"] == 1
    assert rep["ok"] is False
    # ledger 100*1000 − counter 95*1000 = 5000 µUSD
    assert rep["details"][0]["tenant_id"] == "t1"
    assert rep["details"][0]["drift_micros"] == 5000
    assert rep["total_abs_drift_micros"] == 5000


def test_empty_says_nothing_to_check_not_agreement(wired):
    """No credit rows is a real state — but it is not evidence of agreement."""
    rep = ledger_recon.credit_drift()
    assert rep["evidence"] == ledger_recon.NOTHING_TO_CHECK
    assert rep["tenants_checked"] == 0
    assert rep["tenants_enumerated"] == 0
    assert rep["unreadable"] == 0
    assert rep["drifted"] == 0
    assert rep["ok"] is True  # narrow meaning: no drift *among what was checked*


def test_fail_soft_when_source_unavailable(wired, monkeypatch):
    """A dead source must not raise — and must not read as a clean night."""
    def _boom():
        raise RuntimeError("db down")
    monkeypatch.setattr(credits, "all_balances", _boom)
    rep = ledger_recon.credit_drift()   # must not raise
    assert rep["evidence"] == ledger_recon.NOT_AVAILABLE
    assert rep["tenants_checked"] == 0


def test_a_ledger_unreachable_for_every_tenant_cannot_pass_as_checked(wired, monkeypatch):
    """The forgeable gate, pinned.

    Reproduced against production on 2026-08-14: with `reconcile()` raising for
    every tenant, the old report read `{tenants_checked: 2, drifted: 0,
    ok: True}` — which is the documented read-cutover condition ("clean with
    tenants_checked > 0") satisfied while *nothing whatsoever* was verified.
    """
    credits.purchase_credits("t1", "credits_100")
    credits.purchase_credits("t2", "credits_500")

    from warden.ledger import dual_write

    def _boom(*a, **kw):
        raise RuntimeError("ledger unreachable")
    monkeypatch.setattr(dual_write, "reconcile", _boom)

    rep = ledger_recon.credit_drift()
    assert rep["tenants_checked"] == 0, "an unverified tenant must never count as checked"
    assert rep["tenants_enumerated"] == 2
    assert rep["unreadable"] == 2
    assert rep["evidence"] == ledger_recon.NOT_AVAILABLE
    assert ledger_recon.read_cutover_ready()["ready"] is False


def test_partial_failure_is_visible_even_when_the_rest_agrees(wired, monkeypatch):
    """One unreadable tenant among healthy ones must not hide behind them."""
    credits.purchase_credits("t1", "credits_100")
    credits.purchase_credits("t2", "credits_500")

    from warden.ledger import accounts, dual_write

    real = dual_write.reconcile
    doomed = accounts.tenant_credits("t2")

    def _selective(account, expected):
        if account == doomed:
            raise RuntimeError("ledger unreachable for t2")
        return real(account, expected)
    monkeypatch.setattr(dual_write, "reconcile", _selective)

    rep = ledger_recon.credit_drift()
    assert rep["tenants_checked"] == 1
    assert rep["unreadable"] == 1
    assert rep["drifted"] == 0
    assert rep["evidence"] == ledger_recon.COUNTED
    # ok is True — no drift was *found* — yet the cutover must still be blocked.
    assert rep["ok"] is True
    assert ledger_recon.read_cutover_ready()["ready"] is False


def test_all_balances_enumerates(wired):
    credits.purchase_credits("t1", "credits_100")
    credits.purchase_credits("t2", "credits_1000")
    balances = credits.all_balances()
    assert balances == {"t1": 100, "t2": 1000}


class TestHoldDrift:
    def test_no_drift_after_mirrored_reserve(self, wired):
        preflight.deposit("t1", 1.0)
        preflight.reserve("t1", 0.10)  # mirrored (dual-write on)

        rep = ledger_recon.hold_drift()
        assert rep["holds_checked"] == 1
        assert rep["drifted"] == 0
        assert rep["ok"] is True
        assert rep["total_abs_drift_micros"] == 0

    def test_detects_unmirrored_hold_drift(self, wired, monkeypatch):
        preflight.deposit("t1", 1.0)
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        hid = preflight.reserve("t1", 0.10)  # live hold created, never mirrored
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        rep = ledger_recon.hold_drift()
        assert rep["drifted"] == 1
        assert rep["ok"] is False
        assert rep["details"][0]["hold_id"] == hid
        assert rep["details"][0]["tenant_id"] == "t1"
        # ledger 0 − live 100_000 = -100_000 µUSD
        assert rep["details"][0]["drift_micros"] == -100_000
        assert rep["total_abs_drift_micros"] == 100_000

    def test_resolved_hold_self_clears_even_if_never_mirrored(self, wired, monkeypatch):
        preflight.deposit("t1", 1.0)
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        hid = preflight.reserve("t1", 0.10)  # never mirrored
        preflight.release(hid)               # resolved — out of scope now
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        rep = ledger_recon.hold_drift()
        assert rep["holds_checked"] == 0
        assert rep["drifted"] == 0
        assert rep["ok"] is True
        assert rep["evidence"] == ledger_recon.NOTHING_TO_CHECK

    def test_empty_says_nothing_to_check_not_agreement(self, wired):
        rep = ledger_recon.hold_drift()
        assert rep["evidence"] == ledger_recon.NOTHING_TO_CHECK
        assert rep["holds_checked"] == 0
        assert rep["holds_enumerated"] == 0
        assert rep["unreadable"] == 0

    def test_fail_soft_when_source_unavailable(self, wired, monkeypatch):
        def _boom():
            raise RuntimeError("db down")
        monkeypatch.setattr(preflight, "open_holds", _boom)
        rep = ledger_recon.hold_drift()  # must not raise
        assert rep["evidence"] == ledger_recon.NOT_AVAILABLE
        assert rep["holds_checked"] == 0

    def test_unreconcilable_hold_is_not_counted_as_checked(self, wired, monkeypatch):
        preflight.deposit("t1", 1.0)
        preflight.reserve("t1", 0.10)

        from warden.ledger import dual_write

        def _boom(*a, **kw):
            raise RuntimeError("ledger unreachable")
        monkeypatch.setattr(dual_write, "reconcile", _boom)

        rep = ledger_recon.hold_drift()
        assert rep["holds_checked"] == 0
        assert rep["holds_enumerated"] == 1
        assert rep["unreadable"] == 1
        assert rep["evidence"] == ledger_recon.NOT_AVAILABLE


class TestReadCutoverGate:
    """The FT-2 go/no-go, expressed as code rather than a roadmap sentence."""

    def test_not_ready_while_production_has_observed_nothing(self, wired):
        """Production's actual state since the flag went live on 2026-08-12."""
        gate = ledger_recon.read_cutover_ready()
        assert gate["ready"] is False
        assert "no positive evidence" in gate["reason"]

    def test_ready_once_real_tenants_reconcile_clean(self, wired):
        credits.purchase_credits("t1", "credits_100")
        credits.purchase_credits("t2", "credits_500")

        gate = ledger_recon.read_cutover_ready()
        assert gate["ready"] is True, gate["reason"]
        assert gate["credits"]["tenants_checked"] == 2
        assert gate["credits"]["evidence"] == ledger_recon.COUNTED

    def test_no_open_holds_does_not_block_a_ready_gate(self, wired):
        """open_holds() is an instantaneous snapshot — empty is normal."""
        credits.purchase_credits("t1", "credits_100")
        assert ledger_recon.hold_drift()["evidence"] == ledger_recon.NOTHING_TO_CHECK
        assert ledger_recon.read_cutover_ready()["ready"] is True

    def test_drift_blocks(self, wired, monkeypatch):
        credits.purchase_credits("t1", "credits_100")
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        credits.deduct_credits("t1", 5)
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        gate = ledger_recon.read_cutover_ready()
        assert gate["ready"] is False
        assert "drifted" in gate["reason"]
