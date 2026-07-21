"""
FT-2 slice 2d — dual-run reconciliation (`warden/finops/ledger_recon.py`).

End-to-end: with dual-write on, mirrored credit grants leave the ledger in exact
agreement with the counter (zero drift); an unmirrored change (dual-write off)
creates drift the job reports; and the job fail-soft-returns an ok summary when a
source is unavailable — it observes, never blocks.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from warden.config import settings
from warden.finops import ledger_recon
from warden.ledger import journal, operations
from warden.marketplace import credits
from warden.sac import preflight as p


@pytest.fixture
def wired(tmp_path, monkeypatch):
    # Isolate both the credits SQLite and the (frozen) ledger DB to tmp files, so
    # the mirror write and the recon read share one consistent ledger.
    monkeypatch.setattr(credits, "_DB_PATH", str(tmp_path / "mkt.db"))
    monkeypatch.setattr(journal, "_DB_PATH", str(tmp_path / "ledger.db"))
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


def test_empty_is_ok_by_vacuity(wired):
    rep = ledger_recon.credit_drift()
    assert rep == {
        "tenants_checked": 0, "drifted": 0,
        "total_abs_drift_micros": 0, "ok": True, "details": [],
    }


def test_fail_soft_when_source_unavailable(wired, monkeypatch):
    def _boom():
        raise RuntimeError("db down")
    monkeypatch.setattr(credits, "all_balances", _boom)
    rep = ledger_recon.credit_drift()   # must not raise
    assert rep["ok"] is True
    assert rep["tenants_checked"] == 0


def test_all_balances_enumerates(wired):
    credits.purchase_credits("t1", "credits_100")
    credits.purchase_credits("t2", "credits_1000")
    balances = credits.all_balances()
    assert balances == {"t1": 100, "t2": 1000}


# ── FT-4 remainder — holds_drift() ────────────────────────────────────────────
# Same physical-DB isolation trick as `wired`, plus the sac_wallet DB (live hold
# state machine) pointed at its own tmp file. `journal._DB_PATH` doubles as the
# ledger-side holds DB (warden/ledger/holds.py shares the journal's db_key).

@pytest.fixture
def wired_holds(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "sac_wallet_db_path", str(tmp_path / "wallet.db"))
    monkeypatch.setattr(journal, "_DB_PATH", str(tmp_path / "ledger.db"))
    monkeypatch.setattr(settings, "ledger_dual_write", True)
    monkeypatch.setattr(settings, "ledger_holds_recon_cutoff_ts", "1970-01-01T00:00:00+00:00")


class TestHoldsDrift:
    def test_no_mismatch_after_mirrored_reserve(self, wired_holds):
        p.deposit("t1", 1.0)
        p.reserve("t1", 0.10)
        rep = ledger_recon.holds_drift()
        assert rep == {"holds_checked": 1, "mismatched": 0, "ok": True, "details": []}

    def test_missing_in_ledger_when_mirror_never_ran(self, wired_holds, monkeypatch):
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)  # live-only, no ledger mirror at all
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        rep = ledger_recon.holds_drift()
        assert rep["ok"] is False
        assert rep["mismatched"] == 1
        assert rep["details"][0] == {
            "hold_id": hid, "tenant_id": "t1",
            "issue": "missing_in_ledger", "live_status": "HELD",
        }

    def test_status_mismatch_when_release_mirror_fails(self, wired_holds, monkeypatch):
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)  # mirrors fine → ledger HELD

        def _boom(*a, **k):
            raise RuntimeError("ledger down")
        monkeypatch.setattr(operations, "void", _boom)
        p.release(hid)  # live → RELEASED; mirror raises, swallowed → ledger stays HELD

        rep = ledger_recon.holds_drift()
        assert rep["ok"] is False
        assert rep["details"][0] == {
            "hold_id": hid, "tenant_id": "t1", "issue": "status_mismatch",
            "live_status": "RELEASED", "ledger_status": "HELD",
        }

    def test_holds_before_cutoff_are_excluded(self, wired_holds, monkeypatch):
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        p.deposit("t1", 1.0)
        p.reserve("t1", 0.10)  # live-only — would be a mismatch if in scope
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        # Cutoff set after the hold's created_at → excluded from recon entirely.
        future = datetime.now(UTC).replace(year=2999).isoformat()
        monkeypatch.setattr(settings, "ledger_holds_recon_cutoff_ts", future)

        rep = ledger_recon.holds_drift()
        assert rep == {"holds_checked": 0, "mismatched": 0, "ok": True, "details": []}

    def test_unset_cutoff_is_a_noop(self, wired_holds, monkeypatch):
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        p.deposit("t1", 1.0)
        p.reserve("t1", 0.10)  # would be a mismatch if checked
        monkeypatch.setattr(settings, "ledger_holds_recon_cutoff_ts", "")

        rep = ledger_recon.holds_drift()
        assert rep == {"holds_checked": 0, "mismatched": 0, "ok": True, "details": []}

    def test_fail_soft_when_source_unavailable(self, wired_holds, monkeypatch):
        def _boom(_cutoff):
            raise RuntimeError("db down")
        monkeypatch.setattr(p, "list_holds_since", _boom)
        rep = ledger_recon.holds_drift()  # must not raise
        assert rep == {"holds_checked": 0, "mismatched": 0, "ok": True, "details": []}
