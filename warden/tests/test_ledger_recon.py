"""
FT-2 slice 2d — dual-run reconciliation (`warden/finops/ledger_recon.py`).

End-to-end: with dual-write on, mirrored credit grants leave the ledger in exact
agreement with the counter (zero drift); an unmirrored change (dual-write off)
creates drift the job reports; and the job fail-soft-returns an ok summary when a
source is unavailable — it observes, never blocks.
"""
from __future__ import annotations

import pytest

from warden.config import settings
from warden.finops import ledger_recon
from warden.ledger import journal
from warden.marketplace import credits


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
