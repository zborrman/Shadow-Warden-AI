"""
FT-2 slice 2c — sac/preflight.py mirrors its hold lifecycle into the ledger.

Verifies the WIRING: with dual-write on, reserve/commit/release call
operations.reserve/capture/void with the right accounts and µUSD amounts; with it
off (default) nothing is mirrored; and preflight's own behaviour and return values
are unchanged, even if a ledger op raises. (Ledger-side hold conservation itself
is covered by test_ledger_holds_rollup.py.)
"""
from __future__ import annotations

import pytest

from warden.config import settings
from warden.ledger import accounts, operations
from warden.ledger.money import Money
from warden.sac import preflight as p


@pytest.fixture
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(p.settings, "sac_wallet_db_path", str(tmp_path / "wallet.db"))


@pytest.fixture
def captured(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(operations, "reserve",
                        lambda *a, **k: calls.append(("reserve", *a)))
    monkeypatch.setattr(operations, "capture",
                        lambda *a, **k: calls.append(("capture", *a)))
    monkeypatch.setattr(operations, "void",
                        lambda *a, **k: calls.append(("void", *a)))
    return calls


@pytest.fixture
def dual_on(monkeypatch):
    monkeypatch.setattr(settings, "ledger_dual_write", True)


@pytest.fixture
def dual_off(monkeypatch):
    monkeypatch.setattr(settings, "ledger_dual_write", False)


class TestMirrorWhenEnabled:
    def test_reserve_mirrors(self, _db, captured, dual_on):
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)
        assert captured == [("reserve", hid, accounts.tenant_cash("t1"), Money.from_usd("0.10"))]

    def test_commit_mirrors_capped_at_held(self, _db, captured, dual_on):
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)
        captured.clear()
        p.commit(hid, 0.03)
        assert captured == [("capture", hid, accounts.platform_fees(), Money.from_usd("0.03"))]

    def test_commit_over_held_is_capped(self, _db, captured, dual_on):
        # held = $0.10, actual = $0.50 (balance allows it) → ledger capture caps at $0.10
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)
        captured.clear()
        p.commit(hid, 0.50)
        assert captured == [("capture", hid, accounts.platform_fees(), Money.from_usd("0.10"))]

    def test_release_mirrors_void(self, _db, captured, dual_on):
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)
        captured.clear()
        p.release(hid)
        assert captured == [("void", hid)]


class TestNoMirrorWhenDisabled:
    def test_reserve_commit_release_no_mirror(self, _db, captured, dual_off):
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)
        p.commit(hid, 0.03)
        hid2 = p.reserve("t1", 0.10)
        p.release(hid2)
        assert captured == []


class TestBehaviorNeutral:
    def test_wallet_accounting_unchanged(self, _db, dual_on):
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)
        assert p.get_wallet("t1")["net_usd"] == pytest.approx(0.90)
        res = p.commit(hid, 0.03)
        assert res["committed_usd"] == pytest.approx(0.03)
        assert res["released_usd"] == pytest.approx(0.07)

    def test_mirror_failure_never_breaks_preflight(self, _db, dual_on, monkeypatch):
        def _boom(*a, **k):
            raise RuntimeError("ledger down")
        monkeypatch.setattr(operations, "reserve", _boom)
        # reserve must still return a hold and reduce net despite the ledger error
        hid = p.reserve("t1", 0.10) if p.deposit("t1", 1.0) else None
        assert hid and hid.startswith("sac_hold_")
        assert p.get_wallet("t1")["hold_usd"] == pytest.approx(0.10)
