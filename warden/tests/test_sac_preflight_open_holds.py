"""
FT-4 remainder — `sac/preflight.py::open_holds()`, the enumeration source for
hold reconciliation (`finops/ledger_recon.py::hold_drift()`).
"""
from __future__ import annotations

import pytest

from warden.sac import preflight as p


@pytest.fixture
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(p.settings, "sac_wallet_db_path", str(tmp_path / "wallet.db"))


class TestOpenHolds:
    def test_empty_when_no_holds(self, _db):
        assert p.open_holds() == []

    def test_lists_currently_held(self, _db):
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)
        holds = p.open_holds()
        assert holds == [{"hold_id": hid, "tenant_id": "t1", "amount_micros": 100_000}]

    def test_committed_hold_drops_out(self, _db):
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)
        p.commit(hid, 0.03)
        assert p.open_holds() == []

    def test_released_hold_drops_out(self, _db):
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)
        p.release(hid)
        assert p.open_holds() == []

    def test_multiple_tenants(self, _db):
        p.deposit("t1", 1.0)
        p.deposit("t2", 2.0)
        h1 = p.reserve("t1", 0.10)
        h2 = p.reserve("t2", 0.20)
        holds = {h["hold_id"]: h for h in p.open_holds()}
        assert holds[h1]["tenant_id"] == "t1"
        assert holds[h1]["amount_micros"] == 100_000
        assert holds[h2]["tenant_id"] == "t2"
        assert holds[h2]["amount_micros"] == 200_000
