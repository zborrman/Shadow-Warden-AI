"""
SAC two-phase preflight billing (reserve → commit / release) tests.

Covers: deposit, reserve/net accounting, commit (charges actual, releases
remainder, never overdraws), release, insufficient funds, and hold-state
guards (unknown/already-resolved holds).
"""
from __future__ import annotations

import pytest

from warden.sac import preflight as p


@pytest.fixture
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(p.settings, "sac_wallet_db_path", str(tmp_path / "wallet.db"))
    yield


def test_deposit_and_get_wallet(_db):
    w = p.deposit("t1", 5.0)
    assert w == {"tenant_id": "t1", "balance_usd": 5.0, "hold_usd": 0.0, "net_usd": 5.0}


def test_deposit_rejects_non_positive(_db):
    with pytest.raises(ValueError):
        p.deposit("t1", 0)
    with pytest.raises(ValueError):
        p.deposit("t1", -1)


def test_reserve_holds_and_reduces_net(_db):
    p.deposit("t1", 1.0)
    hold_id = p.reserve("t1", 0.10)
    w = p.get_wallet("t1")
    assert w["hold_usd"] == pytest.approx(0.10)
    assert w["net_usd"] == pytest.approx(0.90)
    assert hold_id.startswith("sac_hold_")


def test_reserve_insufficient_funds(_db):
    p.deposit("t1", 0.05)
    with pytest.raises(p.InsufficientFundsError):
        p.reserve("t1", 1.00)
    # Failed reservation must not have moved the hold.
    assert p.get_wallet("t1")["hold_usd"] == 0.0


def test_commit_charges_actual_and_releases_remainder(_db):
    p.deposit("t1", 1.0)
    hold_id = p.reserve("t1", 0.10)
    out = p.commit(hold_id, 0.03)
    assert out["committed_usd"] == pytest.approx(0.03)
    assert out["released_usd"] == pytest.approx(0.07)
    w = p.get_wallet("t1")
    assert w["balance_usd"] == pytest.approx(0.97)
    assert w["hold_usd"] == 0.0


def test_commit_never_overdraws_balance(_db):
    p.deposit("t1", 0.10)
    hold_id = p.reserve("t1", 0.10)
    # Actual cost reported higher than the whole balance — must clamp, not go negative.
    out = p.commit(hold_id, 5.00)
    assert out["committed_usd"] == pytest.approx(0.10)
    assert p.get_wallet("t1")["balance_usd"] == 0.0


def test_release_refunds_hold_without_charging(_db):
    p.deposit("t1", 1.0)
    hold_id = p.reserve("t1", 0.20)
    out = p.release(hold_id)
    assert out["released_usd"] == pytest.approx(0.20)
    w = p.get_wallet("t1")
    assert w["balance_usd"] == pytest.approx(1.0)
    assert w["hold_usd"] == 0.0


def test_double_settle_rejected(_db):
    p.deposit("t1", 1.0)
    hold_id = p.reserve("t1", 0.10)
    p.commit(hold_id, 0.05)
    with pytest.raises(p.HoldError, match="already committed"):
        p.commit(hold_id, 0.01)
    with pytest.raises(p.HoldError, match="already committed"):
        p.release(hold_id)


def test_unknown_hold_rejected(_db):
    with pytest.raises(p.HoldError, match="not found"):
        p.commit("sac_hold_doesnotexist", 0.01)
    with pytest.raises(p.HoldError, match="not found"):
        p.release("sac_hold_doesnotexist")


def test_wallets_are_per_tenant(_db):
    p.deposit("t1", 1.0)
    p.deposit("t2", 2.0)
    assert p.get_wallet("t1")["balance_usd"] == 1.0
    assert p.get_wallet("t2")["balance_usd"] == 2.0


def test_recent_agent_cost_usd_fail_open_without_gsam(_db):
    # No GSAM rollup data present — must return 0.0, never raise.
    assert p.recent_agent_cost_usd("no-such-agent") == 0.0


def test_cross_tenant_commit_rejected(_db):
    """A hold_id belonging to tenant A must not be settleable by tenant B —
    prevents cross-tenant financial manipulation via a guessed/observed id."""
    p.deposit("tenant-a", 1.0)
    hold_id = p.reserve("tenant-a", 0.10, agent_id="bdr")
    with pytest.raises(p.HoldError, match="not found"):
        p.commit(hold_id, 0.05, expected_tenant_id="tenant-b")
    # The hold must remain untouched — still resolvable by its real owner.
    out = p.commit(hold_id, 0.05, expected_tenant_id="tenant-a")
    assert out["committed_usd"] == pytest.approx(0.05)


def test_cross_tenant_release_rejected(_db):
    p.deposit("tenant-a", 1.0)
    hold_id = p.reserve("tenant-a", 0.10)
    with pytest.raises(p.HoldError, match="not found"):
        p.release(hold_id, expected_tenant_id="tenant-b")
    out = p.release(hold_id, expected_tenant_id="tenant-a")
    assert out["released_usd"] == pytest.approx(0.10)


def test_no_expected_tenant_id_skips_ownership_check(_db):
    """Internal callers (e.g. StaffAgentRunner, which controls both sides) may
    omit expected_tenant_id — ownership enforcement is opt-in per caller."""
    p.deposit("tenant-a", 1.0)
    hold_id = p.reserve("tenant-a", 0.10)
    out = p.commit(hold_id, 0.05)  # no expected_tenant_id
    assert out["committed_usd"] == pytest.approx(0.05)


class TestListHoldsSince:
    """Read-only recon accessor for warden.finops.ledger_recon.holds_drift()."""

    def test_returns_hold_with_expected_fields(self, _db):
        p.deposit("t1", 1.0)
        hid = p.reserve("t1", 0.10)
        rows = p.list_holds_since("1970-01-01T00:00:00+00:00")
        assert rows == [{
            "hold_id": hid, "tenant_id": "t1", "status": "HELD",
            "created_at": rows[0]["created_at"],
        }]

    def test_cutoff_excludes_earlier_holds(self, _db):
        p.deposit("t1", 1.0)
        p.reserve("t1", 0.10)
        rows = p.list_holds_since("2999-01-01T00:00:00+00:00")
        assert rows == []

    def test_no_holds_returns_empty_list(self, _db):
        assert p.list_holds_since("1970-01-01T00:00:00+00:00") == []
