"""
warden/tests/test_settlement_trade_cap.py

`docs/launch-program.md` names a per-trade value cap twice — in the risk
register against "mainnet moves real value through untested paths", and in the
pre-launch controls — with the same reasoning both times: clearing once settled
every trade at $0.00 for months, with tests that agreed, so assume that bug
class is still latent and bound what one wrong settlement can cost.

Nothing implemented it until now. These tests pin the cap where it has to hold:
in `settlement_preflight`, which every escrow passes through, and again in
`deposit_params`, because a cap only one call site honours is not a cap.

The cap is read per call, never snapshotted, so lowering it takes effect without
a restart — the rule `sending_enabled()` already follows for the chain list.
"""
from __future__ import annotations

import pytest

from warden.web3.settlement import (
    Preflight,
    SettlementRefused,
    deposit_params,
    settlement_preflight,
    trade_cap_usd,
)

_BUYER = "0x1111111111111111111111111111111111111111"
_SELLER = "0x2222222222222222222222222222222222222222"


@pytest.fixture()
def cap(monkeypatch):
    """Set the cap the way an operator would — through settings."""
    def _set(value: float) -> None:
        from warden.config import settings
        monkeypatch.setattr(settings, "settlement_max_trade_usd", value, raising=False)
    return _set


def _preflight(amount_usd: float):
    # No chain is configured in tests, so preflight refuses before it reaches an
    # RPC. The cap must be visible in the verdict regardless of what follows it.
    return settlement_preflight(
        escrow_id="ESC-CAP-TEST", amount_usd=amount_usd,
        buyer_address=_BUYER, seller_address=_SELLER, chain="base_sepolia",
    )


# ── the cap itself ────────────────────────────────────────────────────────────


def test_the_default_cap_is_a_cap_not_an_absence(cap):
    """A deployment that configures nothing still settles bounded."""
    from warden.config import Settings
    assert Settings().settlement_max_trade_usd > 0


def test_an_unparseable_cap_does_not_become_no_cap(cap):
    """A typo in the env var must not read as 'uncapped' — that turns a
    fat-fingered value into an unbounded settlement."""
    cap("twenty five")
    assert trade_cap_usd() == 25.0


def test_a_negative_cap_is_treated_as_zero(cap):
    cap(-5.0)
    assert trade_cap_usd() == 0.0


def test_the_cap_is_read_per_call(cap):
    cap(10.0)
    assert trade_cap_usd() == 10.0
    cap(1.0)
    assert trade_cap_usd() == 1.0, "the cap was snapshotted; lowering it did nothing"


# ── preflight ─────────────────────────────────────────────────────────────────


def test_a_trade_over_the_cap_is_refused_by_name(cap):
    cap(25.0)
    pre = _preflight(100.0)
    assert pre.ok is False
    assert pre.reason == "above_trade_cap", pre.reason
    assert "100.00" in pre.detail and "25.00" in pre.detail


def test_a_trade_at_the_cap_passes_the_cap_check(cap):
    """Exactly at the limit is within it — an off-by-one here refuses trades
    the operator deliberately allowed."""
    cap(25.0)
    names = {c.name for c in _preflight(25.0).checks}
    assert "within_trade_cap" in names
    assert _preflight(25.0).reason != "above_trade_cap"


def test_the_verdict_records_which_cap_applied(cap):
    cap(25.0)
    check = next(c for c in _preflight(1.0).checks if c.name == "within_trade_cap")
    assert "25.00" in check.detail


def test_zero_disables_the_cap(cap):
    cap(0.0)
    pre = _preflight(1_000_000.0)
    assert pre.reason != "above_trade_cap"
    check = next(c for c in pre.checks if c.name == "within_trade_cap")
    assert check.detail == "uncapped"


# ── deposit_params, the second place it must hold ─────────────────────────────


def _passing_verdict(amount_usd: float) -> Preflight:
    """A verdict that already said yes — as if taken before the cap dropped."""
    decimals = 6
    return Preflight(
        ok=True, configured=True, trade_id="0x" + "ab" * 32,
        amount_minor=int(amount_usd * 10 ** decimals),
        token_address="0x" + "cd" * 20, token_decimals=decimals,
    )


def test_deposit_params_refuses_a_verdict_above_the_current_cap(cap):
    cap(25.0)
    with pytest.raises(SettlementRefused, match="per-trade cap"):
        deposit_params(_passing_verdict(100.0), _BUYER, _SELLER, 3600)


def test_deposit_params_builds_when_within_the_cap(cap):
    cap(25.0)
    params = deposit_params(_passing_verdict(10.0), _BUYER, _SELLER, 3600)
    assert params["amount"] == 10_000_000
    assert params["buyer"] == _BUYER and params["seller"] == _SELLER
