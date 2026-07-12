"""
StaffAgentRunner ↔ SAC preflight wiring.

The reserve/settle calls are pure helpers in warden.staff.agents.base — this
tests them directly rather than driving a full Anthropic-backed run (that path
is already offline-covered by the "no ANTHROPIC_API_KEY" early return). Focus:
default-off is a true no-op; insufficient funds blocks; failures fail-open.
"""
from __future__ import annotations

from warden.staff.agents import base


def test_disabled_is_noop(monkeypatch):
    monkeypatch.setattr("warden.config.settings.sac_preflight_enabled", False)
    hold_id, blocked = base._preflight_reserve("t1", "bdr")
    assert hold_id is None and blocked is False


def test_enabled_reserves_and_settles(monkeypatch, tmp_path):
    monkeypatch.setattr("warden.config.settings.sac_preflight_enabled", True)
    monkeypatch.setattr("warden.config.settings.sac_preflight_estimate_usd", 0.05)
    monkeypatch.setattr("warden.config.settings.sac_wallet_db_path", str(tmp_path / "wallet.db"))

    from warden.sac import preflight as p
    p.deposit("t1", 1.0)

    hold_id, blocked = base._preflight_reserve("t1", "bdr")
    assert blocked is False and hold_id is not None
    assert p.get_wallet("t1")["hold_usd"] == 0.05

    base._preflight_settle(hold_id, "bdr", "claude-haiku-4-5-20251001", 1000, 200)
    w = p.get_wallet("t1")
    assert w["hold_usd"] == 0.0
    assert w["balance_usd"] < 1.0  # some amount was actually charged


def test_insufficient_funds_blocks(monkeypatch, tmp_path):
    monkeypatch.setattr("warden.config.settings.sac_preflight_enabled", True)
    monkeypatch.setattr("warden.config.settings.sac_preflight_estimate_usd", 5.0)
    monkeypatch.setattr("warden.config.settings.sac_wallet_db_path", str(tmp_path / "wallet.db"))

    from warden.sac import preflight as p
    p.deposit("t1", 0.01)  # far below the estimate

    hold_id, blocked = base._preflight_reserve("t1", "bdr")
    assert blocked is True and hold_id is None


def test_reserve_fail_open_on_wallet_error(monkeypatch):
    monkeypatch.setattr("warden.config.settings.sac_preflight_enabled", True)

    def _boom(*a, **kw):
        raise RuntimeError("db unavailable")

    monkeypatch.setattr("warden.sac.preflight.reserve", _boom)
    hold_id, blocked = base._preflight_reserve("t1", "bdr")
    assert hold_id is None and blocked is False  # never blocks on infra failure


def test_settle_is_noop_without_hold():
    # No hold_id (feature disabled) — must not raise or touch the wallet.
    base._preflight_settle(None, "bdr", "claude-haiku-4-5-20251001", 10, 5)


def test_settle_fail_open_on_error(monkeypatch, tmp_path):
    monkeypatch.setattr("warden.config.settings.sac_wallet_db_path", str(tmp_path / "wallet.db"))

    def _boom(*a, **kw):
        raise RuntimeError("commit failed")

    monkeypatch.setattr("warden.sac.preflight.commit", _boom)
    # Must not raise even though commit() blows up.
    base._preflight_settle("sac_hold_fake", "bdr", "claude-haiku-4-5-20251001", 10, 5)
