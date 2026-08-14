"""
Tests for warden/workers/ledger_recon_job.py (FT-4 slice 2).

credit_drift() is pure (see test_ledger_recon.py) — this file only tests the
observability wrapper: gauges published, and a Slack alert fired on drift *or*
on a run that verified nothing because something broke.

The second condition is the one that was missing: a reconciliation in which the
ledger was unreachable for every subject used to publish drift 0.0, send no
alert and log "clean", which is exactly what a healthy night looks like.
"""
from __future__ import annotations

import pytest

from warden.config import settings
from warden.finops import ledger_recon
from warden.ledger import journal
from warden.marketplace import credits
from warden.sac import preflight
from warden.workers import ledger_recon_job as job


@pytest.fixture
def wired(tmp_path, monkeypatch):
    monkeypatch.setattr(credits, "_DB_PATH", str(tmp_path / "mkt.db"))
    monkeypatch.setattr(journal, "_DB_PATH", str(tmp_path / "ledger.db"))
    monkeypatch.setattr(preflight.settings, "sac_wallet_db_path", str(tmp_path / "wallet.db"))
    monkeypatch.setattr(settings, "ledger_dual_write", True)


@pytest.fixture
def alerts(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(job, "send_alert", lambda msg, **kw: sent.append(msg))
    return sent


@pytest.fixture(autouse=True)
def _reset_gauge():
    # Module-level Prometheus singletons — reset so test order never matters.
    job.LEDGER_RECON_DRIFT_USD.set(0.0)
    job.LEDGER_RECON_HOLD_DRIFT_USD.set(0.0)
    yield


class TestRunLedgerReconciliation:
    def test_clean_state_no_alert_gauge_zero(self, wired, alerts):
        credits.purchase_credits("t1", "credits_100")  # mirrored, zero drift

        report = job.run_ledger_reconciliation()

        assert report["ok"] is True
        assert alerts == []
        assert job.LEDGER_RECON_DRIFT_USD._value.get() == 0.0

    def test_drift_fires_alert_and_sets_gauge(self, wired, alerts, monkeypatch):
        credits.purchase_credits("t1", "credits_100")  # ledger + counter both 100
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        assert credits.deduct_credits("t1", 5) is True  # counter-only drop → drift
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        report = job.run_ledger_reconciliation()

        assert report["ok"] is False
        assert report["drifted"] == 1
        assert len(alerts) == 1
        assert "drift" in alerts[0].lower()
        # 5000 micros = $0.005
        assert job.LEDGER_RECON_DRIFT_USD._value.get() == pytest.approx(0.005)

    def test_returns_underlying_report_unchanged(self, wired, alerts):
        report = job.run_ledger_reconciliation()
        assert report == ledger_recon.credit_drift()

    def test_alert_failure_is_non_fatal(self, wired, monkeypatch):
        credits.purchase_credits("t1", "credits_100")
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        credits.deduct_credits("t1", 5)
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        def _boom(*a, **kw):
            raise RuntimeError("slack down")
        monkeypatch.setattr(job, "send_alert", _boom)

        report = job.run_ledger_reconciliation()  # must not raise
        assert report["ok"] is False


class TestArqEntryPoint:
    @pytest.mark.asyncio
    async def test_nightly_ledger_recon_returns_report(self, wired, alerts):
        result = await job.nightly_ledger_recon(ctx={})
        assert result["ok"] is True


class TestRunHoldReconciliation:
    def test_clean_state_no_alert_gauge_zero(self, wired, alerts):
        preflight.deposit("t1", 1.0)
        preflight.reserve("t1", 0.10)  # mirrored, zero drift

        report = job.run_hold_reconciliation()

        assert report["ok"] is True
        assert alerts == []
        assert job.LEDGER_RECON_HOLD_DRIFT_USD._value.get() == 0.0

    def test_drift_fires_alert_and_sets_gauge(self, wired, alerts, monkeypatch):
        preflight.deposit("t1", 1.0)
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        preflight.reserve("t1", 0.10)  # never mirrored → drift
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        report = job.run_hold_reconciliation()

        assert report["ok"] is False
        assert report["drifted"] == 1
        assert len(alerts) == 1
        assert "drift" in alerts[0].lower()
        # 100_000 micros = $0.10
        assert job.LEDGER_RECON_HOLD_DRIFT_USD._value.get() == pytest.approx(0.10)

    def test_returns_underlying_report_unchanged(self, wired, alerts):
        report = job.run_hold_reconciliation()
        assert report == ledger_recon.hold_drift()

    def test_alert_failure_is_non_fatal(self, wired, monkeypatch):
        preflight.deposit("t1", 1.0)
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        preflight.reserve("t1", 0.10)
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        def _boom(*a, **kw):
            raise RuntimeError("slack down")
        monkeypatch.setattr(job, "send_alert", _boom)

        report = job.run_hold_reconciliation()  # must not raise
        assert report["ok"] is False


class TestHoldArqEntryPoint:
    @pytest.mark.asyncio
    async def test_nightly_hold_recon_returns_report(self, wired, alerts):
        result = await job.nightly_hold_recon(ctx={})
        assert result["ok"] is True


class TestBlindRunIsNotACleanRun:
    """The failure the wrapper used to report as a healthy night."""

    def test_unreachable_ledger_alerts_instead_of_logging_a_clean_night(
        self, wired, alerts, monkeypatch
    ):
        credits.purchase_credits("t1", "credits_100")
        credits.purchase_credits("t2", "credits_500")

        from warden.ledger import dual_write

        def _boom(*a, **kw):
            raise RuntimeError("ledger unreachable")
        monkeypatch.setattr(dual_write, "reconcile", _boom)

        report = job.run_ledger_reconciliation()

        assert report["tenants_checked"] == 0
        assert report["unreadable"] == 2
        assert len(alerts) == 1
        assert "verified nothing" in alerts[0]
        # The drift gauge alone is still 0.0 — which is why it cannot be the
        # only signal an operator watches.
        assert job.LEDGER_RECON_DRIFT_USD._value.get() == 0.0

    def test_dead_source_alerts(self, wired, alerts, monkeypatch):
        def _boom():
            raise RuntimeError("db down")
        monkeypatch.setattr(credits, "all_balances", _boom)

        job.run_ledger_reconciliation()

        assert len(alerts) == 1
        assert "could not run" in alerts[0]

    def test_nothing_to_reconcile_is_quiet_but_not_reported_as_clean(self, wired, alerts):
        """An empty credits table must not page anyone nightly...

        ...but it must not be published as verified agreement either — that is
        exactly the state the FT-2 shadow period has been sitting in.
        """
        report = job.run_ledger_reconciliation()

        assert report["evidence"] == ledger_recon.NOTHING_TO_CHECK
        assert alerts == []

    def test_partially_unreadable_run_alerts_even_though_ok_is_true(
        self, wired, alerts, monkeypatch
    ):
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

        report = job.run_ledger_reconciliation()

        assert report["ok"] is True          # no drift was found...
        assert report["unreadable"] == 1     # ...because one tenant was never read
        assert len(alerts) == 1
        assert "could not be reconciled" in alerts[0]

    def test_unreachable_holds_alert_instead_of_logging_a_clean_night(
        self, wired, alerts, monkeypatch
    ):
        preflight.deposit("t1", 1.0)
        preflight.reserve("t1", 0.10)

        from warden.ledger import dual_write

        def _boom(*a, **kw):
            raise RuntimeError("ledger unreachable")
        monkeypatch.setattr(dual_write, "reconcile", _boom)

        report = job.run_hold_reconciliation()

        assert report["holds_checked"] == 0
        assert report["unreadable"] == 1
        assert len(alerts) == 1
