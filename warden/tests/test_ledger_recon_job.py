"""
Tests for warden/workers/ledger_recon_job.py (FT-4 slice 2 + holds remainder).

credit_drift()/holds_drift() are pure (see test_ledger_recon.py) — this file
only tests the observability wrappers: gauge published, Slack alert fired
iff drift/mismatch != 0.
"""
from __future__ import annotations

import pytest

from warden.config import settings
from warden.ledger import journal
from warden.marketplace import credits
from warden.sac import preflight as p
from warden.workers import ledger_recon_job as job


@pytest.fixture
def wired(tmp_path, monkeypatch):
    monkeypatch.setattr(credits, "_DB_PATH", str(tmp_path / "mkt.db"))
    monkeypatch.setattr(journal, "_DB_PATH", str(tmp_path / "ledger.db"))
    monkeypatch.setattr(settings, "ledger_dual_write", True)


@pytest.fixture
def wired_holds(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "sac_wallet_db_path", str(tmp_path / "wallet.db"))
    monkeypatch.setattr(journal, "_DB_PATH", str(tmp_path / "ledger.db"))
    monkeypatch.setattr(settings, "ledger_dual_write", True)
    monkeypatch.setattr(settings, "ledger_holds_recon_cutoff_ts", "1970-01-01T00:00:00+00:00")


@pytest.fixture
def alerts(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(job, "send_alert", lambda msg, **kw: sent.append(msg))
    return sent


@pytest.fixture(autouse=True)
def _reset_gauge():
    # Module-level Prometheus singletons — reset so test order never matters.
    job.LEDGER_RECON_DRIFT_USD.set(0.0)
    job.LEDGER_HOLDS_RECON_MISMATCHES.set(0)
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
        assert report == {
            "tenants_checked": 0, "drifted": 0,
            "total_abs_drift_micros": 0, "ok": True, "details": [],
        }

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


class TestRunHoldsReconciliation:
    def test_clean_state_no_alert_gauge_zero(self, wired_holds, alerts):
        p.deposit("t1", 1.0)
        p.reserve("t1", 0.10)  # mirrored, zero mismatch

        report = job.run_holds_reconciliation()

        assert report["ok"] is True
        assert alerts == []
        assert job.LEDGER_HOLDS_RECON_MISMATCHES._value.get() == 0

    def test_mismatch_fires_alert_and_sets_gauge(self, wired_holds, alerts, monkeypatch):
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        p.deposit("t1", 1.0)
        p.reserve("t1", 0.10)  # live-only, never mirrored → mismatch
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        report = job.run_holds_reconciliation()

        assert report["ok"] is False
        assert report["mismatched"] == 1
        assert len(alerts) == 1
        assert "holds" in alerts[0].lower()
        assert job.LEDGER_HOLDS_RECON_MISMATCHES._value.get() == 1

    def test_returns_underlying_report_unchanged(self, wired_holds, alerts):
        report = job.run_holds_reconciliation()
        assert report == {"holds_checked": 0, "mismatched": 0, "ok": True, "details": []}

    def test_alert_failure_is_non_fatal(self, wired_holds, monkeypatch):
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        p.deposit("t1", 1.0)
        p.reserve("t1", 0.10)
        monkeypatch.setattr(settings, "ledger_dual_write", True)

        def _boom(*a, **kw):
            raise RuntimeError("slack down")
        monkeypatch.setattr(job, "send_alert", _boom)

        report = job.run_holds_reconciliation()  # must not raise
        assert report["ok"] is False

    @pytest.mark.asyncio
    async def test_nightly_holds_recon_returns_report(self, wired_holds, alerts):
        result = await job.nightly_holds_recon(ctx={})
        assert result["ok"] is True
