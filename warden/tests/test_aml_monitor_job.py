"""Tests for warden/workers/aml_monitor_job.py — ARQ wrapper (FT-5)."""
from __future__ import annotations

import pytest

from warden.ledger import accounts, journal
from warden.ledger.journal import Posting
from warden.ledger.money import Money
from warden.workers import aml_monitor_job as job


@pytest.fixture()
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "ledger.db")
    monkeypatch.setattr("warden.ledger.journal._DB_PATH", path)
    return path


class TestRunAmlScan:
    def test_disabled_returns_underlying_report(self, db):
        result = job.run_aml_scan()
        assert result == {"scanned": False}

    def test_clean_scan_no_flags(self, db, monkeypatch):
        monkeypatch.setenv("AML_MONITOR_ENABLED", "true")
        journal.post("idem-clean", "xfer", [
            Posting(accounts.tenant_cash("t1"), Money.from_usd("10")),
            Posting(accounts.platform_fees(), Money.from_usd("-10")),
        ], db_path=db)
        result = job.run_aml_scan()
        assert result["scanned"] is True
        assert result["flagged"] == 0

    def test_flagged_scan_returns_details(self, db, monkeypatch):
        monkeypatch.setenv("AML_MONITOR_ENABLED", "true")
        import warden.finops.aml_monitor as aml_mod
        monkeypatch.setattr(aml_mod, "_open_incident", lambda *a, **k: None)

        acct = accounts.tenant_cash("flagged-tenant")
        for n in range(5):
            journal.post(f"idem-f{n}", "xfer", [
                Posting(acct, Money.from_usd("3000")),
                Posting(accounts.platform_fees(), Money.from_usd("-3000")),
            ], db_path=db)

        result = job.run_aml_scan()
        assert result["scanned"] is True
        assert result["flagged"] == 1


class TestArqEntryPoint:
    @pytest.mark.asyncio
    async def test_nightly_aml_scan_returns_report(self, db):
        result = await job.nightly_aml_scan(ctx={})
        assert result == {"scanned": False}
