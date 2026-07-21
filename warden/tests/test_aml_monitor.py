"""Tests for warden/finops/aml_monitor.py — structuring detection on the ledger journal (FT-5)."""
from __future__ import annotations

import pytest

from warden.ledger import accounts, journal
from warden.ledger.journal import Posting
from warden.ledger.money import Money


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "ledger.db")


def _post(db, idem, account, amount_usd):
    journal.post(idem, "xfer", [
        Posting(account, Money.from_usd(amount_usd)),
        Posting(accounts.platform_fees(), Money.from_usd(str(-float(amount_usd)))),
    ], db_path=db)


class TestScanEnabledFlag:
    def test_disabled_by_default(self):
        from warden.finops.aml_monitor import scan_enabled
        assert scan_enabled() is False

    def test_enabled_via_env(self, monkeypatch):
        from warden.finops.aml_monitor import scan_enabled
        monkeypatch.setenv("AML_MONITOR_ENABLED", "true")
        assert scan_enabled() is True


class TestAssessStructuringRisk:
    def test_no_activity_is_low_risk(self, db):
        from warden.finops.aml_monitor import assess_structuring_risk
        report = assess_structuring_risk(accounts.tenant_cash("never-active"), db_path=db)
        assert report["flagged"] is False
        assert report["risk_level"] == "LOW"
        assert report["sub_threshold_count"] == 0

    def test_many_sub_threshold_postings_flags(self, db):
        from warden.finops.aml_monitor import assess_structuring_risk
        acct = accounts.tenant_cash("structurer")
        for n in range(5):
            _post(db, f"idem-s{n}", acct, "3000")  # 5 x $3000 = $15,000, each < $10k threshold
        report = assess_structuring_risk(
            acct, threshold_usd=10_000.0, min_postings=3, db_path=db
        )
        assert report["flagged"] is True
        assert report["risk_level"] == "HIGH"
        assert report["sub_threshold_count"] == 5
        assert report["sub_threshold_total_usd"] == pytest.approx(15_000.0)

    def test_single_large_transfer_is_not_structuring(self, db):
        """One large postings above the threshold — not structuring by definition."""
        from warden.finops.aml_monitor import assess_structuring_risk
        acct = accounts.tenant_cash("legit-big-spender")
        _post(db, "idem-big", acct, "50000")  # single posting, ABOVE threshold
        report = assess_structuring_risk(acct, threshold_usd=10_000.0, db_path=db)
        assert report["flagged"] is False
        assert report["sub_threshold_count"] == 0  # the $50k posting doesn't count

    def test_below_min_postings_count_not_flagged(self, db):
        """Two sub-threshold postings summing past threshold, but min_postings=3 not met."""
        from warden.finops.aml_monitor import assess_structuring_risk
        acct = accounts.tenant_cash("two-postings")
        _post(db, "idem-tp1", acct, "6000")
        _post(db, "idem-tp2", acct, "6000")
        report = assess_structuring_risk(acct, threshold_usd=10_000.0, min_postings=3, db_path=db)
        assert report["flagged"] is False

    def test_sub_threshold_but_total_under_threshold_not_flagged(self, db):
        from warden.finops.aml_monitor import assess_structuring_risk
        acct = accounts.tenant_cash("small-fry")
        for n in range(3):
            _post(db, f"idem-sf{n}", acct, "100")  # 3 x $100 = $300, well under threshold
        report = assess_structuring_risk(acct, threshold_usd=10_000.0, min_postings=3, db_path=db)
        assert report["flagged"] is False

    def test_window_excludes_old_activity(self, db):
        from warden.finops.aml_monitor import assess_structuring_risk
        acct = accounts.tenant_cash("stale-activity")
        for n in range(5):
            _post(db, f"idem-st{n}", acct, "3000")
        # window_hours=0 excludes everything (created_at is always "now" or earlier)
        report = assess_structuring_risk(acct, window_hours=0.0, threshold_usd=10_000.0, db_path=db)
        assert report["sub_threshold_count"] == 0
        assert report["flagged"] is False


class TestScanForStructuring:
    def test_noop_when_disabled(self, db):
        from warden.finops.aml_monitor import scan_for_structuring
        result = scan_for_structuring(db_path=db)
        assert result == {"scanned": False}

    def test_clean_ledger_no_flags(self, db, monkeypatch):
        monkeypatch.setenv("AML_MONITOR_ENABLED", "true")
        from warden.finops.aml_monitor import scan_for_structuring
        acct = accounts.tenant_cash("clean-tenant")
        _post(db, "idem-clean", acct, "50")
        result = scan_for_structuring(db_path=db)
        assert result["scanned"] is True
        assert result["flagged"] == 0
        assert result["details"] == []

    def test_structuring_pattern_opens_incident(self, db, monkeypatch):
        monkeypatch.setenv("AML_MONITOR_ENABLED", "true")
        import warden.finops.aml_monitor as aml_mod

        incidents = []
        monkeypatch.setattr(
            aml_mod, "_open_incident",
            lambda tenant_id, account, report: incidents.append((tenant_id, account, report)),
        )

        acct = accounts.tenant_cash("bad-actor")
        for n in range(5):
            _post(db, f"idem-ba{n}", acct, "3000")

        result = aml_mod.scan_for_structuring(threshold_usd=10_000.0, min_postings=3, db_path=db)
        assert result["scanned"] is True
        assert result["flagged"] == 1
        assert result["accounts_scanned"] >= 1
        assert len(incidents) == 1
        assert incidents[0][0] == "bad-actor"

    def test_only_tenant_cash_accounts_scanned(self, db, monkeypatch):
        """platform:fees postings from the fixture's offsetting leg must not be scanned."""
        monkeypatch.setenv("AML_MONITOR_ENABLED", "true")
        import warden.finops.aml_monitor as aml_mod

        incidents = []
        monkeypatch.setattr(
            aml_mod, "_open_incident",
            lambda tenant_id, account, report: incidents.append(account),
        )
        for n in range(5):
            _post(db, f"idem-pf{n}", accounts.tenant_cash("t-scan"), "3000")

        aml_mod.scan_for_structuring(threshold_usd=10_000.0, min_postings=3, db_path=db)
        assert all(a.startswith("tenant:") and a.endswith(":cash") for a in incidents)

    def test_fail_soft_on_enumeration_error(self, db, monkeypatch):
        monkeypatch.setenv("AML_MONITOR_ENABLED", "true")
        import warden.ledger.journal as journal_mod

        def _boom(**kwargs):
            raise RuntimeError("db down")
        monkeypatch.setattr(journal_mod, "distinct_accounts", _boom)

        from warden.finops.aml_monitor import scan_for_structuring
        result = scan_for_structuring(db_path=db)  # must not raise
        assert result["scanned"] is False
        assert "error" in result
