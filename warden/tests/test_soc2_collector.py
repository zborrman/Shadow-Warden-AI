"""
Tests for warden/compliance/soc2_collector.py — SOC 2 Type II Evidence Collector.

Verifies:
  - All 5 TSC sections are collected
  - PII/DID identifiers are pseudonymised
  - Clearing integrity check catches decimal drift
  - Daily evidence JSON is written atomically
  - load_evidence_range returns snapshots in order
  - ARQ cron function does not block the event loop (asyncio test)
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture()
def logs_with_events(tmp_path, monkeypatch):
    """Write a synthetic logs.json with events for today UTC."""
    logs_path = tmp_path / "logs.json"
    arch = tmp_path / "archives"
    monkeypatch.setenv("LOGS_PATH", str(logs_path))
    monkeypatch.setenv("SOC2_ARCHIVE_DIR", str(arch))
    # `UPTIME_DB_PATH` / `SECRETS_INV_DB_PATH` used to be set here. Both named
    # SQLite files that no module has ever written — the fixture pointed them at
    # tmp_path and so made the collector's reach for them look deliberate. F8:
    # uptime comes from `warden_core.probe_results` via
    # `api.monitor.availability_window()`, and there is no vault access log
    # anywhere. See warden/tests/test_no_ghost_database.py.
    monkeypatch.setenv("SECRETS_DB_PATH", str(tmp_path / "secrets.db"))
    now_ts = time.time()

    # Journal entries carry `ts`; the collectors filter on it. This fixture
    # used to write `timestamp`, i.e. the same key the collectors wrongly read,
    # so it agreed with the bug and passed while production collected nothing.
    #
    # The `stage` / `pqc_*` / `event_type` / `status` / `agent_id` keys below are
    # still synthetic: no producer emits them anywhere in the codebase, which is
    # exactly what docs/soc2-evidence.md records as the open decision. These
    # cases therefore prove the collector's arithmetic, not that the evidence
    # exists.
    lines = [
        # Confused deputy block
        {"ts": now_ts - 10, "stage": "confused_deputy", "blocked": True,
         "action": "BLOCK", "request_id": "req-123", "semantic_score": 0.92},
        # PQC auth failure
        {"ts": now_ts - 20, "pqc_auth_failed": True,
         "agent_id": "did:shadow:abc123", "pqc_fail_reason": "invalid hybrid sig"},
        # GDPR export
        {"ts": now_ts - 30, "event_type": "gdpr_export_request",
         "request_id": "gdpr-456", "tenant_id": "tenant_a", "status": "ok"},
        # E2EE activation
        {"ts": now_ts - 40, "event_type": "e2ee_session_start", "session_id": "sess-789"},
        # PQC signing op
        {"ts": now_ts - 50, "pqc_signed": True},
        # PII redacted — three secret types, as the redactor records them
        {"ts": now_ts - 60, "secrets_found": ["aws_key", "email", "phone"]},
    ]
    logs_path.write_text("\n".join(json.dumps(e) for e in lines) + "\n")
    return logs_path


@pytest.fixture()
def clearing_db(tmp_path, monkeypatch):
    """Create a marketplace_clearing_log SQLite table with one valid record."""
    db = tmp_path / "clearing.db"
    # MARKETPLACE_DB_PATH, not MARKETPLACE_CLEARING_DB_PATH: this fixture
    # used to create the file the collector guessed at, which is what made a
    # never-written database look live. `marketplace/clearing.py` writes
    # `marketplace_clearing_log` into warden_marketplace.db.
    monkeypatch.setenv("MARKETPLACE_DB_PATH", str(db))
    monkeypatch.setenv("SOC2_ARCHIVE_DIR", str(tmp_path / "archives"))
    monkeypatch.setenv("LOGS_PATH", str(tmp_path / "empty.json"))
    (tmp_path / "empty.json").write_text("")
    con = sqlite3.connect(db)
    con.execute("""
        CREATE TABLE marketplace_clearing_log (
            clearing_id      TEXT PRIMARY KEY,
            winner_neg_id    TEXT NOT NULL,
            buyer_agent_id   TEXT NOT NULL,
            rejected_neg_ids TEXT NOT NULL,
            cleared_at       REAL NOT NULL,
            platform_fee_usd REAL NOT NULL DEFAULT 0.0,
            seller_net_usd   REAL NOT NULL DEFAULT 0.0
        )
    """)
    now_ts = time.time()
    # Valid record: 1.000000 - 0.015000 = 0.985000
    con.execute(
        "INSERT INTO marketplace_clearing_log VALUES (?,?,?,?,?,?,?)",
        ("clr-001", "neg-001", "did:buyer:111", "[]", now_ts - 100, 0.015000, 0.985000),
    )
    con.commit()
    con.close()
    return db


@pytest.fixture()
def clearing_db_with_violation(tmp_path, monkeypatch):
    """Clearing DB with a Decimal drift violation."""
    db = tmp_path / "clearing_bad.db"
    # MARKETPLACE_DB_PATH, not MARKETPLACE_CLEARING_DB_PATH: this fixture
    # used to create the file the collector guessed at, which is what made a
    # never-written database look live. `marketplace/clearing.py` writes
    # `marketplace_clearing_log` into warden_marketplace.db.
    monkeypatch.setenv("MARKETPLACE_DB_PATH", str(db))
    monkeypatch.setenv("SOC2_ARCHIVE_DIR", str(tmp_path / "archives"))
    monkeypatch.setenv("LOGS_PATH", str(tmp_path / "empty.json"))
    (tmp_path / "empty.json").write_text("")
    con = sqlite3.connect(db)
    con.execute("""
        CREATE TABLE marketplace_clearing_log (
            clearing_id      TEXT PRIMARY KEY,
            winner_neg_id    TEXT NOT NULL,
            buyer_agent_id   TEXT NOT NULL,
            rejected_neg_ids TEXT NOT NULL,
            cleared_at       REAL NOT NULL,
            platform_fee_usd REAL NOT NULL DEFAULT 0.0,
            seller_net_usd   REAL NOT NULL DEFAULT 0.0
        )
    """)
    now_ts = time.time()
    # A negative seller_net is the arithmetic fault this schema can actually
    # express. It cannot hold an agreed-vs-fee+net mismatch: there is no
    # agreed_price column, which is why the collector no longer claims to
    # verify that identity.
    con.execute(
        "INSERT INTO marketplace_clearing_log VALUES (?,?,?,?,?,?,?)",
        ("clr-bad", "neg-bad", "did:buyer:x", "[]", now_ts - 50, 0.015000, -0.990000),
    )
    con.commit()
    con.close()
    return db


# ── Unit tests ────────────────────────────────────────────────────────────────

class TestPseudonymisation:
    def test_pseudo_is_hex16(self):
        from warden.compliance.soc2_collector import _pseudo
        result = _pseudo("did:shadow:abc123")
        assert len(result) == 16
        assert all(c in "0123456789abcdef" for c in result)

    def test_pseudo_deterministic(self):
        from warden.compliance.soc2_collector import _pseudo
        assert _pseudo("test") == _pseudo("test")

    def test_pseudo_different_inputs(self):
        from warden.compliance.soc2_collector import _pseudo
        assert _pseudo("did:a:111") != _pseudo("did:b:222")


class TestCollectSecurity:
    def test_counts_confused_deputy_blocks(self, logs_with_events):
        from warden.compliance.soc2_collector import _collect_security
        now = time.time()
        result = _collect_security(now - 3600, now + 60)
        assert result["tsc"] == "CC1-CC8"
        assert result["confused_deputy_block_count"] == 1
        assert result["pqc_auth_failure_count"] == 1
        # Agent IDs must be pseudonymised — no raw DID
        for failure in result["pqc_auth_failures"]:
            assert "did:shadow" not in failure["agent_id"]

    def test_no_events_in_window_returns_zero(self, logs_with_events):
        from warden.compliance.soc2_collector import _collect_security
        # Past window that doesn't include fixtures (1 year ago)
        far_past = time.time() - 365 * 24 * 3600
        result = _collect_security(far_past, far_past + 3600)
        assert result["confused_deputy_block_count"] == 0


class TestCollectProcessingIntegrity:
    def test_valid_clearing_passes(self, clearing_db):
        from warden.compliance.soc2_collector import _collect_processing_integrity
        now = time.time()
        result = _collect_processing_integrity(now - 3600, now + 60)
        assert result["clearings_in_window"] == 1
        assert result["decimal_violation_count"] == 0
        assert result["integrity_pass_rate_pct"] == 100.0

    def test_drift_violation_detected(self, clearing_db_with_violation):
        from warden.compliance.soc2_collector import _collect_processing_integrity
        now = time.time()
        result = _collect_processing_integrity(now - 3600, now + 60)
        assert result["decimal_violation_count"] == 1
        assert result["integrity_pass_rate_pct"] < 100.0

    def test_buyer_seller_pseudonymised(self, clearing_db):
        from warden.compliance.soc2_collector import _collect_processing_integrity
        now = time.time()
        result = _collect_processing_integrity(now - 3600, now + 60)
        for rec in result.get("decimal_violations", []):
            assert "did:" not in rec.get("clearing_id", "")


class TestCollectPrivacy:
    def test_gdpr_export_counted(self, logs_with_events):
        from warden.compliance.soc2_collector import _collect_privacy
        now = time.time()
        result = _collect_privacy(now - 3600, now + 60)
        assert result["tsc"] == "P1-P8"
        assert result["gdpr_export_count"] == 1
        # request_id must be pseudonymised — no raw uuid
        for ev in result["gdpr_export_events"]:
            assert "gdpr-456" not in ev["request_id"]

    def test_e2ee_counted(self, logs_with_events):
        from warden.compliance.soc2_collector import _collect_privacy
        now = time.time()
        result = _collect_privacy(now - 3600, now + 60)
        assert result["e2ee_activations_count"] == 1

    def test_pii_redacted_sum(self, logs_with_events):
        from warden.compliance.soc2_collector import _collect_privacy
        now = time.time()
        result = _collect_privacy(now - 3600, now + 60)
        assert result["pii_fields_redacted"] == 3


class TestCollectDailyEvidence:
    def test_writes_json_file(self, logs_with_events):
        from warden.compliance.soc2_collector import collect_daily_evidence
        today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        collect_daily_evidence(date=today)

        archive_dir = Path(os.getenv("SOC2_ARCHIVE_DIR", ""))
        expected = archive_dir / f"{today.strftime('%Y-%m-%d')}_tsc.json"
        assert expected.exists(), f"Archive file not found: {expected}"

        with open(expected) as f:
            loaded = json.load(f)
        # v2 adds evidence_status / evidence_coverage — the fields that tell an
        # auditor whether the zeroes below are absence of events or absence
        # of data. See test_evidence_declares_absence.py.
        assert loaded["schema_version"] == "SOC2Collector-v2"
        assert "evidence_status" in loaded
        assert "tsc_evidence" in loaded

    def test_all_five_tsc_present(self, logs_with_events):
        from warden.compliance.soc2_collector import collect_daily_evidence
        today = datetime.now(UTC)
        evidence = collect_daily_evidence(date=today)
        tsc = evidence["tsc_evidence"]
        for key in ("security", "availability", "processing_integrity", "privacy", "confidentiality"):
            assert key in tsc

    def test_atomic_write_no_partial_file(self, logs_with_events):
        """collect_daily_evidence must use tempfile+os.replace() — no .tmp files remain."""
        from warden.compliance.soc2_collector import collect_daily_evidence
        today = datetime.now(UTC)
        collect_daily_evidence(date=today)
        archive_dir = Path(os.getenv("SOC2_ARCHIVE_DIR", ""))
        tmp_files = list(archive_dir.glob("*.tmp"))
        assert tmp_files == [], f"Stale .tmp files found: {tmp_files}"


class TestLoadEvidenceRange:
    def test_returns_snapshots_most_recent_first(self, tmp_path, monkeypatch):
        arch = tmp_path / "archives"
        monkeypatch.setenv("SOC2_ARCHIVE_DIR", str(arch))
        monkeypatch.setenv("LOGS_PATH", str(tmp_path / "empty.json"))
        (tmp_path / "empty.json").write_text("")

        from warden.compliance.soc2_collector import collect_daily_evidence, load_evidence_range
        now = datetime.now(UTC)
        d0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
        d1 = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        collect_daily_evidence(date=d1)
        collect_daily_evidence(date=d0)
        snapshots = load_evidence_range(days=7)
        assert len(snapshots) >= 2
        dates = [s["period_start"][:10] for s in snapshots]
        assert dates == sorted(dates, reverse=True)

    def test_missing_days_silently_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SOC2_ARCHIVE_DIR", str(tmp_path / "empty_arch"))
        from warden.compliance.soc2_collector import load_evidence_range
        snapshots = load_evidence_range(days=30)
        assert isinstance(snapshots, list)
        assert len(snapshots) == 0


# ── ARQ cron function (asyncio) ───────────────────────────────────────────────

class TestSovaSoc2DailyCollect:
    def test_returns_dict_with_status(self, logs_with_events):
        from warden.agent.scheduler import sova_soc2_daily_collect
        result = asyncio.run(sova_soc2_daily_collect({}))
        assert isinstance(result, dict)
        assert "status" in result
        assert "date" in result

    def test_does_not_raise_on_empty_logs(self, tmp_path, monkeypatch):
        """Cron job must be fail-open — never raise to the ARQ worker."""
        (tmp_path / "empty_logs.json").write_text("")
        arch = tmp_path / "arch2"
        monkeypatch.setenv("LOGS_PATH", str(tmp_path / "empty_logs.json"))
        monkeypatch.setenv("SOC2_ARCHIVE_DIR", str(arch))
        from warden.agent.scheduler import sova_soc2_daily_collect
        result = asyncio.run(sova_soc2_daily_collect({}))
        assert result["status"] in ("ok", "error")


# ── F8: cross-module reads go through a contract ──────────────────────────────

def test_availability_comes_from_the_probe_store_not_a_file(logs_with_events, monkeypatch):
    """A1.1/A1.2 read `warden_uptime.db`, which nothing writes, while 548 k
    probe rows sat in `warden_core.probe_results`. Prove the collector now
    consumes the uptime module's contract and reports what it returns."""
    from warden.compliance import soc2_collector as sc

    monkeypatch.setattr(
        "warden.api.monitor.availability_window",
        lambda since, until, **kw: {
            "source": "warden_core.probe_results",
            "checks": 400,
            "up_count": 399,
            "availability_pct": 99.75,
            "avg_response_ms": 41.5,
        },
    )
    out = sc._collect_availability(time.time() - 3600, time.time())
    assert out["uptime_checks_in_window"] == 400
    assert out["availability_pct"] == 99.75
    assert out["uptime_evidence"] == "counted"
    assert out["uptime_source"] == "warden_core.probe_results"


def test_availability_says_so_when_it_cannot_measure(logs_with_events, monkeypatch):
    """`None` from the contract must not become a zero that reads as uptime
    data — that is precisely how the original defect stayed invisible."""
    from warden.compliance import soc2_collector as sc

    monkeypatch.setattr(
        "warden.api.monitor.availability_window", lambda since, until, **kw: None
    )
    out = sc._collect_availability(time.time() - 3600, time.time())
    assert out["uptime_evidence"] == "not_available"
    assert out["availability_pct"] is None
    assert out["uptime_source"] is None


def test_availability_distinguishes_empty_from_unavailable(logs_with_events, monkeypatch):
    from warden.compliance import soc2_collector as sc

    monkeypatch.setattr(
        "warden.api.monitor.availability_window",
        lambda since, until, **kw: {
            "source": "warden_core.probe_results", "checks": 0, "up_count": 0,
            "availability_pct": None, "avg_response_ms": None,
        },
    )
    out = sc._collect_availability(time.time() - 3600, time.time())
    assert out["uptime_evidence"] == "no_probes_in_window"


def test_confidentiality_labels_the_missing_vault_access_log(logs_with_events, monkeypatch):
    """There is no access log in any store, so a count of 0 would claim more
    than the truth. It must be labelled, and the inventory that *does* exist
    must be reported instead."""
    from warden.compliance import soc2_collector as sc

    monkeypatch.setattr(
        "warden.secrets_gov.inventory.inventory_census",
        lambda: {"secrets_under_management": 12, "vaults_registered": 2,
                 "secrets_expired": 1},
    )
    out = sc._collect_confidentiality(time.time() - 3600, time.time())
    assert out["vault_accesses_in_window"] == "not_instrumented"
    assert out["secrets_under_management"] == 12
    assert out["secrets_inventory_evidence"] == "counted"


def test_confidentiality_when_the_inventory_cannot_be_read(logs_with_events, monkeypatch):
    from warden.compliance import soc2_collector as sc

    monkeypatch.setattr("warden.secrets_gov.inventory.inventory_census", lambda: None)
    out = sc._collect_confidentiality(time.time() - 3600, time.time())
    assert out["secrets_under_management"] is None
    assert out["secrets_inventory_evidence"] == "not_available"


def test_a1_reports_the_worst_target_not_just_the_mean(logs_with_events, monkeypatch):
    """A blended 76% that is really one dead monitor is as misleading as the
    zeros this section used to report — it just errs the other way."""
    from warden.compliance import soc2_collector as sc

    monkeypatch.setattr(
        "warden.api.monitor.availability_window",
        lambda since, until, **kw: {
            "source": "warden_core.probe_results",
            "checks": 24151, "up_count": 18414,
            "availability_pct": 76.2453, "avg_response_ms": 104.06,
            "by_monitor": [
                {"target": "Portal", "checks": 5724, "up_count": 0,
                 "availability_pct": 0.0, "avg_response_ms": 4.0},
                {"target": "Landing", "checks": 5724, "up_count": 5724,
                 "availability_pct": 100.0, "avg_response_ms": 90.0},
                {"target": "API Gateway", "checks": 5724, "up_count": 5716,
                 "availability_pct": 99.86, "avg_response_ms": 181.0},
            ],
        },
    )
    out = sc._collect_availability(time.time() - 86400, time.time())
    assert len(out["by_monitor"]) == 3
    assert out["worst_monitor"]["target"] == "Portal"
    assert out["worst_monitor"]["availability_pct"] == 0.0
    # The blended number is still reported — it is not wrong, only incomplete.
    assert out["availability_pct"] == 76.2453


def test_a1_by_monitor_is_empty_not_missing_when_unmeasurable(logs_with_events, monkeypatch):
    from warden.compliance import soc2_collector as sc

    monkeypatch.setattr(
        "warden.api.monitor.availability_window", lambda since, until, **kw: None
    )
    out = sc._collect_availability(time.time() - 86400, time.time())
    assert out["by_monitor"] == []
    assert out["worst_monitor"] is None


def test_a1_worst_monitor_ignores_targets_with_no_percentage(logs_with_events, monkeypatch):
    """A target with 0 checks has `availability_pct: None`; it is not the worst,
    it is unmeasured, and sorting it to the front would invent a finding."""
    from warden.compliance import soc2_collector as sc

    monkeypatch.setattr(
        "warden.api.monitor.availability_window",
        lambda since, until, **kw: {
            "source": "warden_core.probe_results", "checks": 10, "up_count": 9,
            "availability_pct": 90.0, "avg_response_ms": 5.0,
            "by_monitor": [
                {"target": "Never probed", "checks": 0, "up_count": 0,
                 "availability_pct": None, "avg_response_ms": None},
                {"target": "Real", "checks": 10, "up_count": 9,
                 "availability_pct": 90.0, "avg_response_ms": 5.0},
            ],
        },
    )
    out = sc._collect_availability(time.time() - 86400, time.time())
    assert out["worst_monitor"]["target"] == "Real"
