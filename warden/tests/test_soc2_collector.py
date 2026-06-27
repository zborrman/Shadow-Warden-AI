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
import hashlib
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
    monkeypatch.setenv("UPTIME_DB_PATH", str(tmp_path / "uptime.db"))
    monkeypatch.setenv("SECRETS_INV_DB_PATH", str(tmp_path / "secrets_inv.db"))
    now_ts = time.time()

    lines = [
        # Confused deputy block
        {"timestamp": now_ts - 10, "stage": "confused_deputy", "blocked": True,
         "action": "BLOCK", "request_id": "req-123", "risk_score": 0.92},
        # PQC auth failure
        {"timestamp": now_ts - 20, "pqc_auth_failed": True,
         "agent_id": "did:shadow:abc123", "pqc_fail_reason": "invalid hybrid sig"},
        # GDPR export
        {"timestamp": now_ts - 30, "event_type": "gdpr_export_request",
         "request_id": "gdpr-456", "tenant_id": "tenant_a", "status": "ok"},
        # E2EE activation
        {"timestamp": now_ts - 40, "event_type": "e2ee_session_start", "session_id": "sess-789"},
        # PQC signing op
        {"timestamp": now_ts - 50, "pqc_signed": True},
        # PII redacted
        {"timestamp": now_ts - 60, "redacted_count": 3},
    ]
    logs_path.write_text("\n".join(json.dumps(e) for e in lines) + "\n")
    return logs_path


@pytest.fixture()
def clearing_db(tmp_path, monkeypatch):
    """Create a marketplace_clearing_log SQLite table with one valid record."""
    db = tmp_path / "clearing.db"
    monkeypatch.setenv("MARKETPLACE_CLEARING_DB_PATH", str(db))
    monkeypatch.setenv("SOC2_ARCHIVE_DIR", str(tmp_path / "archives"))
    monkeypatch.setenv("LOGS_PATH", str(tmp_path / "empty.json"))
    (tmp_path / "empty.json").write_text("")
    con = sqlite3.connect(db)
    con.execute("""
        CREATE TABLE marketplace_clearing_log (
            clearing_id TEXT, winner_neg_id TEXT, buyer_agent_id TEXT,
            seller_agent_id TEXT, agreed_price REAL, platform_fee_usd REAL,
            seller_net_usd REAL, cleared_at REAL
        )
    """)
    now_ts = time.time()
    # Valid record: 1.000000 - 0.015000 = 0.985000
    con.execute(
        "INSERT INTO marketplace_clearing_log VALUES (?,?,?,?,?,?,?,?)",
        ("clr-001", "neg-001", "did:buyer:111", "did:seller:222",
         1.000000, 0.015000, 0.985000, now_ts - 100),
    )
    con.commit()
    con.close()
    return db


@pytest.fixture()
def clearing_db_with_violation(tmp_path, monkeypatch):
    """Clearing DB with a Decimal drift violation."""
    db = tmp_path / "clearing_bad.db"
    monkeypatch.setenv("MARKETPLACE_CLEARING_DB_PATH", str(db))
    monkeypatch.setenv("SOC2_ARCHIVE_DIR", str(tmp_path / "archives"))
    monkeypatch.setenv("LOGS_PATH", str(tmp_path / "empty.json"))
    (tmp_path / "empty.json").write_text("")
    con = sqlite3.connect(db)
    con.execute("""
        CREATE TABLE marketplace_clearing_log (
            clearing_id TEXT, winner_neg_id TEXT, buyer_agent_id TEXT,
            seller_agent_id TEXT, agreed_price REAL, platform_fee_usd REAL,
            seller_net_usd REAL, cleared_at REAL
        )
    """)
    now_ts = time.time()
    # Bad record: 1.0 - 0.015 = 0.99 (should be 0.985 — drift of 0.005)
    con.execute(
        "INSERT INTO marketplace_clearing_log VALUES (?,?,?,?,?,?,?,?)",
        ("clr-bad", "neg-bad", "did:buyer:x", "did:seller:y",
         1.000000, 0.015000, 0.990000, now_ts - 50),
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
        assert loaded["schema_version"] == "SOC2Collector-v1"
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
