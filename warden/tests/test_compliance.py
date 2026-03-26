"""
warden/tests/test_compliance.py
────────────────────────────────
Unit tests for warden/compliance/ — Art30, SOC2, Incident, Dashboard.

All tests use in-memory/tmp_path fixtures — no Redis, no real files needed.
"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def empty_logs(monkeypatch, tmp_path):
    """Patch LOGS_PATH to a nonexistent path so load_entries returns []."""
    import warden.analytics.logger as lg
    monkeypatch.setattr(lg, "LOGS_PATH", tmp_path / "logs.json")
    return tmp_path


@pytest.fixture()
def populated_logs(monkeypatch, tmp_path):
    """Write a small NDJSON log and patch LOGS_PATH."""
    from datetime import UTC, datetime

    import warden.analytics.logger as lg

    log_file = tmp_path / "logs.json"
    entries = [
        {"ts": datetime.now(UTC).isoformat(), "request_id": f"r{i}", "allowed": i % 3 != 0,
         "risk_level": "high" if i % 3 == 0 else "low",
         "flags": ["jailbreak"] if i % 3 == 0 else [],
         "secrets_found": ["anthropic_key"] if i % 5 == 0 else [],
         "payload_len": 200, "payload_tokens": 50, "attack_cost_usd": 0.0000075,
         "elapsed_ms": 12.0, "strict": False,
         "entities_detected": ["email"] if i % 4 == 0 else [], "entity_count": 1 if i % 4 == 0 else 0,
         "masked": i % 4 == 0}
        for i in range(20)
    ]
    log_file.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    monkeypatch.setattr(lg, "LOGS_PATH", log_file)
    return tmp_path


@pytest.fixture()
def monitor(monkeypatch, tmp_path):
    monkeypatch.setenv("ANALYTICS_DATA_PATH", str(tmp_path))
    import warden.agent_monitor as am
    monkeypatch.setattr(am, "SESSIONS_PATH", tmp_path / "sessions.json")
    from warden.agent_monitor import AgentMonitor
    m = AgentMonitor()
    m._redis = None
    return m


# ── Art30Generator ────────────────────────────────────────────────────────────


class TestArt30Generator:
    def test_generate_returns_dict(self, empty_logs):
        from warden.compliance.art30 import Art30Generator
        record = Art30Generator().generate(days=7)
        assert isinstance(record, dict)
        assert record["record_type"] == "GDPR_ART30_RECORD_OF_PROCESSING_ACTIVITIES"

    def test_generate_has_two_processing_activities(self, empty_logs):
        from warden.compliance.art30 import Art30Generator
        record = Art30Generator().generate()
        assert len(record["processing_activities"]) == 2

    def test_generate_traffic_summary_counts(self, populated_logs):
        from warden.compliance.art30 import Art30Generator
        record = Art30Generator().generate(days=1)
        stats = record["traffic_summary"]
        assert stats["total_requests"] == 20
        assert stats["blocked_requests"] > 0

    def test_generate_no_third_country_by_default(self, empty_logs, monkeypatch):
        monkeypatch.delenv("THIRD_COUNTRY_TRANSFER", raising=False)
        from warden.compliance.art30 import Art30Generator
        record = Art30Generator().generate()
        act = record["processing_activities"][0]
        assert act["third_country_transfer"] is False
        assert act["third_country_name"] is None

    def test_to_html_returns_string(self, populated_logs):
        from warden.compliance.art30 import Art30Generator
        gen    = Art30Generator()
        record = gen.generate(days=1)
        html   = gen.to_html(record)
        assert "<html" in html
        assert "Article 30" in html
        assert "<script" not in html   # no JS in compliance docs

    def test_to_html_contains_traffic_stats(self, populated_logs):
        from warden.compliance.art30 import Art30Generator
        gen    = Art30Generator()
        html   = gen.to_html(gen.generate(days=1))
        assert "20" in html   # total_requests

    def test_html_escapes_special_chars(self, empty_logs, monkeypatch):
        monkeypatch.setenv("CONTROLLER_NAME", "<Acme & Co>")
        import importlib  # noqa: E401

        import warden.compliance.art30 as m30
        importlib.reload(m30)
        html = m30.Art30Generator().to_html(m30.Art30Generator().generate())
        assert "<Acme" not in html
        assert "&lt;Acme" in html


# ── SOC2Exporter ──────────────────────────────────────────────────────────────


class TestSOC2Exporter:
    def test_export_returns_bytes_io(self, empty_logs):
        from warden.compliance.soc2 import SOC2Exporter
        buf = SOC2Exporter().export_bundle(days=1)
        assert isinstance(buf, io.BytesIO)

    def test_export_is_valid_zip(self, empty_logs):
        from warden.compliance.soc2 import SOC2Exporter
        buf = SOC2Exporter().export_bundle(days=1)
        assert zipfile.is_zipfile(buf)

    def test_export_contains_all_expected_files(self, empty_logs):
        from warden.compliance.soc2 import SOC2Exporter
        buf   = SOC2Exporter().export_bundle(days=1)
        names = {Path(n).name for n in zipfile.ZipFile(buf).namelist()}
        for expected in [
            "README.txt",
            "01_config_snapshot.json",
            "02_threat_statistics.json",
            "03_audit_chain_status.json",
            "04_evolved_rules.json",
            "05_sessions_summary.json",
            "06_audit_manifest.json",
        ]:
            assert expected in names, f"Missing: {expected}"

    def test_audit_manifest_has_hashes(self, empty_logs):
        from warden.compliance.soc2 import SOC2Exporter
        buf = SOC2Exporter().export_bundle(days=1)
        zf  = zipfile.ZipFile(buf)
        manifest_name = next(n for n in zf.namelist() if "audit_manifest" in n)
        manifest = json.loads(zf.read(manifest_name))
        assert "files" in manifest
        assert "01_config_snapshot.json" in manifest["files"]
        # SHA-256 hashes are 64 chars
        for h in manifest["files"].values():
            assert len(h) == 64

    def test_config_snapshot_redacts_secrets(self, empty_logs, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-real-key-1234")
        from warden.compliance.soc2 import SOC2Exporter
        buf   = SOC2Exporter().export_bundle(days=1)
        zf    = zipfile.ZipFile(buf)
        cfg_name = next(n for n in zf.namelist() if "config_snapshot" in n)
        cfg   = json.loads(zf.read(cfg_name))
        assert cfg["security_settings"]["ANTHROPIC_API_KEY"] == "[REDACTED]"

    def test_threat_statistics_no_content(self, populated_logs):
        from warden.compliance.soc2 import SOC2Exporter
        buf   = SOC2Exporter().export_bundle(days=1)
        zf    = zipfile.ZipFile(buf)
        stats_name = next(n for n in zf.namelist() if "threat_statistics" in n)
        stats = json.loads(zf.read(stats_name))
        assert "totals" in stats
        assert stats["totals"]["requests_processed"] == 20
        # Ensure no raw content field exists
        assert "content" not in stats
        assert "prompt" not in stats

    def test_audit_chain_status_without_trail(self, empty_logs):
        from warden.compliance.soc2 import SOC2Exporter
        buf  = SOC2Exporter(audit_trail=None).export_bundle(days=1)
        zf   = zipfile.ZipFile(buf)
        name = next(n for n in zf.namelist() if "audit_chain" in n)
        data = json.loads(zf.read(name))
        assert data["status"] == "audit_trail_unavailable"


# ── IncidentReporter ──────────────────────────────────────────────────────────


class TestIncidentReporter:
    def test_generate_unknown_session(self, monitor):
        from warden.compliance.incident import IncidentReporter
        r = IncidentReporter(agent_monitor=monitor).generate("no-such-sess")
        assert r["error"] != "" or r["summary"] == {}

    def test_generate_known_session_clean(self, monitor):
        from warden.compliance.incident import IncidentReporter
        monitor.record_tool_event("ir1", "read_file", "call", False, None)
        r = IncidentReporter(agent_monitor=monitor).generate("ir1")
        assert r["summary"]["session_id"] == "ir1"
        assert r["summary"]["tool_event_count"] == 1
        assert r["attestation"]["valid"] is True

    def test_generate_session_with_threat(self, monitor):
        from warden.compliance.incident import IncidentReporter
        # Trigger ROGUE_AGENT
        monitor.record_tool_event("ir2", "read_file", "call", False, None)
        monitor.record_tool_event("ir2", "http_post", "call", False, None)
        monitor.record_tool_event("ir2", "bash", "call", False, None)
        r = IncidentReporter(agent_monitor=monitor).generate("ir2")
        patterns = r["summary"]["patterns_detected"]
        assert "ROGUE_AGENT" in patterns

    def test_generate_includes_recommendations(self, monitor):
        from warden.compliance.incident import IncidentReporter
        monitor.record_tool_event("ir3", "read_file", "call", False, None)
        monitor.record_tool_event("ir3", "http_post", "call", False, None)
        monitor.record_tool_event("ir3", "bash", "call", False, None)
        r = IncidentReporter(agent_monitor=monitor).generate("ir3")
        assert len(r["recommended_actions"]) > 0
        triggers = [a["trigger"] for a in r["recommended_actions"]]
        assert "ROGUE_AGENT" in triggers

    def test_generate_revoked_session_noted(self, monitor):
        from warden.compliance.incident import IncidentReporter
        monitor.record_tool_event("ir4", "read_file", "call", False, None)
        monitor.revoke_session("ir4", "test_revoke")
        r = IncidentReporter(agent_monitor=monitor).generate("ir4")
        assert r["summary"]["revoked"] is True
        triggers = [a["trigger"] for a in r["recommended_actions"]]
        assert "session_revoked" in triggers

    def test_generate_tamper_detected_in_report(self, monitor):
        from warden.compliance.incident import IncidentReporter
        monitor.record_tool_event("ir5", "read_file", "call", False, None)
        # Tamper attestation
        with monitor._fallback_lock:
            monitor._fallback["ir5"]["meta"]["attestation_token"] = "00" * 16
        r = IncidentReporter(agent_monitor=monitor).generate("ir5")
        assert r["attestation"]["valid"] is False
        triggers = [a["trigger"] for a in r["recommended_actions"]]
        assert "attestation_mismatch" in triggers

    def test_to_html_returns_string(self, monitor):
        from warden.compliance.incident import IncidentReporter
        monitor.record_tool_event("ir6", "read_file", "call", False, None)
        rep  = IncidentReporter(agent_monitor=monitor)
        r    = rep.generate("ir6")
        html = rep.to_html(r)
        assert "<html" in html
        assert "Post-Mortem" in html
        assert "<script" not in html


# ── ComplianceDashboard ───────────────────────────────────────────────────────


class TestComplianceDashboard:
    def test_get_metrics_returns_dict(self, empty_logs):
        from warden.compliance.dashboard import ComplianceDashboard
        m = ComplianceDashboard().get_metrics(days=1)
        assert isinstance(m, dict)
        assert "roi_summary" in m

    def test_get_metrics_with_traffic(self, populated_logs):
        from warden.compliance.dashboard import ComplianceDashboard
        m = ComplianceDashboard().get_metrics(days=1)
        assert m["traffic"]["total_requests"] == 20
        assert m["traffic"]["blocked_requests"] > 0

    def test_roi_summary_non_negative(self, populated_logs):
        from warden.compliance.dashboard import ComplianceDashboard
        roi = ComplianceDashboard().get_metrics(days=1)["roi_summary"]
        assert roi["total_estimated_roi_usd"] >= 0
        assert roi["breach_cost_avoided_usd"] >= 0

    def test_assumptions_exposed(self, empty_logs):
        from warden.compliance.dashboard import ComplianceDashboard
        m = ComplianceDashboard().get_metrics(days=1)
        assert "assumptions" in m
        assert "llm_cost_per_token_usd" in m["assumptions"]

    def test_agent_security_with_monitor(self, populated_logs, monitor):
        from warden.compliance.dashboard import ComplianceDashboard
        # Create a session with ROGUE_AGENT
        monitor.record_tool_event("dash1", "read_file", "call", False, None)
        monitor.record_tool_event("dash1", "http_post", "call", False, None)
        monitor.record_tool_event("dash1", "bash", "call", False, None)
        m = ComplianceDashboard(agent_monitor=monitor).get_metrics(days=1)
        assert m["agent_security"]["rogue_agents_detected"] >= 1

    def test_secret_protection_counted(self, populated_logs):
        from warden.compliance.dashboard import ComplianceDashboard
        m = ComplianceDashboard().get_metrics(days=1)
        # populated_logs has secrets_found for every 5th entry (4 entries)
        assert m["secret_protection"]["total_secrets_redacted"] == 4
        assert m["secret_protection"]["estimated_credential_cost_avoided"] > 0
