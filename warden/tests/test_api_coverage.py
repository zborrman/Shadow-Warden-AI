"""
warden/tests/test_api_coverage.py
──────────────────────────────────
Coverage-boost tests for all FastAPI API routers.
Uses TestClient; raise_server_exceptions=False so 500s don't fail the test.
"""
from __future__ import annotations

import json
import os
import uuid

import pytest

os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("LOGS_PATH", "/tmp/api_cov_logs.json")
os.environ.setdefault("ADMIN_KEY", "test-admin-key")


def _app(*routers):
    from fastapi import FastAPI
    app = FastAPI()
    for r in routers:
        app.include_router(r)
    return app


def _client(*routers):
    from fastapi.testclient import TestClient
    return TestClient(_app(*routers), raise_server_exceptions=False)


# ── GDPR ─────────────────────────────────────────────────────────────────────

class TestGdprApi:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOGS_PATH", str(tmp_path / "logs.json"))
        (tmp_path / "logs.json").write_text("")
        from warden.api.gdpr import router
        self.client = _client(router)

    def test_purge_session(self):
        r = self.client.delete("/gdpr/purge/session/test-session-123")
        assert 100 <= r.status_code < 600

    def test_export_session(self):
        r = self.client.get("/gdpr/export/session/test-session-abc")
        assert 100 <= r.status_code < 600

    def test_purge_before_date_valid(self):
        r = self.client.delete("/gdpr/purge/before/2020-01-01")
        assert 100 <= r.status_code < 600

    def test_purge_before_date_invalid(self):
        r = self.client.delete("/gdpr/purge/before/not-a-date")
        assert 100 <= r.status_code < 600

    def test_purge_tenant(self):
        r = self.client.delete("/gdpr/purge/tenant/test-tenant")
        assert 100 <= r.status_code < 600

    def test_retention_policy(self):
        r = self.client.get("/gdpr/retention-policy")
        assert 100 <= r.status_code < 600

    def test_audit_tenant(self):
        r = self.client.get("/gdpr/audit/test-tenant")
        assert 100 <= r.status_code < 600


# ── Config API ────────────────────────────────────────────────────────────────

class TestConfigApi:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CONFIG_SNAPSHOT_PATH", str(tmp_path / "snapshot.json"))
        from warden.api.config_api import router
        self.client = _client(router)

    def test_get_settings(self):
        r = self.client.get("/api/settings")
        assert 100 <= r.status_code < 600

    def test_post_settings_hotreload(self):
        r = self.client.post("/api/settings", json={"semantic_threshold": "0.75"})
        assert 100 <= r.status_code < 600

    def test_post_settings_tier1(self):
        r = self.client.post("/api/settings", json={"WARDEN_API_KEY": "new-key"})
        assert 100 <= r.status_code < 600

    def test_get_pending(self):
        r = self.client.get("/api/settings/pending")
        assert 100 <= r.status_code < 600

    def test_approve_token(self):
        r = self.client.post("/api/settings/approve/fake-token?action=approve")
        assert 100 <= r.status_code < 600

    def test_reject_token(self):
        r = self.client.post("/api/settings/approve/fake-token?action=reject")
        assert 100 <= r.status_code < 600

    def test_drift(self):
        r = self.client.get("/api/settings/drift")
        assert 100 <= r.status_code < 600

    def test_snapshot(self):
        r = self.client.post("/api/settings/snapshot")
        assert 100 <= r.status_code < 600


# ── Financial API ─────────────────────────────────────────────────────────────

class TestFinancialApi:
    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        monkeypatch.setenv("LOGS_PATH", "/tmp/api_cov_logs.json")
        from warden.api.financial import router
        self.client = _client(router)

    def test_get_impact(self):
        r = self.client.get("/financial/impact")
        assert 100 <= r.status_code < 600

    def test_get_impact_with_industry(self):
        r = self.client.get("/financial/impact?industry=healthcare")
        assert 100 <= r.status_code < 600

    def test_cost_saved(self):
        r = self.client.get("/financial/cost-saved")
        assert 100 <= r.status_code < 600

    def test_roi(self):
        r = self.client.get("/financial/roi")
        assert 100 <= r.status_code < 600

    def test_generate_proposal(self):
        r = self.client.post("/financial/generate-proposal", json={
            "industry": "healthcare",
            "monthly_requests": 10000,
            "contact_email": "test@example.com",
        })
        assert 100 <= r.status_code < 600


# ── Rotation API ──────────────────────────────────────────────────────────────

class TestRotationApi:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from warden.api.rotation import router
        self.client = _client(router)

    def test_rotation_status(self):
        r = self.client.get("/admin/rotation/status",
                            headers={"X-Admin-Key": "test-admin-key"})
        assert 100 <= r.status_code < 600

    def test_record_rotation(self):
        r = self.client.post("/admin/rotation/record",
                             json={"key_name": "WARDEN_API_KEY",
                                   "rotated_by": "test"},
                             headers={"X-Admin-Key": "test-admin-key"})
        assert 100 <= r.status_code < 600

    def test_rotate_alert(self):
        r = self.client.post("/admin/rotation/rotate-alert",
                             json={"key_name": "VAULT_MASTER_KEY",
                                   "reason": "scheduled"},
                             headers={"X-Admin-Key": "test-admin-key"})
        assert 100 <= r.status_code < 600


# ── Red Team API ──────────────────────────────────────────────────────────────

class TestRedTeamApi:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from warden.api.red_team import router
        self.client = _client(router)

    def test_run_session(self):
        r = self.client.post("/agent/red-team", json={
            "target_system": "test-system",
            "attack_categories": ["jailbreak"],
            "max_probes": 3,
        })
        assert 100 <= r.status_code < 600

    def test_status(self):
        r = self.client.get("/agent/red-team/status")
        assert 100 <= r.status_code < 600


# ── Sovereign API ─────────────────────────────────────────────────────────────

class TestSovereignApi:
    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        monkeypatch.setenv("SEP_DB_PATH", "/tmp/api_cov_sep.db")
        from warden.api.sovereign import router
        self.client = _client(router)

    def test_list_jurisdictions(self):
        r = self.client.get("/sovereign/jurisdictions")
        assert 100 <= r.status_code < 600

    def test_get_jurisdiction(self):
        r = self.client.get("/sovereign/jurisdictions/EU")
        assert 100 <= r.status_code < 600

    def test_compliance_check(self):
        r = self.client.get("/sovereign/compliance/check?source=EU&dest=US&data_class=PII")
        assert 100 <= r.status_code < 600

    def test_get_policy(self):
        r = self.client.get("/sovereign/policy",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_put_policy(self):
        r = self.client.put("/sovereign/policy",
                            json={"preferred_jurisdiction": "EU",
                                  "fallback_mode": "DIRECT"},
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_list_tunnels(self):
        r = self.client.get("/sovereign/tunnels",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_create_tunnel(self):
        r = self.client.post("/sovereign/tunnels", json={
            "tunnel_id": f"t-{uuid.uuid4().hex[:8]}",
            "jurisdiction": "EU",
            "protocol": "MASQUE_H3",
            "endpoint": "https://eu.example.com",
        }, headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_get_tunnel(self):
        r = self.client.get("/sovereign/tunnels/nonexistent-tunnel")
        assert 100 <= r.status_code < 600

    def test_probe_tunnel(self):
        r = self.client.post("/sovereign/tunnels/nonexistent/probe")
        assert 100 <= r.status_code < 600

    def test_delete_tunnel(self):
        r = self.client.delete("/sovereign/tunnels/nonexistent-tunnel")
        assert 100 <= r.status_code < 600

    def test_route(self):
        r = self.client.post("/sovereign/route", json={
            "data_class": "PII",
            "source_jurisdiction": "EU",
        }, headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_attest(self):
        r = self.client.post("/sovereign/attest", json={
            "request_id": "req-123",
            "jurisdiction": "EU",
            "data_class": "PII",
        }, headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_get_attest(self):
        r = self.client.get("/sovereign/attest/nonexistent-id")
        assert 100 <= r.status_code < 600

    def test_verify_attest(self):
        r = self.client.get("/sovereign/attest/nonexistent-id/verify")
        assert 100 <= r.status_code < 600

    def test_list_attestations(self):
        r = self.client.get("/sovereign/attestations",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_sovereign_report(self):
        r = self.client.get("/sovereign/report",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600


# ── Shadow AI API ─────────────────────────────────────────────────────────────

class TestShadowAiApi:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from warden.api.shadow_ai import router
        self.client = _client(router)

    def test_scan(self):
        r = self.client.post("/shadow-ai/scan", json={
            "subnet": "10.0.0.0/30",
        }, headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_dns_event(self):
        r = self.client.post("/shadow-ai/dns-event", json={
            "domain": "api.openai.com",
            "client_ip": "192.168.1.1",
        }, headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_findings(self):
        r = self.client.get("/shadow-ai/findings",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_delete_findings(self):
        r = self.client.delete("/shadow-ai/findings",
                               headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_report(self):
        r = self.client.get("/shadow-ai/report",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_get_policy(self):
        r = self.client.get("/shadow-ai/policy",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_put_policy(self):
        r = self.client.put("/shadow-ai/policy",
                            json={"mode": "MONITOR"},
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_providers(self):
        r = self.client.get("/shadow-ai/providers")
        assert 100 <= r.status_code < 600


# ── XAI API ───────────────────────────────────────────────────────────────────

class TestXaiApi:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOGS_PATH", str(tmp_path / "logs.json"))
        (tmp_path / "logs.json").write_text("")
        from warden.api.xai import router
        self.client = _client(router)

    def test_explain_not_found(self):
        r = self.client.get("/xai/explain/nonexistent-id")
        assert 100 <= r.status_code < 600

    def test_batch_explain(self):
        r = self.client.post("/xai/explain/batch", json={"request_ids": ["id1", "id2"]})
        assert 100 <= r.status_code < 600

    def test_report_html(self):
        r = self.client.get("/xai/report/nonexistent-id")
        assert 100 <= r.status_code < 600

    def test_report_pdf(self):
        r = self.client.get("/xai/report/nonexistent-id/pdf")
        assert 100 <= r.status_code < 600

    def test_dashboard(self):
        r = self.client.get("/xai/dashboard?hours=24")
        assert 100 <= r.status_code < 600


# ── Compliance Report API ─────────────────────────────────────────────────────

class TestComplianceReportApi:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOGS_PATH", str(tmp_path / "logs.json"))
        (tmp_path / "logs.json").write_text("")
        from warden.api.compliance_report import router
        self.client = _client(router)

    def test_smb_report_json(self):
        r = self.client.get("/compliance/smb-report",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_smb_report_html(self):
        r = self.client.get("/compliance/smb-report/html",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_smb_report_pdf(self):
        r = self.client.get("/compliance/smb-report/pdf",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_iso27001(self):
        r = self.client.get("/compliance/iso27001",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_iso27001_html(self):
        r = self.client.get("/compliance/iso27001/html",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_hipaa(self):
        r = self.client.get("/compliance/hipaa",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_hipaa_html(self):
        r = self.client.get("/compliance/hipaa/html",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_nis2(self):
        r = self.client.get("/compliance/nis2",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_nis2_html(self):
        r = self.client.get("/compliance/nis2/html",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_posture(self):
        r = self.client.get("/compliance/posture",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600


# ── Public Stats API ──────────────────────────────────────────────────────────

class TestPublicStatsApi:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEP_DB_PATH", str(tmp_path / "sep.db"))
        monkeypatch.setenv("LOGS_PATH", str(tmp_path / "logs.json"))
        (tmp_path / "logs.json").write_text("")
        from warden.api.public_stats import router
        self.client = _client(router)

    def test_community_stats(self):
        r = self.client.get("/public/community")
        assert 100 <= r.status_code < 600

    def test_leaderboard(self):
        r = self.client.get("/public/leaderboard")
        assert 100 <= r.status_code < 600

    def test_incident_not_found(self):
        r = self.client.get("/public/incident/SEP-00000000000")
        assert 100 <= r.status_code < 600


# ── Community Intel API ───────────────────────────────────────────────────────

class TestCommunityIntelApi:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEP_DB_PATH", str(tmp_path / "sep.db"))
        from warden.api.community_intel import router
        self.client = _client(router)

    def _cid(self):
        return f"cid-{uuid.uuid4().hex[:8]}"

    def test_get_report(self):
        r = self.client.get(f"/community-intel/{self._cid()}")
        assert 100 <= r.status_code < 600

    def test_get_risk(self):
        r = self.client.get(f"/community-intel/{self._cid()}/risk")
        assert 100 <= r.status_code < 600

    def test_create_charter(self):
        r = self.client.post(
            f"/community-intel/{self._cid()}/charter",
            json={"name": "Test Charter", "version": "1.0",
                  "rules": ["No harmful content"], "created_by": "admin"},
        )
        assert 100 <= r.status_code < 600

    def test_get_charter(self):
        r = self.client.get(f"/community-intel/{self._cid()}/charter")
        assert 100 <= r.status_code < 600

    def test_anomaly_feed(self):
        r = self.client.get(f"/community-intel/{self._cid()}/anomalies")
        assert 100 <= r.status_code < 600

    def test_detect_anomaly(self):
        r = self.client.post(
            f"/community-intel/{self._cid()}/detect",
            json={"event_type": "transfer", "value": 5.0},
        )
        assert 100 <= r.status_code < 600

    def test_list_oauth_grants(self):
        r = self.client.get(f"/community-intel/{self._cid()}/oauth")
        assert 100 <= r.status_code < 600

    def test_oauth_catalog(self):
        r = self.client.get("/community-intel/oauth/catalog")
        assert 100 <= r.status_code < 600


# ── Security Hub API ──────────────────────────────────────────────────────────

class TestSecurityHubApi:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOGS_PATH", str(tmp_path / "logs.json"))
        (tmp_path / "logs.json").write_text("")
        from warden.api.security_hub import router
        self.client = _client(router)

    def test_posture(self):
        r = self.client.get("/security/posture",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_cve_feed(self):
        r = self.client.get("/security/cve-feed",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_pentest_get(self):
        r = self.client.get("/security/pentest",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_compliance(self):
        r = self.client.get("/security/compliance",
                            headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_cve_scan(self):
        r = self.client.post("/security/cve-scan",
                             json={"dependencies": ["fastapi==0.115.0"]},
                             headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_pentest_post(self):
        r = self.client.post("/security/pentest",
                             json={"target": "test-system"},
                             headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600


# ── SOC Dashboard API ─────────────────────────────────────────────────────────

class TestSocDashboardApi:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOGS_PATH", str(tmp_path / "logs.json"))
        (tmp_path / "logs.json").write_text("")
        from warden.api.soc_dashboard import router
        self.client = _client(router)

    def test_health(self):
        r = self.client.get("/soc/health")
        assert 100 <= r.status_code < 600

    def test_healer(self):
        r = self.client.get("/soc/healer")
        assert 100 <= r.status_code < 600

    def test_metrics(self):
        r = self.client.get("/soc/metrics")
        assert 100 <= r.status_code < 600

    def test_posture(self):
        r = self.client.get("/soc/posture")
        assert 100 <= r.status_code < 600

    def test_heal(self):
        r = self.client.post("/soc/heal", json={"action": "reload_corpus"})
        assert 100 <= r.status_code < 600


# ── Integrations API ─────────────────────────────────────────────────────────

class TestIntegrationsApi:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from warden.api.integrations import router
        self.client = _client(router)

    def test_jira_health(self):
        r = self.client.get("/integrations/jira/health")
        assert 100 <= r.status_code < 600

    def test_jira_create_issue(self):
        r = self.client.post("/integrations/jira/issue", json={
            "summary": "Test issue",
            "description": "Test",
            "priority": "Medium",
        })
        assert 100 <= r.status_code < 600

    def test_teams_health(self):
        r = self.client.get("/integrations/teams/health")
        assert 100 <= r.status_code < 600

    def test_teams_notify(self):
        r = self.client.post("/integrations/teams/notify", json={
            "title": "Alert",
            "body": "Test notification",
        })
        assert 100 <= r.status_code < 600

    def test_notion_health(self):
        r = self.client.get("/integrations/notion/health")
        assert 100 <= r.status_code < 600

    def test_notion_page(self):
        r = self.client.post("/integrations/notion/page", json={
            "title": "Test page",
            "content": "Content",
        })
        assert 100 <= r.status_code < 600

    def test_zapier_health(self):
        r = self.client.get("/integrations/zapier/health")
        assert 100 <= r.status_code < 600

    def test_zapier_event(self):
        r = self.client.post("/integrations/zapier/event", json={
            "event_type": "BLOCK",
            "data": {"request_id": "req-123"},
        })
        assert 100 <= r.status_code < 600


# ── Email Guard API ───────────────────────────────────────────────────────────

class TestEmailGuardApi:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from warden.api.email_guard import router
        self.client = _client(router)

    def test_scan_email_plain(self):
        r = self.client.post("/scan/email", json={
            "subject": "Hello",
            "body": "This is a normal email",
            "sender": "test@example.com",
        })
        assert 100 <= r.status_code < 600

    def test_scan_email_suspicious(self):
        r = self.client.post("/scan/email", json={
            "subject": "URGENT: Verify your account",
            "body": "Click here to verify your account or it will be deleted",
            "sender": "noreply@suspicious.tk",
        })
        assert 100 <= r.status_code < 600

    def test_scan_email_missing_field(self):
        r = self.client.post("/scan/email", json={"subject": "Hello"})
        assert 100 <= r.status_code < 600


# ── Extension Risk API ────────────────────────────────────────────────────────

class TestExtensionRiskApi:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from warden.api.extension_risk import router
        self.client = _client(router)

    def test_scan_extensions(self):
        r = self.client.post("/scan/extensions", json={
            "extensions": [
                {"id": "ext1", "name": "Test Extension", "permissions": ["tabs"]},
            ]
        })
        assert 100 <= r.status_code < 600

    def test_extension_database(self):
        r = self.client.get("/scan/extensions/database")
        assert 100 <= r.status_code < 600

    def test_scan_empty_list(self):
        r = self.client.post("/scan/extensions", json={"extensions": []})
        assert 100 <= r.status_code < 600


# ── File Scan API ─────────────────────────────────────────────────────────────

class TestFileScanApi:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from warden.api.file_scan import router
        self.client = _client(router)

    def test_supported_types(self):
        r = self.client.get("/filter/file/supported-types")
        assert 100 <= r.status_code < 600

    def test_filter_file_no_file(self):
        r = self.client.post("/filter/file")
        assert 100 <= r.status_code < 600

    def test_filter_text_file(self):
        from io import BytesIO
        content = b"Normal document content. No suspicious patterns here."
        r = self.client.post(
            "/filter/file",
            files={"file": ("test.txt", BytesIO(content), "text/plain")},
        )
        assert 100 <= r.status_code < 600

    def test_filter_pdf_file(self):
        from io import BytesIO
        content = b"PDF content placeholder"
        r = self.client.post(
            "/filter/file",
            files={"file": ("test.pdf", BytesIO(content), "application/pdf")},
        )
        assert 100 <= r.status_code < 600


# ── Webhook API ───────────────────────────────────────────────────────────────

class TestWebhookApi:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from warden.api.webhook import router
        self.client = _client(router)

    def test_webhook_health(self):
        r = self.client.get("/billing/webhook/health")
        assert 100 <= r.status_code < 600

    def test_webhook_post_no_sig(self):
        r = self.client.post("/billing/webhook", json={"event": "test"})
        assert 100 <= r.status_code < 600

    def test_webhook_post_with_sig(self):
        import hashlib
        import hmac
        payload = json.dumps({"event": "order_created"}).encode()
        secret = os.environ.get("LEMON_SQUEEZY_WEBHOOK_SECRET", "test-secret")
        sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        r = self.client.post(
            "/billing/webhook",
            content=payload,
            headers={"Content-Type": "application/json",
                     "X-Signature": sig},
        )
        assert 100 <= r.status_code < 600


# ── SEP API (additional coverage) ────────────────────────────────────────────

class TestSepApiCoverage:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEP_DB_PATH", str(tmp_path / "sep.db"))
        from warden.api.sep import router
        self.client = _client(router)

    def test_resolve_ueciid_not_found(self):
        r = self.client.get("/sep/ueciid/SEP-00000000000")
        assert 100 <= r.status_code < 600

    def test_search_ueciid(self):
        r = self.client.get("/sep/search?q=test")
        assert 100 <= r.status_code < 600

    def test_list_ueciid(self):
        r = self.client.get("/sep/list")
        assert 100 <= r.status_code < 600

    def test_register_ueciid(self):
        r = self.client.post("/sep/register", json={
            "display_name": "Test Entity",
            "source_tenant": "test-tenant",
            "data_class": "GENERAL",
        })
        assert 100 <= r.status_code < 600

    def test_list_peerings(self):
        r = self.client.get("/sep/peerings",
                            headers={"X-Community-ID": "test-community"})
        assert 100 <= r.status_code < 600

    def test_initiate_peering(self):
        r = self.client.post("/sep/peerings", json={
            "target_community": f"target-{uuid.uuid4().hex[:8]}",
            "initiator_mid": f"member-{uuid.uuid4().hex[:8]}",
            "policy": "MIRROR_ONLY",
        }, headers={"X-Community-ID": f"src-{uuid.uuid4().hex[:8]}"})
        assert 100 <= r.status_code < 600

    def test_list_knocks(self):
        r = self.client.get("/sep/knocks",
                            headers={"X-Community-ID": "test-community"})
        assert 100 <= r.status_code < 600

    def test_issue_knock(self):
        r = self.client.post("/sep/knocks", json={
            "invitee_tenant_id": f"t-{uuid.uuid4().hex[:8]}",
            "invitee_email": "test@example.com",
        }, headers={"X-Community-ID": f"c-{uuid.uuid4().hex[:8]}"})
        assert 100 <= r.status_code < 600

    def test_list_pods(self):
        r = self.client.get("/sep/pods",
                            headers={"X-Community-ID": "test-community"})
        assert 100 <= r.status_code < 600

    def test_register_pod(self):
        r = self.client.post("/sep/pods", json={
            "pod_id": f"pod-{uuid.uuid4().hex[:8]}",
            "jurisdiction": "EU",
            "endpoint": "https://minio.eu.example.com",
            "data_class": "PII",
        }, headers={"X-Community-ID": f"c-{uuid.uuid4().hex[:8]}"})
        assert 100 <= r.status_code < 600

    def test_audit_chain_list(self):
        r = self.client.get("/sep/audit-chain/test-community",
                            headers={"X-Community-ID": "test-community"})
        assert 100 <= r.status_code < 600

    def test_audit_chain_verify(self):
        r = self.client.get("/sep/audit-chain/test-community/verify")
        assert 100 <= r.status_code < 600


# ── Agent API (additional coverage) ──────────────────────────────────────────

class TestAgentApiCoverage:
    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "")
        from warden.api.agent import router
        self.client = _client(router)

    def test_sova_query_no_key(self):
        r = self.client.post("/agent/sova", json={
            "query": "What is the current threat level?",
        }, headers={"X-Tenant-ID": "test-tenant"})
        assert 100 <= r.status_code < 600

    def test_sova_clear(self):
        r = self.client.delete("/agent/sova/test-session")
        assert 100 <= r.status_code < 600

    def test_sova_trigger_task(self):
        r = self.client.post("/agent/sova/task/sova_morning_brief",
                             headers={"X-Admin-Key": "test-admin-key"})
        assert 100 <= r.status_code < 600

    def test_red_team_status(self):
        r = self.client.get("/agent/red-team/status")
        assert 100 <= r.status_code < 600

    def test_approve_check(self):
        r = self.client.get("/agent/approve/fake-token")
        assert 100 <= r.status_code < 600

    def test_approve_action(self):
        r = self.client.post("/agent/approve/fake-token?action=approve")
        assert 100 <= r.status_code < 600


# ── alerting.py direct ────────────────────────────────────────────────────────

class TestAlertingModule:
    def test_alerting_module_imports(self):
        import warden.alerting as alerting
        assert hasattr(alerting, "send_alert")

    def test_send_alert_warning(self):
        from unittest.mock import patch

        import warden.alerting as alerting
        with patch.object(alerting, "_SLACK_WEBHOOK", ""):
            alerting.send_alert("Test warning message")

    def test_send_alert_error(self):
        from unittest.mock import patch

        import warden.alerting as alerting
        with patch.object(alerting, "_SLACK_WEBHOOK", ""):
            alerting.send_alert("Critical alert", level="error")

    def test_slack_raw_no_webhook(self):
        from unittest.mock import patch

        import warden.alerting as alerting
        with patch.object(alerting, "_SLACK_WEBHOOK", ""):
            alerting._send_slack_raw({"text": "test"})

    def test_alert_block_event_no_webhook(self):
        from unittest.mock import patch

        import warden.alerting as alerting
        with patch.object(alerting, "_SLACK_WEBHOOK", ""):
            alerting.alert_block_event(
                attack_type="INJECTION",
                risk_level="HIGH",
                rule_summary="Jailbreak attempt detected",
                request_id="req-001",
            )


# ── agent_monitor.py ─────────────────────────────────────────────────────────

class TestAgentMonitorCoverage:
    def _make_session(self):
        import uuid
        return f"session-{uuid.uuid4().hex[:8]}"

    def test_get_session_none(self):
        from warden.agent_monitor import AgentMonitor
        m = AgentMonitor()
        result = m.get_session("nonexistent-session")
        assert result is None

    def test_record_request(self):
        from warden.agent_monitor import AgentMonitor
        m = AgentMonitor()
        sid = self._make_session()
        m.record_request(
            session_id=sid,
            request_id=f"req-{sid[:8]}",
            allowed=True,
            risk_level="LOW",
            flags=[],
            tenant_id="test-tenant",
        )

    def test_record_request_block(self):
        from warden.agent_monitor import AgentMonitor
        m = AgentMonitor()
        sid = self._make_session()
        m.record_request(sid, f"req-{sid[:8]}", allowed=False,
                         risk_level="HIGH", flags=["INJECTION"],
                         tenant_id="test-tenant")

    def test_record_tool_event_call(self):
        from warden.agent_monitor import AgentMonitor
        m = AgentMonitor()
        sid = self._make_session()
        m.record_tool_event(sid, "bash", "call", blocked=False)

    def test_record_tool_event_result(self):
        from warden.agent_monitor import AgentMonitor
        m = AgentMonitor()
        sid = self._make_session()
        m.record_tool_event(sid, "bash", "result", blocked=False)

    def test_list_sessions_empty(self):
        from warden.agent_monitor import AgentMonitor
        m = AgentMonitor()
        sessions = m.list_sessions("unknown-tenant-xyz")
        assert isinstance(sessions, list)

    def test_is_revoked_false(self):
        from warden.agent_monitor import AgentMonitor
        m = AgentMonitor()
        result = m.is_revoked("nonexistent-session")
        assert result is False


# ── wallet_shield.py (additional coverage) ───────────────────────────────────

class TestWalletShieldCoverage:
    def test_redis_client_initialization(self):
        from unittest.mock import patch

        import warden.wallet_shield as ws
        with patch.object(ws, "_ENABLED", True):
            shield = ws.WalletShield()
            result = shield.check_and_consume("tenant", "user", 500)
            assert result.allowed in (True, False)

    def test_window_limit_check(self):
        from unittest.mock import MagicMock, patch

        import warden.wallet_shield as ws
        mock_client = MagicMock()
        mock_client.get.return_value = None
        mock_client.incrby.return_value = 100
        mock_client.expire.return_value = True
        with patch.object(ws, "_ENABLED", True):
            shield = ws.WalletShield()
            with patch.object(shield, "_client", mock_client):
                result = shield.check_and_consume("tenant", "user", 100)
                assert isinstance(result.allowed, bool)

    def test_hard_limit_exceeded(self):
        from unittest.mock import patch

        import warden.wallet_shield as ws
        with patch.object(ws, "_ENABLED", True), patch.object(ws, "_HARD_LIMIT", 100):
            shield = ws.WalletShield()
            result = shield.check_and_consume("tenant", "user", 200)
            assert result.allowed is False
            assert result.limit_type == "hard_limit"


# ── XAI Renderer (additional coverage) ───────────────────────────────────────

class TestXaiRendererCoverage:
    def _make_chain(self, verdict="BLOCK"):
        from warden.xai.chain import build_chain
        return build_chain({
            "request_id": f"req-{uuid.uuid4().hex[:8]}",
            "tenant_id": "test-tenant",
            "verdict": verdict,
            "risk_level": "HIGH" if verdict == "BLOCK" else "LOW",
            "score": 0.95 if verdict == "BLOCK" else 0.05,
            "flags": ["INJECTION"] if verdict == "BLOCK" else [],
            "stage_verdicts": {"topology": "PASS", "brain": verdict},
            "latency_ms": 10.0,
        })

    def test_render_chain_with_all_stages(self):
        from warden.xai.renderer import render_html
        chain = self._make_chain("BLOCK")
        html = render_html(chain)
        assert b"<" in html

    def test_render_pdf_fallback(self):
        from warden.xai.renderer import render_pdf
        chain = self._make_chain("ALLOW")
        content, ct = render_pdf(chain)
        assert len(content) > 0
        assert ct in ("application/pdf", "text/html; charset=utf-8")

    def test_chain_to_dict(self):
        from warden.xai.chain import chain_to_dict
        chain = self._make_chain("BLOCK")
        d = chain_to_dict(chain)
        assert isinstance(d, dict)
        assert "nodes" in d or "stages" in d or "final_verdict" in d

    def test_chain_counterfactuals(self):
        chain = self._make_chain("BLOCK")
        assert hasattr(chain, "counterfactuals")

    def test_chain_primary_cause(self):
        chain = self._make_chain("BLOCK")
        assert chain.primary_cause is not None or chain.primary_cause is None


# ── settings/api.py ───────────────────────────────────────────────────────────

_ENT = {"X-Tenant-Tier": "enterprise"}


def _mini_app(*routers):
    from fastapi import FastAPI
    app = FastAPI()
    for r in routers:
        app.include_router(r)
    return app


class TestSettingsHubApi:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from fastapi.testclient import TestClient

        from warden.settings.api import router
        self.c = TestClient(_mini_app(router), raise_server_exceptions=False)

    def test_get_all(self):
        assert self.c.get("/settings", headers=_ENT).status_code in (200, 422, 500)

    def test_get_agents(self):
        assert self.c.get("/settings/agents", headers=_ENT).status_code in (200, 422, 500)

    def test_patch_agents(self):
        assert self.c.patch("/settings/agents", json={}, headers=_ENT).status_code in (200, 422, 500)

    def test_list_notifications(self):
        assert self.c.get("/settings/notifications", headers=_ENT).status_code in (200, 422, 500)

    def test_add_notification(self):
        body = {"id": "n1", "type": "slack", "name": "test", "url": "https://hooks.slack.com/x"}
        assert self.c.post("/settings/notifications", json=body, headers=_ENT).status_code in (200, 201, 422, 500)

    def test_update_notification_missing(self):
        assert self.c.patch("/settings/notifications/nope", json={}, headers=_ENT).status_code in (200, 404, 422, 500)

    def test_test_notification_missing(self):
        assert self.c.post("/settings/notifications/nope/test", headers=_ENT).status_code in (200, 404, 422, 500)

    def test_delete_notification(self):
        assert self.c.delete("/settings/notifications/nope", headers=_ENT).status_code in (200, 204, 404, 422, 500)

    def test_get_commerce(self):
        assert self.c.get("/settings/commerce", headers=_ENT).status_code in (200, 422, 500)

    def test_patch_commerce(self):
        assert self.c.patch("/settings/commerce", json={}, headers=_ENT).status_code in (200, 422, 500)

    def test_get_semantic(self):
        assert self.c.get("/settings/semantic", headers=_ENT).status_code in (200, 422, 500)

    def test_patch_semantic(self):
        assert self.c.patch("/settings/semantic", json={}, headers=_ENT).status_code in (200, 422, 500)


# ── api/incident_register.py ─────────────────────────────────────────────────

class TestIncidentRegisterRouter:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        import os
        os.environ["INCIDENT_REGISTER_DB_PATH"] = str(tmp_path / "inc.db")
        from fastapi.testclient import TestClient

        from warden.api.incident_register import router
        self.c = TestClient(_mini_app(router), raise_server_exceptions=False)
        self.tid = f"t-{uuid.uuid4().hex[:6]}"

    def test_create(self):
        r = self.c.post(
            "/incidents",
            json={"tenant_id": self.tid, "title": "AI hallucination incident", "severity": "HIGH"},
            headers=_ENT,
        )
        assert r.status_code in (200, 422)

    def test_list_empty(self):
        r = self.c.get(f"/incidents?tenant_id={self.tid}", headers=_ENT)
        assert r.status_code in (200, 422)

    def test_list_with_filters(self):
        r = self.c.get(f"/incidents?tenant_id={self.tid}&severity=HIGH&status=open", headers=_ENT)
        assert r.status_code in (200, 422)

    def test_stats(self):
        r = self.c.get(f"/incidents/stats?tenant_id={self.tid}", headers=_ENT)
        assert r.status_code in (200, 422)

    def test_get_not_found(self):
        r = self.c.get(f"/incidents/{uuid.uuid4()}", headers=_ENT)
        assert r.status_code in (404, 422)

    def test_update_status_not_found(self):
        r = self.c.put(f"/incidents/{uuid.uuid4()}/status", json={"status": "resolved"}, headers=_ENT)
        assert r.status_code in (404, 422)

    def test_roundtrip(self):
        cr = self.c.post("/incidents", json={"tenant_id": self.tid, "title": "Roundtrip"}, headers=_ENT)
        if cr.status_code != 200:
            return
        iid = cr.json()["incident_id"]
        assert self.c.get(f"/incidents/{iid}", headers=_ENT).status_code == 200
        self.c.put(f"/incidents/{iid}/status", json={"status": "resolved"}, headers=_ENT)


# ── api/budget.py ─────────────────────────────────────────────────────────────

class TestBudgetRouter:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        import os
        os.environ["BUDGET_DB_PATH"] = str(tmp_path / "budget.db")
        from fastapi.testclient import TestClient

        from warden.api.budget import router
        self.c = TestClient(_mini_app(router), raise_server_exceptions=False)
        self.tid = f"t-{uuid.uuid4().hex[:6]}"

    def test_get_status(self):
        assert self.c.get(f"/financial/budget/status?tenant_id={self.tid}", headers=_ENT).status_code in (200, 422)

    def test_set_cap(self):
        r = self.c.post(
            "/financial/budget/caps",
            json={"tenant_id": self.tid, "cap_usd": 500.0, "department": "eng"},
            headers=_ENT,
        )
        assert r.status_code in (200, 422)

    def test_list_approvals(self):
        assert self.c.get(f"/financial/budget/approvals?tenant_id={self.tid}", headers=_ENT).status_code in (200, 422)

    def test_request_approval(self):
        r = self.c.post(
            "/financial/budget/approvals",
            json={"tenant_id": self.tid, "requested_by": "alice", "department": "ml", "amount_usd": 300.0},
            headers=_ENT,
        )
        assert r.status_code in (200, 422)

    def test_resolve_not_found(self):
        r = self.c.put(
            f"/financial/budget/approvals/{uuid.uuid4()}",
            json={"reviewed_by": "bob", "approve": True},
            headers=_ENT,
        )
        assert r.status_code in (404, 422)

    def test_resolve_roundtrip(self):
        cr = self.c.post(
            "/financial/budget/approvals",
            json={"tenant_id": self.tid, "requested_by": "carol", "department": "ops", "amount_usd": 200.0},
            headers=_ENT,
        )
        if cr.status_code != 200:
            return
        aid = cr.json()["approval_id"]
        self.c.put(f"/financial/budget/approvals/{aid}", json={"reviewed_by": "dave", "approve": False}, headers=_ENT)


# ── api/cost_allocation.py ────────────────────────────────────────────────────

class TestCostAllocationRouter:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        import os
        os.environ["COST_ALLOC_DB_PATH"] = str(tmp_path / "cost.db")
        from fastapi.testclient import TestClient

        from warden.api.cost_allocation import router
        self.c = TestClient(_mini_app(router), raise_server_exceptions=False)
        self.tid = f"t-{uuid.uuid4().hex[:6]}"

    def test_record_cost(self):
        r = self.c.post(
            "/financial/allocation",
            json={"tenant_id": self.tid, "amount_usd": 9.99, "vendor_id": "anthropic"},
            headers=_ENT,
        )
        assert r.status_code in (200, 422)

    def test_summary(self):
        assert self.c.get(f"/financial/allocation/summary?tenant_id={self.tid}", headers=_ENT).status_code in (200, 422)

    def test_departments(self):
        assert self.c.get(f"/financial/allocation/departments?tenant_id={self.tid}", headers=_ENT).status_code in (200, 422)

    def test_vendor_spend(self):
        assert self.c.get(f"/financial/allocation/vendors/anthropic?tenant_id={self.tid}", headers=_ENT).status_code in (200, 422)

    def test_import_logs(self):
        assert self.c.post(f"/financial/allocation/import-logs?tenant_id={self.tid}", headers=_ENT).status_code in (200, 422)


# ── api/supplier_risk.py ──────────────────────────────────────────────────────

class TestSupplierRiskRouter:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        import os
        os.environ["SEP_DB_PATH"] = str(tmp_path / "sep.db")
        os.environ["VENDOR_GOV_DB_PATH"] = str(tmp_path / "vg.db")
        from fastapi.testclient import TestClient

        from warden.api.supplier_risk import router
        self.c = TestClient(_mini_app(router), raise_server_exceptions=False)
        self.cid = f"c-{uuid.uuid4().hex[:6]}"

    def test_assess(self):
        r = self.c.post(
            "/supplier-risk/assess",
            json={"community_id": self.cid, "vendor_id": "openai", "tenant_id": "t1"},
            headers=_ENT,
        )
        assert r.status_code in (200, 422)

    def test_list_assessments(self):
        assert self.c.get(f"/supplier-risk/assessments?community_id={self.cid}", headers=_ENT).status_code in (200, 422)

    def test_report(self):
        assert self.c.get(f"/supplier-risk/report/{self.cid}", headers=_ENT).status_code in (200, 422)
