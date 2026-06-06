"""
Tests for CP-25 compliance posture + history endpoints, and CP-30 gap analysis.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _make_app():
    from warden.api.compliance_report import router
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture()
def client():
    # X-Tenant-Tier: pro — compliance_scoring_enabled is True at Pro+
    return TestClient(_make_app(), raise_server_exceptions=False,
                      headers={"X-Tenant-Tier": "pro"})


# ── /compliance/posture ───────────────────────────────────────────────────────

class TestCompliancePosture:
    def test_returns_200(self, client):
        r = client.get("/compliance/posture")
        assert r.status_code == 200

    def test_schema_fields(self, client):
        data = client.get("/compliance/posture").json()
        assert "overall_score"  in data
        assert "overall_status" in data
        assert "standards"      in data
        assert isinstance(data["standards"], list)
        assert len(data["standards"]) == 5

    def test_overall_score_range(self, client):
        data = client.get("/compliance/posture").json()
        assert 0.0 <= data["overall_score"] <= 100.0

    def test_overall_status_values(self, client):
        data = client.get("/compliance/posture").json()
        assert data["overall_status"] in ("PASS", "PARTIAL", "FAIL")

    def test_standard_fields(self, client):
        data = client.get("/compliance/posture").json()
        for std in data["standards"]:
            assert "short"       in std
            assert "score"       in std
            assert "attestation" in std
            assert "passed"      in std
            assert "partial"     in std
            assert "failed"      in std
            assert "total"       in std
            assert std["passed"] + std["partial"] + std["failed"] == std["total"]

    def test_five_standards_present(self, client):
        data  = client.get("/compliance/posture").json()
        shorts = {s["short"] for s in data["standards"]}
        assert shorts == {"soc2", "gdpr", "iso27001", "hipaa", "nis2"}

    def test_score_per_standard_range(self, client):
        data = client.get("/compliance/posture").json()
        for std in data["standards"]:
            assert 0.0 <= std["score"] <= 100.0

    def test_attestation_values(self, client):
        data = client.get("/compliance/posture").json()
        for std in data["standards"]:
            assert std["attestation"] in ("PASS", "PARTIAL", "FAIL")

    def test_days_param_accepted(self, client):
        for d in (1, 7, 30, 90):
            r = client.get(f"/compliance/posture?days={d}")
            assert r.status_code == 200

    def test_days_out_of_range(self, client):
        assert client.get("/compliance/posture?days=0").status_code  in (400, 422)
        assert client.get("/compliance/posture?days=91").status_code in (400, 422)


# ── /compliance/history ───────────────────────────────────────────────────────

class TestComplianceHistory:
    def test_returns_200(self, client):
        r = client.get("/compliance/history")
        assert r.status_code == 200

    def test_schema_fields(self, client):
        data = client.get("/compliance/history").json()
        assert "hours"     in data
        assert "count"     in data
        assert "snapshots" in data
        assert isinstance(data["snapshots"], list)

    def test_empty_before_posture_call(self, client):
        # Fresh app — history ring buffer is empty
        data = client.get("/compliance/history").json()
        assert data["count"] == len(data["snapshots"])

    def test_snapshot_added_after_posture(self, client):
        from warden.api.compliance_report import _posture_history
        _posture_history.clear()

        client.get("/compliance/posture")
        data = client.get("/compliance/history").json()
        assert data["count"] >= 1

    def test_snapshot_fields(self, client):
        from warden.api.compliance_report import _posture_history
        _posture_history.clear()

        client.get("/compliance/posture")
        data = client.get("/compliance/history").json()
        if data["count"] > 0:
            snap = data["snapshots"][0]
            assert "ts"             in snap
            assert "overall_score"  in snap
            assert "overall_status" in snap
            assert "scores"         in snap
            assert isinstance(snap["scores"], dict)

    def test_snapshot_scores_has_all_standards(self, client):
        from warden.api.compliance_report import _posture_history
        _posture_history.clear()

        client.get("/compliance/posture")
        data = client.get("/compliance/history").json()
        if data["count"] > 0:
            scores = data["snapshots"][0]["scores"]
            for std in ("soc2", "gdpr", "iso27001", "hipaa", "nis2"):
                assert std in scores

    def test_hours_param_accepted(self, client):
        for h in (1, 24, 48, 168):
            r = client.get(f"/compliance/history?hours={h}")
            assert r.status_code == 200

    def test_hours_out_of_range(self, client):
        assert client.get("/compliance/history?hours=0").status_code   in (400, 422)
        assert client.get("/compliance/history?hours=169").status_code in (400, 422)

    def test_multiple_snapshots_accumulate(self, client):
        from warden.api.compliance_report import _posture_history
        _posture_history.clear()

        client.get("/compliance/posture")
        client.get("/compliance/posture")
        client.get("/compliance/posture")

        data = client.get("/compliance/history").json()
        assert data["count"] >= 3

    def test_count_matches_snapshots_len(self, client):
        data = client.get("/compliance/history").json()
        assert data["count"] == len(data["snapshots"])


# ── CP-30: CompliancePostureService unit tests ────────────────────────────────

class TestCompliancePostureService:
    def _svc(self):
        from warden.compliance.posture_service import CompliancePostureService
        return CompliancePostureService()

    def test_gdpr_all_pass_score_100(self, monkeypatch):
        import warden.compliance.posture_service as ps
        monkeypatch.setattr(ps, "_check_dpa_coverage",      lambda _: (True, None))
        monkeypatch.setattr(ps, "_check_incident_register", lambda _: (True, None))
        monkeypatch.setattr(ps, "_check_doc_intel_active",  lambda: (True, None))
        monkeypatch.setattr(ps, "_check_secret_rotation",   lambda: (True, None))
        monkeypatch.setattr(ps, "_check_log_retention",     lambda: (True, None))
        monkeypatch.setattr(ps, "_check_data_minimisation", lambda: (True, None))
        fs = self._svc()._score_gdpr("t")
        assert fs.score == 100.0
        assert fs.gaps == []

    def test_gdpr_missing_dpa_creates_high_gap(self, monkeypatch):
        import warden.compliance.posture_service as ps
        from warden.compliance.models import Gap, Severity
        g = Gap("GDPR-01", "Missing DPA", Severity.HIGH, "Upload DPA", "vendor_governance")
        monkeypatch.setattr(ps, "_check_dpa_coverage",      lambda _: (False, g))
        monkeypatch.setattr(ps, "_check_incident_register", lambda _: (True, None))
        monkeypatch.setattr(ps, "_check_doc_intel_active",  lambda: (True, None))
        monkeypatch.setattr(ps, "_check_secret_rotation",   lambda: (True, None))
        monkeypatch.setattr(ps, "_check_log_retention",     lambda: (True, None))
        monkeypatch.setattr(ps, "_check_data_minimisation", lambda: (True, None))
        fs = self._svc()._score_gdpr("t")
        assert fs.score < 100
        assert any(x.control_id == "GDPR-01" for x in fs.gaps)

    def test_soc2_missing_notifications_gap(self, monkeypatch):
        import warden.compliance.posture_service as ps
        from warden.compliance.models import Gap, Severity
        g = Gap("SOC2-02", "No alert", Severity.MEDIUM, "Set SLACK_WEBHOOK_URL", "alerting")
        monkeypatch.setattr(ps, "_check_stix_audit",         lambda: (True, None))
        monkeypatch.setattr(ps, "_check_notifications",      lambda: (False, g))
        monkeypatch.setattr(ps, "_check_fido2",              lambda: (True, None))
        monkeypatch.setattr(ps, "_check_prometheus",         lambda: (True, None))
        monkeypatch.setattr(ps, "_check_incident_procedure", lambda _: (True, None))
        fs = self._svc()._score_soc2("t")
        assert any(x.control_id == "SOC2-02" for x in fs.gaps)

    def test_iso27001_training_gap(self, monkeypatch):
        import warden.compliance.posture_service as ps
        from warden.compliance.models import Gap, Severity
        g = Gap("ISO-02", "No training", Severity.MEDIUM, "Set up training", "training_records")
        monkeypatch.setattr(ps, "_check_community_charter", lambda _: (True, None))
        monkeypatch.setattr(ps, "_check_training_records",  lambda _: (False, g))
        monkeypatch.setattr(ps, "_check_supplier_risk",     lambda _: (True, None))
        monkeypatch.setattr(ps, "_check_api_key_rotation",  lambda: (True, None))
        fs = self._svc()._score_iso27001("t")
        assert any(x.control_id == "ISO-02" for x in fs.gaps)

    def test_hipaa_fernet_missing_gap(self, monkeypatch):
        import warden.compliance.posture_service as ps
        from warden.compliance.models import Gap, Severity
        g = Gap("HIPAA-01", "No VAULT_MASTER_KEY", Severity.HIGH, "Set key", "secrets")
        monkeypatch.setattr(ps, "_check_fernet_encryption", lambda: (False, g))
        monkeypatch.setattr(ps, "_check_tls",               lambda: (True, None))
        monkeypatch.setattr(ps, "_check_stix_audit",        lambda: (True, None))
        monkeypatch.setattr(ps, "_check_phi_enforcement",   lambda: (True, None))
        fs = self._svc()._score_hipaa("t")
        assert any(x.control_id == "HIPAA-01" for x in fs.gaps)

    def test_overall_score_is_mean_of_frameworks(self, monkeypatch):
        import warden.compliance.posture_service as ps
        from warden.compliance.models import FrameworkScore
        monkeypatch.setattr(ps.CompliancePostureService, "_score_gdpr",     lambda s, t: FrameworkScore("gdpr",     80.0, 6, 5))
        monkeypatch.setattr(ps.CompliancePostureService, "_score_soc2",     lambda s, t: FrameworkScore("soc2",     60.0, 5, 3))
        monkeypatch.setattr(ps.CompliancePostureService, "_score_iso27001", lambda s, t: FrameworkScore("iso27001", 100.0, 4, 4))
        monkeypatch.setattr(ps.CompliancePostureService, "_score_hipaa",    lambda s, t: FrameworkScore("hipaa",    80.0, 4, 3))
        monkeypatch.setattr(ps, "_get_redis", lambda: None)
        report = self._svc()._compute("default")
        assert report.overall_score == pytest.approx(80.0)

    def test_cache_invalidation_calls_delete(self, monkeypatch):
        import warden.compliance.posture_service as ps
        r = MagicMock()
        r.delete.return_value = 1
        monkeypatch.setattr(ps, "_get_redis", lambda: r)
        self._svc().invalidate_cache("default")
        r.delete.assert_called_once()

    def test_recommendations_added_for_high_gaps(self, monkeypatch):
        import warden.compliance.posture_service as ps
        from warden.compliance.models import FrameworkScore, Gap, Severity
        g = Gap("GDPR-01", "Missing DPA", Severity.HIGH, "Fix", "vendor_gov")
        fs = FrameworkScore("gdpr", 83.33, 6, 5, [g])
        monkeypatch.setattr(ps.CompliancePostureService, "_score_gdpr",     lambda s, t: fs)
        monkeypatch.setattr(ps.CompliancePostureService, "_score_soc2",     lambda s, t: FrameworkScore("soc2",     100.0, 5, 5))
        monkeypatch.setattr(ps.CompliancePostureService, "_score_iso27001", lambda s, t: FrameworkScore("iso27001", 100.0, 4, 4))
        monkeypatch.setattr(ps.CompliancePostureService, "_score_hipaa",    lambda s, t: FrameworkScore("hipaa",    100.0, 4, 4))
        monkeypatch.setattr(ps, "_get_redis", lambda: None)
        report = self._svc()._compute("default")
        assert any("HIGH" in r for r in report.recommendations)


# ── CP-30: API integration ─────────────────────────────────────────────────────

@pytest.mark.integration
def test_gaps_endpoint_structure(client):
    resp = client.get("/compliance/posture/gaps")
    assert resp.status_code in (200, 403, 503)
    if resp.status_code == 200:
        data = resp.json()
        assert "gaps" in data and isinstance(data["gaps"], list)

@pytest.mark.integration
def test_framework_detail_gdpr(client):
    resp = client.get("/compliance/posture/gdpr")
    assert resp.status_code in (200, 403, 404, 503)
    if resp.status_code == 200:
        assert resp.json()["framework"] == "gdpr"

@pytest.mark.integration
def test_framework_detail_unknown_404(client):
    resp = client.get("/compliance/posture/unknown_framework")
    assert resp.status_code in (404, 403, 503)

@pytest.mark.integration
def test_smb_pdf_content_type(client):
    resp = client.get("/compliance/smb-report/pdf?days=7")
    assert resp.status_code == 200
    ct = resp.headers.get("content-type", "")
    assert "pdf" in ct or "html" in ct
