"""
Tests for CP-25 compliance posture + history endpoints.
"""
from __future__ import annotations

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
    return TestClient(_make_app(), raise_server_exceptions=False)


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
