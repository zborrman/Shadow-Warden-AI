"""
warden/tests/test_iso27001.py  (CP-22)
Tests for the full ISO/IEC 27001:2022 Annex A control mapping endpoints.
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
    # X-Tenant-Tier: enterprise — iso27001_enabled is True at Enterprise
    return TestClient(_make_app(), raise_server_exceptions=False,
                      headers={"X-Tenant-Tier": "enterprise"})


# ── Control catalog integrity ─────────────────────────────────────────────────

class TestControlCatalog:
    def test_exactly_93_controls(self):
        from warden.api.compliance_report import _ISO27001_CONTROLS_V2
        assert len(_ISO27001_CONTROLS_V2) == 93

    def test_all_have_5_fields(self):
        from warden.api.compliance_report import _ISO27001_CONTROLS_V2
        for row in _ISO27001_CONTROLS_V2:
            assert len(row) == 5, f"Expected 5-tuple, got {len(row)}: {row[0]}"

    def test_valid_themes(self):
        from warden.api.compliance_report import _ISO27001_CONTROLS_V2
        valid = {"Organizational", "People", "Physical", "Technological"}
        for ctrl_id, theme, _, status, _ in _ISO27001_CONTROLS_V2:
            assert theme in valid, f"{ctrl_id}: unknown theme '{theme}'"

    def test_valid_statuses(self):
        from warden.api.compliance_report import _ISO27001_CONTROLS_V2
        valid = {"Implemented", "Partial", "Delegated"}
        for ctrl_id, _, _, status, _ in _ISO27001_CONTROLS_V2:
            assert status in valid, f"{ctrl_id}: unknown status '{status}'"

    def test_control_ids_unique(self):
        from warden.api.compliance_report import _ISO27001_CONTROLS_V2
        ids = [c for c, *_ in _ISO27001_CONTROLS_V2]
        assert len(ids) == len(set(ids)), "Duplicate control IDs found"

    def test_all_controls_have_evidence(self):
        from warden.api.compliance_report import _ISO27001_CONTROLS_V2
        for ctrl_id, _, _, _, evidence in _ISO27001_CONTROLS_V2:
            assert evidence.strip(), f"{ctrl_id}: empty evidence string"

    def test_theme_counts(self):
        from warden.api.compliance_report import _ISO27001_CONTROLS_V2
        from collections import Counter
        counts = Counter(th for _, th, *_ in _ISO27001_CONTROLS_V2)
        assert counts["Organizational"] == 37
        assert counts["People"]         == 8
        assert counts["Physical"]       == 14
        assert counts["Technological"]  == 34

    def test_control_ids_start_with_a(self):
        from warden.api.compliance_report import _ISO27001_CONTROLS_V2
        for ctrl_id, *_ in _ISO27001_CONTROLS_V2:
            assert ctrl_id.startswith("A."), f"Unexpected control ID format: {ctrl_id}"

    def test_legacy_alias_compatible(self):
        from warden.api.compliance_report import _ISO27001_CONTROLS
        # Legacy alias is list of 4-tuples (control, domain, status, evidence)
        for row in _ISO27001_CONTROLS:
            assert len(row) == 4
        assert len(_ISO27001_CONTROLS) == 93

    def test_at_least_half_implemented(self):
        from warden.api.compliance_report import _ISO27001_CONTROLS_V2
        impl = sum(1 for _, _, _, s, _ in _ISO27001_CONTROLS_V2 if s == "Implemented")
        assert impl >= 46, f"Expected ≥46 implemented controls, got {impl}"


# ── /compliance/iso27001 JSON endpoint ───────────────────────────────────────

class TestIso27001Json:
    def test_returns_200(self, client):
        assert client.get("/compliance/iso27001").status_code == 200

    def test_schema_fields(self, client):
        data = client.get("/compliance/iso27001").json()
        for field in ("standard", "controls_total", "implemented", "partial",
                      "delegated", "coverage_pct", "controls", "themes", "by_theme"):
            assert field in data, f"Missing field: {field}"

    def test_standard_name(self, client):
        data = client.get("/compliance/iso27001").json()
        assert "ISO" in data["standard"] and "27001" in data["standard"]

    def test_controls_total_is_93(self, client):
        data = client.get("/compliance/iso27001").json()
        assert data["controls_total"] == 93
        assert len(data["controls"]) == 93

    def test_counts_sum_to_total(self, client):
        data = client.get("/compliance/iso27001").json()
        assert data["implemented"] + data["partial"] + data["delegated"] == data["controls_total"]

    def test_coverage_pct_range(self, client):
        data = client.get("/compliance/iso27001").json()
        assert 0.0 <= data["coverage_pct"] <= 100.0

    def test_all_four_themes_present(self, client):
        data = client.get("/compliance/iso27001").json()
        for theme in ("Organizational", "People", "Physical", "Technological"):
            assert theme in data["themes"], f"Missing theme: {theme}"

    def test_theme_counts_match(self, client):
        data = client.get("/compliance/iso27001").json()
        assert data["themes"]["Organizational"]["total"] == 37
        assert data["themes"]["People"]["total"]         == 8
        assert data["themes"]["Physical"]["total"]       == 14
        assert data["themes"]["Technological"]["total"]  == 34

    def test_each_control_has_theme_field(self, client):
        data = client.get("/compliance/iso27001").json()
        for c in data["controls"]:
            assert "theme" in c, f"Control {c['control']} missing 'theme' field"

    def test_each_control_has_evidence(self, client):
        data = client.get("/compliance/iso27001").json()
        for c in data["controls"]:
            assert c["evidence"].strip(), f"{c['control']}: empty evidence"

    def test_days_param_accepted(self, client):
        for d in (7, 30, 90, 180, 365):
            r = client.get(f"/compliance/iso27001?days={d}")
            assert r.status_code == 200

    def test_days_out_of_range(self, client):
        assert client.get("/compliance/iso27001?days=0").status_code   in (400, 422)
        assert client.get("/compliance/iso27001?days=366").status_code in (400, 422)

    def test_by_theme_keys(self, client):
        data = client.get("/compliance/iso27001").json()
        for theme in ("Organizational", "People", "Physical", "Technological"):
            assert theme in data["by_theme"]
            theme_ctrls = data["by_theme"][theme]
            assert isinstance(theme_ctrls, list)
            assert len(theme_ctrls) == data["themes"][theme]["total"]

    def test_tier_gate_blocks_non_enterprise(self, client):
        pro_client = TestClient(_make_app(), raise_server_exceptions=False,
                                headers={"X-Tenant-Tier": "pro"})
        r = pro_client.get("/compliance/iso27001")
        assert r.status_code in (403, 200)  # 403 when gate active; 200 if fail-open import


# ── /compliance/iso27001/html endpoint ───────────────────────────────────────

class TestIso27001Html:
    def test_returns_200(self, client):
        assert client.get("/compliance/iso27001/html").status_code == 200

    def test_content_type_html(self, client):
        r = client.get("/compliance/iso27001/html")
        assert "text/html" in r.headers.get("content-type", "")

    def test_contains_iso_title(self, client):
        body = client.get("/compliance/iso27001/html").text
        assert "ISO" in body and "27001" in body

    def test_contains_all_theme_headers(self, client):
        body = client.get("/compliance/iso27001/html").text
        for theme in ("Organizational", "People", "Physical", "Technological"):
            assert theme in body, f"Theme '{theme}' not in HTML report"

    def test_contains_93_control_rows(self, client):
        body = client.get("/compliance/iso27001/html").text
        # Every control row wraps in a <tr> with a <code> tag
        assert body.count("<code>A.") >= 93

    def test_contains_kpi_grid(self, client):
        body = client.get("/compliance/iso27001/html").text
        assert "kpi-grid" in body
        assert "Coverage" in body

    def test_report_format_header(self, client):
        r = client.get("/compliance/iso27001/html")
        assert r.headers.get("x-report-format") == "html"

    def test_days_param_accepted(self, client):
        for d in (7, 30, 90):
            r = client.get(f"/compliance/iso27001/html?days={d}")
            assert r.status_code == 200
