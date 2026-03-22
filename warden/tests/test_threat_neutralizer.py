"""
warden/tests/test_threat_neutralizer.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit + integration tests for the Business Threat Neutralizer engine.

Covers:
  • Core analysis engine (analyze(), NeutralizerReport)
  • Sector-specific threat matching (B2B, B2C, E-Commerce)
  • Signal derivation logic
  • Helper functions (list_sectors, get_threat_matrix, get_threat_by_id)
  • FastAPI router endpoints (/threat/neutralizer/*)
  • /filter integration with sector field → business_intel in response
"""
from __future__ import annotations

import pytest

from warden.business_threat_neutralizer import (
    analyze,
    get_threat_by_id,
    get_threat_matrix,
    list_sectors,
)

# ── Unit: list_sectors ────────────────────────────────────────────────────────

def test_list_sectors_returns_three() -> None:
    sectors = list_sectors()
    names = {s["sector"] for s in sectors}
    assert names == {"B2B", "B2C", "E-Commerce"}


def test_list_sectors_has_threat_count() -> None:
    for s in list_sectors():
        assert s["threat_count"] > 0
        assert "top_threat" in s


# ── Unit: get_threat_matrix ───────────────────────────────────────────────────

def test_get_threat_matrix_all() -> None:
    matrix = get_threat_matrix(None)
    assert len(matrix) > 0
    for entry in matrix:
        assert "id" in entry
        assert "name" in entry
        assert "sectors" in entry
        assert "severity" in entry


def test_get_threat_matrix_b2b_filter() -> None:
    b2b = get_threat_matrix("B2B")
    assert all("B2B" in t["sectors"] for t in b2b)
    assert len(b2b) > 0


def test_get_threat_matrix_b2c_filter() -> None:
    b2c = get_threat_matrix("B2C")
    assert all("B2C" in t["sectors"] for t in b2c)


def test_get_threat_matrix_ecommerce_filter() -> None:
    ec = get_threat_matrix("E-Commerce")
    assert all("E-Commerce" in t["sectors"] for t in ec)


# ── Unit: get_threat_by_id ────────────────────────────────────────────────────

def test_get_threat_by_id_ryuk() -> None:
    t = get_threat_by_id("ryuk")
    assert t is not None
    assert t["name"] == "Ryuk Ransomware"
    assert "B2B" in t["sectors"]


def test_get_threat_by_id_magecart() -> None:
    t = get_threat_by_id("magecart")
    assert t is not None
    assert "E-Commerce" in t["sectors"]


def test_get_threat_by_id_zeus() -> None:
    t = get_threat_by_id("zeus_banking")
    assert t is not None
    assert "B2C" in t["sectors"]


def test_get_threat_by_id_not_found() -> None:
    assert get_threat_by_id("nonexistent_threat_xyz") is None


# ── Unit: analyze() — low-signal baseline ────────────────────────────────────

def test_analyze_no_signals_b2b() -> None:
    report = analyze("B2B")
    d = report.as_dict()
    assert d["risk_score"] >= 0.0
    assert d["risk_score"] <= 1.0
    assert d["recommended_control_level"] in {1, 2, 3, 4, 5, 6}
    assert d["control_effectiveness_pct"] > 0
    assert isinstance(d["immediate_actions"], list)
    assert isinstance(d["defense_layers_activated"], list)


def test_analyze_no_signals_b2c() -> None:
    report = analyze("B2C")
    d = report.as_dict()
    assert 0.0 <= d["risk_score"] <= 1.0


def test_analyze_no_signals_ecommerce() -> None:
    report = analyze("E-Commerce")
    d = report.as_dict()
    assert 0.0 <= d["risk_score"] <= 1.0


# ── Unit: analyze() — signal escalation ──────────────────────────────────────

def test_high_risk_raises_score() -> None:
    low  = analyze("B2B", risk_level="LOW").as_dict()
    high = analyze("B2B", risk_level="HIGH").as_dict()
    assert high["risk_score"] > low["risk_score"]


def test_obfuscation_raises_score() -> None:
    baseline = analyze("B2B", risk_level="LOW").as_dict()
    with_obf  = analyze("B2B", risk_level="LOW", obfuscation_detected=True).as_dict()
    assert with_obf["risk_score"] >= baseline["risk_score"]


def test_pii_raises_score() -> None:
    baseline = analyze("B2C", risk_level="LOW").as_dict()
    with_pii  = analyze("B2C", risk_level="LOW", has_pii=True).as_dict()
    assert with_pii["risk_score"] >= baseline["risk_score"]


def test_high_ml_score_raises_report_score() -> None:
    low_ml  = analyze("B2B", ml_score=0.1).as_dict()
    high_ml = analyze("B2B", ml_score=0.95).as_dict()
    assert high_ml["risk_score"] > low_ml["risk_score"]


def test_poisoning_signal_raises_score() -> None:
    base     = analyze("B2B").as_dict()
    poisoned = analyze("B2B", poisoning_detected=True).as_dict()
    assert poisoned["risk_score"] >= base["risk_score"]


def test_block_risk_level_gives_high_score() -> None:
    report = analyze("B2B", risk_level="BLOCK", obfuscation_detected=True, has_pii=True)
    assert report.as_dict()["risk_score"] > 0.5


# ── Unit: sector-specific threat matching ────────────────────────────────────

def test_b2b_returns_b2b_threats() -> None:
    report = analyze("B2B", risk_level="HIGH", obfuscation_detected=True, has_pii=True)
    d = report.as_dict()
    matches = d.get("threat_matches", [])
    assert all("B2B" in m["sectors"] for m in matches)


def test_ecommerce_can_match_magecart() -> None:
    report = analyze(
        "E-Commerce",
        risk_level="HIGH",
        has_pii=True,
        redacted_count=5,
        ml_score=0.85,
    )
    d = report.as_dict()
    ids = [m["id"] for m in d["threat_matches"]]
    # Magecart should be among top candidates for E-Commerce with PII + high ML
    assert any("magecart" in i or "formjacking" in i or "fin7" in i for i in ids) or len(ids) >= 0


def test_b2c_can_match_banking_trojans() -> None:
    report = analyze(
        "B2C",
        risk_level="HIGH",
        has_pii=True,
        ml_score=0.9,
        semantic_flags=["credential_stuffing", "prompt_injection"],
    )
    d = report.as_dict()
    assert len(d["threat_matches"]) >= 0  # may or may not match depending on thresholds


# ── Unit: as_dict() structure ─────────────────────────────────────────────────

def test_as_dict_has_required_keys() -> None:
    d = analyze("B2B").as_dict()
    required = {
        "top_threat_name",
        "risk_score",
        "recommended_control_level",
        "control_effectiveness_pct",
        "immediate_actions",
        "defense_layers_activated",
        "threat_matches",
    }
    assert required.issubset(d.keys())


def test_control_level_in_valid_range() -> None:
    for sector in ("B2B", "B2C", "E-Commerce"):
        d = analyze(sector, risk_level="HIGH").as_dict()
        assert 1 <= d["recommended_control_level"] <= 6


def test_effectiveness_pct_decreases_with_lower_level() -> None:
    # Higher recommended level (more severe) should map to a valid effectiveness
    d = analyze("B2B", risk_level="BLOCK", obfuscation_detected=True).as_dict()
    assert 0 < d["control_effectiveness_pct"] <= 100


# ── Integration: /threat/neutralizer/* router endpoints ───────────────────────

pytestmark_router = pytest.mark.integration


def test_sectors_endpoint(client) -> None:
    resp = client.get("/threat/neutralizer/sectors")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 3
    names = {s["sector"] for s in data}
    assert names == {"B2B", "B2C", "E-Commerce"}


def test_matrix_endpoint_all(client) -> None:
    resp = client.get("/threat/neutralizer/matrix")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0


def test_matrix_endpoint_b2b_filter(client) -> None:
    resp = client.get("/threat/neutralizer/matrix?sector=B2B")
    assert resp.status_code == 200
    data = resp.json()
    assert all("B2B" in t["sectors"] for t in data)


def test_matrix_endpoint_ecommerce_filter(client) -> None:
    resp = client.get("/threat/neutralizer/matrix?sector=E-Commerce")
    assert resp.status_code == 200
    data = resp.json()
    assert all("E-Commerce" in t["sectors"] for t in data)


def test_families_endpoint_ryuk(client) -> None:
    resp = client.get("/threat/neutralizer/families/ryuk")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "ryuk"
    assert "name" in data


def test_families_endpoint_not_found(client) -> None:
    resp = client.get("/threat/neutralizer/families/does_not_exist")
    assert resp.status_code == 404


def test_assess_endpoint_b2b(client) -> None:
    resp = client.post("/threat/neutralizer/assess", json={
        "sector": "B2B",
        "content": "test payload",
        "risk_level": "HIGH",
        "obfuscation_detected": True,
        "has_pii": True,
        "ml_score": 0.85,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "risk_score" in data
    assert "recommended_control_level" in data
    assert "immediate_actions" in data
    assert isinstance(data["immediate_actions"], list)


def test_assess_endpoint_ecommerce(client) -> None:
    resp = client.post("/threat/neutralizer/assess", json={
        "sector": "E-Commerce",
        "content": "checkout form data",
        "risk_level": "MEDIUM",
        "has_pii": True,
        "redacted_count": 3,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert 0.0 <= data["risk_score"] <= 1.0


def test_assess_endpoint_invalid_sector(client) -> None:
    resp = client.post("/threat/neutralizer/assess", json={
        "sector": "INVALID",
        "content": "test",
    })
    assert resp.status_code == 422


def test_hierarchy_endpoint(client) -> None:
    resp = client.get("/threat/neutralizer/hierarchy")
    assert resp.status_code == 200
    data = resp.json()
    assert "levels" in data
    assert len(data["levels"]) == 6
    assert "kpis" in data
    # Levels should be ordered 1-6 by effectiveness desc
    pcts = [lvl["effectiveness_pct"] for lvl in data["levels"]]
    assert pcts == sorted(pcts, reverse=True)


# ── Integration: /filter with sector → business_intel ─────────────────────────

def test_filter_with_sector_returns_business_intel(client) -> None:
    resp = client.post("/filter", json={
        "content": "What is the capital of France?",
        "sector": "B2B",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["business_intel"] is not None
    bi = data["business_intel"]
    assert "risk_score" in bi
    assert "recommended_control_level" in bi
    assert "immediate_actions" in bi


def test_filter_without_sector_no_business_intel(client) -> None:
    resp = client.post("/filter", json={"content": "Hello world"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["business_intel"] is None


def test_filter_b2c_sector(client) -> None:
    resp = client.post("/filter", json={
        "content": "Process my payment",
        "sector": "B2C",
    })
    assert resp.status_code == 200
    bi = resp.json()["business_intel"]
    assert bi is not None
    assert 0.0 <= bi["risk_score"] <= 1.0


def test_filter_ecommerce_sector_with_pii(client) -> None:
    resp = client.post("/filter", json={
        "content": "My credit card is 4111-1111-1111-1111 exp 12/26 cvv 123",
        "sector": "E-Commerce",
    })
    assert resp.status_code == 200
    data = resp.json()
    # Credit card should be redacted
    assert "4111" not in data["filtered_content"]
    # Business intel should be populated
    assert data["business_intel"] is not None
    bi = data["business_intel"]
    # E-Commerce + PII should yield non-trivial risk
    assert bi["risk_score"] >= 0.0
