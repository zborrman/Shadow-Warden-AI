"""
warden/tests/test_supplier_risk.py
Tests for CM-36 Supplier AI Risk Assessment.
"""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")


def _cid() -> str:
    return f"comm-{uuid.uuid4().hex[:8]}"


def _vid() -> str:
    return f"vendor-{uuid.uuid4().hex[:8]}"


def _tmp_db() -> str:
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    return f.name


class TestScoring:
    def test_assess_returns_assessment_id(self):
        from warden.communities.supplier_risk import assess_supplier
        db  = _tmp_db()
        cid = _cid()
        vid = _vid()
        result = assess_supplier(cid, vid, db_path=db)
        assert "assessment_id" in result
        assert len(result["assessment_id"]) == 36

    def test_assess_composite_score_range(self):
        from warden.communities.supplier_risk import assess_supplier
        db = _tmp_db()
        result = assess_supplier(_cid(), _vid(), db_path=db)
        assert 0.0 <= result["composite_score"] <= 1.0

    def test_assess_risk_label_present(self):
        from warden.communities.supplier_risk import assess_supplier
        db = _tmp_db()
        result = assess_supplier(_cid(), _vid(), db_path=db)
        assert result["risk_label"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_assess_low_risk_context(self):
        from warden.communities.supplier_risk import assess_supplier
        db  = _tmp_db()
        ctx = {
            "data_access":        0.0,
            "ai_capability":      0.0,
            "compliance_posture": 0.0,
            "peering_history":    0.0,
            "disclosure_recency": 0.0,
        }
        result = assess_supplier(_cid(), _vid(), context=ctx, db_path=db)
        assert result["risk_label"] == "LOW"
        assert result["composite_score"] == 0.0

    def test_assess_critical_risk_context(self):
        from warden.communities.supplier_risk import assess_supplier
        db  = _tmp_db()
        ctx = {
            "data_access":        1.0,
            "ai_capability":      1.0,
            "compliance_posture": 1.0,
            "peering_history":    1.0,
            "disclosure_recency": 1.0,
        }
        result = assess_supplier(_cid(), _vid(), context=ctx, db_path=db)
        assert result["risk_label"] == "CRITICAL"
        assert result["composite_score"] == 1.0

    def test_assess_weights_sum_to_one(self):
        from warden.communities.supplier_risk import _WEIGHTS
        assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-9

    def test_assess_clamps_out_of_range_scores(self):
        from warden.communities.supplier_risk import assess_supplier
        db  = _tmp_db()
        ctx = {"data_access": 2.5, "ai_capability": -1.0}
        result = assess_supplier(_cid(), _vid(), context=ctx, db_path=db)
        assert result["scores"]["data_access"] == 1.0
        assert result["scores"]["ai_capability"] == 0.0

    def test_assess_stores_notes(self):
        from warden.communities.supplier_risk import assess_supplier, list_assessments
        db  = _tmp_db()
        cid = _cid()
        assess_supplier(cid, _vid(), notes="test note", db_path=db)
        items = list_assessments(cid, db_path=db)
        assert items[0]["notes"] == "test note"

    def test_assess_medium_boundary(self):
        from warden.communities.supplier_risk import assess_supplier
        db  = _tmp_db()
        # composite near 0.35 boundary
        ctx = {
            "data_access":        0.35,
            "ai_capability":      0.35,
            "compliance_posture": 0.35,
            "peering_history":    0.35,
            "disclosure_recency": 0.35,
        }
        result = assess_supplier(_cid(), _vid(), context=ctx, db_path=db)
        assert result["risk_label"] == "MEDIUM"


class TestListAndReport:
    def test_list_assessments_empty(self):
        from warden.communities.supplier_risk import list_assessments
        db = _tmp_db()
        assert list_assessments(_cid(), db_path=db) == []

    def test_list_assessments_returns_items(self):
        from warden.communities.supplier_risk import assess_supplier, list_assessments
        db  = _tmp_db()
        cid = _cid()
        assess_supplier(cid, _vid(), db_path=db)
        assess_supplier(cid, _vid(), db_path=db)
        items = list_assessments(cid, db_path=db)
        assert len(items) == 2

    def test_list_assessments_filter_by_label(self):
        from warden.communities.supplier_risk import assess_supplier, list_assessments
        db  = _tmp_db()
        cid = _cid()
        low_ctx = {k: 0.0 for k in ("data_access", "ai_capability", "compliance_posture",
                                    "peering_history", "disclosure_recency")}
        crit_ctx = {k: 1.0 for k in low_ctx}
        assess_supplier(cid, _vid(), context=low_ctx,  db_path=db)
        assess_supplier(cid, _vid(), context=crit_ctx, db_path=db)
        lows = list_assessments(cid, risk_label="LOW",      db_path=db)
        crits = list_assessments(cid, risk_label="CRITICAL", db_path=db)
        assert len(lows)  == 1
        assert len(crits) == 1

    def test_report_total_vendors(self):
        from warden.communities.supplier_risk import assess_supplier, get_community_supplier_report
        db  = _tmp_db()
        cid = _cid()
        for _ in range(3):
            assess_supplier(cid, _vid(), db_path=db)
        report = get_community_supplier_report(cid, db_path=db)
        assert report["total_vendors"] == 3

    def test_report_by_label(self):
        from warden.communities.supplier_risk import assess_supplier, get_community_supplier_report
        db  = _tmp_db()
        cid = _cid()
        low_ctx = {k: 0.0 for k in ("data_access", "ai_capability", "compliance_posture",
                                    "peering_history", "disclosure_recency")}
        assess_supplier(cid, _vid(), context=low_ctx, db_path=db)
        report = get_community_supplier_report(cid, db_path=db)
        assert "LOW" in report["by_risk_label"]

    def test_report_top_risky_vendors(self):
        from warden.communities.supplier_risk import assess_supplier, get_community_supplier_report
        db   = _tmp_db()
        cid  = _cid()
        high = {k: 1.0 for k in ("data_access", "ai_capability", "compliance_posture",
                                  "peering_history", "disclosure_recency")}
        low  = {k: 0.0 for k in high}
        vid_high = _vid()
        assess_supplier(cid, vid_high, context=high, db_path=db)
        assess_supplier(cid, _vid(),   context=low,  db_path=db)
        report = get_community_supplier_report(cid, db_path=db)
        assert report["top_risky_vendors"][0]["vendor_id"] == vid_high

    def test_report_empty_community(self):
        from warden.communities.supplier_risk import get_community_supplier_report
        db = _tmp_db()
        report = get_community_supplier_report(_cid(), db_path=db)
        assert report["total_vendors"] == 0
        assert report["top_risky_vendors"] == []
