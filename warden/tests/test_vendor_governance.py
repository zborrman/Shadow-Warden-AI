"""
warden/tests/test_vendor_governance.py
Tests for BL-22 AI Vendor Governance Register.
"""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")


def _tid() -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


def _tmp_db() -> str:
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    return f.name


# ── TestVendorRegistry ────────────────────────────────────────────────────────

class TestVendorRegistry:
    def test_register_vendor_basic(self):
        from warden.vendor_gov.registry import register_vendor
        db = _tmp_db()
        v = register_vendor("t1", "OpenAI", website="https://openai.com", db_path=db)
        assert v.vendor_id
        assert v.display_name == "OpenAI"
        assert v.status == "active"
        assert v.provider_type == "LLM"

    def test_register_vendor_normalizes_type(self):
        from warden.vendor_gov.registry import register_vendor
        db = _tmp_db()
        v = register_vendor("t1", "Embed Co", provider_type="embedding", db_path=db)
        assert v.provider_type == "EMBEDDING"

    def test_register_vendor_unknown_type_fallback(self):
        from warden.vendor_gov.registry import register_vendor
        db = _tmp_db()
        v = register_vendor("t1", "Mystery", provider_type="UNKNOWN_TYPE", db_path=db)
        assert v.provider_type == "OTHER"

    def test_list_vendors_empty(self):
        from warden.vendor_gov.registry import list_vendors
        db = _tmp_db()
        assert list_vendors("no-such-tenant", db_path=db) == []

    def test_list_vendors_filters_by_tenant(self):
        from warden.vendor_gov.registry import register_vendor, list_vendors
        db = _tmp_db()
        t1, t2 = _tid(), _tid()
        register_vendor(t1, "Vendor A", db_path=db)
        register_vendor(t2, "Vendor B", db_path=db)
        assert len(list_vendors(t1, db_path=db)) == 1
        assert len(list_vendors(t2, db_path=db)) == 1

    def test_list_vendors_filter_status(self):
        from warden.vendor_gov.registry import register_vendor, update_vendor, list_vendors
        db  = _tmp_db()
        tid = _tid()
        v1  = register_vendor(tid, "Active",  db_path=db)
        v2  = register_vendor(tid, "Review",  db_path=db)
        update_vendor(v2.vendor_id, tid, status="review", db_path=db)
        assert len(list_vendors(tid, status="active", db_path=db)) == 1
        assert len(list_vendors(tid, status="review", db_path=db)) == 1

    def test_list_vendors_filter_risk_tier(self):
        from warden.vendor_gov.registry import register_vendor, list_vendors
        db  = _tmp_db()
        tid = _tid()
        register_vendor(tid, "Low",  risk_tier="LOW",  db_path=db)
        register_vendor(tid, "High", risk_tier="HIGH", db_path=db)
        assert len(list_vendors(tid, risk_tier="HIGH", db_path=db)) == 1

    def test_get_vendor_found(self):
        from warden.vendor_gov.registry import register_vendor, get_vendor
        db  = _tmp_db()
        tid = _tid()
        v   = register_vendor(tid, "Anthropic", db_path=db)
        fetched = get_vendor(v.vendor_id, tid, db_path=db)
        assert fetched is not None
        assert fetched.display_name == "Anthropic"

    def test_get_vendor_not_found(self):
        from warden.vendor_gov.registry import get_vendor
        db = _tmp_db()
        assert get_vendor("no-such-id", "t1", db_path=db) is None

    def test_get_vendor_wrong_tenant(self):
        from warden.vendor_gov.registry import register_vendor, get_vendor
        db  = _tmp_db()
        t1  = _tid()
        t2  = _tid()
        v   = register_vendor(t1, "Shared?", db_path=db)
        assert get_vendor(v.vendor_id, t2, db_path=db) is None

    def test_update_vendor_display_name(self):
        from warden.vendor_gov.registry import register_vendor, update_vendor, get_vendor
        db  = _tmp_db()
        tid = _tid()
        v   = register_vendor(tid, "Old Name", db_path=db)
        ok  = update_vendor(v.vendor_id, tid, display_name="New Name", db_path=db)
        assert ok
        updated = get_vendor(v.vendor_id, tid, db_path=db)
        assert updated is not None and updated.display_name == "New Name"

    def test_update_vendor_not_found(self):
        from warden.vendor_gov.registry import update_vendor
        db = _tmp_db()
        assert not update_vendor("no-such", "t1", display_name="X", db_path=db)

    def test_update_vendor_no_fields(self):
        from warden.vendor_gov.registry import update_vendor
        db = _tmp_db()
        assert not update_vendor("x", "t", db_path=db)

    def test_vendor_tags_roundtrip(self):
        from warden.vendor_gov.registry import register_vendor, get_vendor
        db  = _tmp_db()
        tid = _tid()
        v   = register_vendor(tid, "Tagged", tags={"env": "prod", "gdpr": True}, db_path=db)
        fetched = get_vendor(v.vendor_id, tid, db_path=db)
        assert fetched is not None
        assert fetched.tags == {"env": "prod", "gdpr": True}


# ── TestDPATracking ───────────────────────────────────────────────────────────

class TestDPATracking:
    def test_add_dpa_basic(self):
        from warden.vendor_gov.registry import register_vendor, add_dpa
        db  = _tmp_db()
        tid = _tid()
        v   = register_vendor(tid, "OpenAI", db_path=db)
        dpa = add_dpa(v.vendor_id, tid, dpa_type="GDPR_ART28", doc_ref="https://openai.com/dpa", db_path=db)
        assert dpa.dpa_id
        assert dpa.dpa_type == "GDPR_ART28"
        assert dpa.status == "active"

    def test_add_dpa_normalizes_type(self):
        from warden.vendor_gov.registry import register_vendor, add_dpa
        db  = _tmp_db()
        tid = _tid()
        v   = register_vendor(tid, "V", db_path=db)
        dpa = add_dpa(v.vendor_id, tid, dpa_type="ccpa", db_path=db)
        assert dpa.dpa_type == "CCPA"

    def test_add_dpa_unknown_type_custom(self):
        from warden.vendor_gov.registry import register_vendor, add_dpa
        db  = _tmp_db()
        tid = _tid()
        v   = register_vendor(tid, "V", db_path=db)
        dpa = add_dpa(v.vendor_id, tid, dpa_type="WEIRD", db_path=db)
        assert dpa.dpa_type == "CUSTOM"

    def test_list_dpas(self):
        from warden.vendor_gov.registry import register_vendor, add_dpa, list_dpas
        db  = _tmp_db()
        tid = _tid()
        v   = register_vendor(tid, "V", db_path=db)
        add_dpa(v.vendor_id, tid, dpa_type="GDPR_ART28", db_path=db)
        add_dpa(v.vendor_id, tid, dpa_type="ISO27001", db_path=db)
        dpas = list_dpas(v.vendor_id, tid, db_path=db)
        assert len(dpas) == 2

    def test_list_dpas_empty(self):
        from warden.vendor_gov.registry import list_dpas
        db = _tmp_db()
        assert list_dpas("no-vendor", "no-tenant", db_path=db) == []


# ── TestExpiryAlerts ──────────────────────────────────────────────────────────

class TestExpiryAlerts:
    def test_expiring_dpa_detected(self):
        from warden.vendor_gov.registry import register_vendor, add_dpa, get_expiring_dpas
        from datetime import UTC, datetime, timedelta
        db  = _tmp_db()
        tid = _tid()
        v   = register_vendor(tid, "Expiring", db_path=db)
        soon = (datetime.now(UTC) + timedelta(days=10)).isoformat()
        add_dpa(v.vendor_id, tid, expires_at=soon, db_path=db)
        expiring = get_expiring_dpas(tid, within_days=30, db_path=db)
        assert len(expiring) == 1

    def test_non_expiring_dpa_not_in_list(self):
        from warden.vendor_gov.registry import register_vendor, add_dpa, get_expiring_dpas
        from datetime import UTC, datetime, timedelta
        db  = _tmp_db()
        tid = _tid()
        v   = register_vendor(tid, "Long lived", db_path=db)
        far = (datetime.now(UTC) + timedelta(days=180)).isoformat()
        add_dpa(v.vendor_id, tid, expires_at=far, db_path=db)
        assert get_expiring_dpas(tid, within_days=30, db_path=db) == []

    def test_no_expiry_date_not_in_list(self):
        from warden.vendor_gov.registry import register_vendor, add_dpa, get_expiring_dpas
        db  = _tmp_db()
        tid = _tid()
        v   = register_vendor(tid, "No expiry", db_path=db)
        add_dpa(v.vendor_id, tid, expires_at=None, db_path=db)
        assert get_expiring_dpas(tid, within_days=30, db_path=db) == []

    def test_stats_structure(self):
        from warden.vendor_gov.registry import register_vendor, add_dpa, get_vendor_stats
        from datetime import UTC, datetime, timedelta
        db  = _tmp_db()
        tid = _tid()
        v1  = register_vendor(tid, "A", risk_tier="HIGH",     db_path=db)
        v2  = register_vendor(tid, "B", risk_tier="CRITICAL", db_path=db)
        register_vendor(tid, "C", risk_tier="LOW", db_path=db)
        soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()
        add_dpa(v1.vendor_id, tid, expires_at=soon, db_path=db)
        s = get_vendor_stats(tid, db_path=db)
        assert s["total_vendors"] == 3
        assert s["high_risk_vendors"] == 2
        assert s["expiring_dpas_30d"] == 1

    def test_stats_empty_tenant(self):
        from warden.vendor_gov.registry import get_vendor_stats
        db = _tmp_db()
        s  = get_vendor_stats("no-such-tenant", db_path=db)
        assert s["total_vendors"] == 0
        assert s["expiring_dpas_30d"] == 0
