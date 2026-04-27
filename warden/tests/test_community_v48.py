"""
warden/tests/test_community_v48.py
────────────────────────────────────
Tests for v4.8 Community Business features:
  • Charter system (communities/charter.py)
  • Behavioral baseline + anomaly detection (communities/behavioral.py)
  • Intelligence reports (communities/intelligence.py)
  • OAuth Agent Discovery (communities/oauth_discovery.py)
  • Community Intel REST API (api/community_intel.py)
"""
from __future__ import annotations

import os
import uuid as _uuid

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("LOGS_PATH", "/tmp/warden_v48_test_logs.json")
os.environ.setdefault("COMMUNITY_REGISTRY_PATH", "/tmp/warden_test_charter.db")
os.environ.setdefault("BEHAVIORAL_DB_PATH", "/tmp/warden_test_behavioral.db")
os.environ.setdefault("OAUTH_DB_PATH", "/tmp/warden_test_oauth.db")
os.environ.setdefault("SEP_DB_PATH", "/tmp/warden_test_sep_v48.db")


def _cid(prefix: str = "com") -> str:
    """Return a unique community ID so tests never share DB state."""
    return f"{prefix}-{_uuid.uuid4().hex[:8]}"


# ══════════════════════════════════════════════════════════════════════════════
# Charter
# ══════════════════════════════════════════════════════════════════════════════

class TestCharter:
    def test_create_draft(self):
        from warden.communities.charter import create_charter
        rec = create_charter(_cid(), "Test Charter", "member-1")
        assert rec.status == "DRAFT"
        assert rec.version >= 1
        assert rec.content_hash

    def test_publish_activates(self):
        from warden.communities.charter import create_charter, publish_charter
        rec = create_charter(_cid(), "Pub Charter", "member-1")
        active = publish_charter(rec.charter_id)
        assert active.status == "ACTIVE"
        assert active.published_at is not None

    def test_publish_supersedes_previous(self):
        from warden.communities.charter import (
            create_charter,
            get_active_charter,
            publish_charter,
        )
        cid = _cid()
        r1 = create_charter(cid, "Charter v1", "m1")
        publish_charter(r1.charter_id)
        r2 = create_charter(cid, "Charter v2", "m1")
        publish_charter(r2.charter_id)
        active = get_active_charter(cid)
        assert active is not None
        assert active.version == r2.version

    def test_version_increments(self):
        from warden.communities.charter import create_charter
        cid = _cid()
        r1 = create_charter(cid, "V1", "m1")
        r2 = create_charter(cid, "V2", "m1")
        assert r2.version == r1.version + 1

    def test_invalid_transparency_raises(self):
        from warden.communities.charter import create_charter
        with pytest.raises(ValueError, match="transparency"):
            create_charter(_cid(), "Title", "m1", transparency="WRONG")

    def test_accept_charter(self):
        from warden.communities.charter import accept_charter, create_charter, publish_charter
        rec = create_charter(_cid(), "Accept Test", "m1")
        publish_charter(rec.charter_id)
        result = accept_charter(rec.charter_id, "member-abc")
        assert result["charter_id"] == rec.charter_id
        assert result["member_id"] == "member-abc"

    def test_accept_draft_raises(self):
        from warden.communities.charter import accept_charter, create_charter
        rec = create_charter(_cid(), "Draft Accept", "m1")
        with pytest.raises(ValueError, match="DRAFT"):
            accept_charter(rec.charter_id, "member-xyz")

    def test_validate_compliance_no_charter(self):
        from warden.communities.charter import validate_charter_compliance
        ok, reason = validate_charter_compliance(_cid(), "transfer", "PII")
        assert ok is True
        assert reason == "no_charter_active"

    def test_validate_compliance_prohibited_action(self):
        from warden.communities.charter import (
            create_charter,
            publish_charter,
            validate_charter_compliance,
        )
        cid = _cid()
        rec = create_charter(cid, "Block Charter", "m1", prohibited_actions=["mass_export"])
        publish_charter(rec.charter_id)
        ok, reason = validate_charter_compliance(cid, "mass_export", "GENERAL")
        assert ok is False
        assert "mass_export" in reason

    def test_validate_compliance_disallowed_class(self):
        from warden.communities.charter import (
            create_charter,
            publish_charter,
            validate_charter_compliance,
        )
        cid = _cid()
        rec = create_charter(cid, "Class Charter", "m1", allowed_data_classes=["GENERAL"])
        publish_charter(rec.charter_id)
        ok, reason = validate_charter_compliance(cid, "transfer", "CLASSIFIED")
        assert ok is False
        assert "CLASSIFIED" in reason

    def test_content_hash_is_deterministic(self):
        from warden.communities.charter import _compute_hash
        h1 = _compute_hash("c1", 1, "Title", {"transparency": "REQUIRED"})
        h2 = _compute_hash("c1", 1, "Title", {"transparency": "REQUIRED"})
        assert h1 == h2

    def test_auto_block_threshold_bounds(self):
        from warden.communities.charter import create_charter
        with pytest.raises(ValueError):
            create_charter(_cid(), "T", "m", auto_block_threshold=1.5)


# ══════════════════════════════════════════════════════════════════════════════
# Behavioral Baseline + Anomaly Detection
# ══════════════════════════════════════════════════════════════════════════════

class TestBehavioral:
    def test_record_event_does_not_raise(self):
        from warden.communities.behavioral import record_event
        record_event("beh-com-1", "request", 1.0)  # must not raise

    def test_compute_baseline_empty(self):
        from warden.communities.behavioral import compute_baseline
        snap = compute_baseline("beh-empty-1", "request")
        assert snap.mean == 0.0
        assert snap.stddev == 1.0
        assert snap.sample_count == 0

    def test_compute_baseline_with_data(self):
        from warden.communities.behavioral import compute_baseline, record_event
        cid = _cid("beh-data")
        for i in range(20):
            record_event(cid, "request", float(i))
        snap = compute_baseline(cid, "request")
        assert snap.sample_count >= 20
        assert snap.mean > 0
        assert snap.stddev > 0

    def test_detect_anomaly_insufficient_history(self):
        from warden.communities.behavioral import detect_anomaly
        result = detect_anomaly(_cid("beh-new"), "request", 999.0)
        assert result.severity == "NORMAL"
        assert result.action == "ALLOW"
        assert result.reason == "insufficient_history"

    def test_detect_anomaly_normal_within_2sigma(self):
        from warden.communities.behavioral import compute_baseline, detect_anomaly, record_event
        cid = _cid("beh-norm")
        for _ in range(30):
            record_event(cid, "request", 5.0)
        compute_baseline(cid, "request")
        result = detect_anomaly(cid, "request", 5.0)
        assert result.severity == "NORMAL"
        assert result.action == "ALLOW"

    def test_detect_anomaly_critical_above_3sigma(self):
        from warden.communities.behavioral import compute_baseline, detect_anomaly, record_event
        cid = _cid("beh-crit")
        for _ in range(30):
            record_event(cid, "bulk_transfer", 1.0)
        compute_baseline(cid, "bulk_transfer")
        result = detect_anomaly(cid, "bulk_transfer", 1000.0)
        assert result.severity == "CRITICAL"
        assert result.action == "BLOCK"

    def test_detect_bulk_transfer(self):
        from warden.communities.behavioral import detect_bulk_transfer
        result = detect_bulk_transfer("beh-bulk-1", 0)
        assert result.event_type == "bulk_transfer"

    def test_detect_off_hours(self):
        from warden.communities.behavioral import detect_off_hours
        result = detect_off_hours("beh-offhours-1")
        assert result.event_type == "off_hours_access"
        assert result.action in ("ALLOW", "ALERT", "BLOCK")

    def test_list_recent_anomalies_empty(self):
        from warden.communities.behavioral import list_recent_anomalies
        result = list_recent_anomalies("beh-no-anomalies")
        assert isinstance(result, list)

    def test_risk_summary_shape(self):
        from warden.communities.behavioral import get_community_risk_summary
        summary = get_community_risk_summary("beh-sum-1")
        assert "community_id" in summary
        assert "metrics" in summary


# ══════════════════════════════════════════════════════════════════════════════
# Intelligence Report
# ══════════════════════════════════════════════════════════════════════════════

class TestIntelligence:
    def test_generate_report_shape(self):
        from warden.communities.intelligence import generate_report
        report = generate_report("intel-com-1")
        d = report.to_dict()
        assert "community_id" in d
        assert "risk" in d
        assert "transfers" in d
        assert "peerings" in d
        assert "governance" in d
        assert "recommendations" in d

    def test_risk_label_valid(self):
        from warden.communities.intelligence import generate_report
        report = generate_report("intel-com-2")
        assert report.risk.label in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_risk_overall_bounds(self):
        from warden.communities.intelligence import generate_report
        report = generate_report("intel-com-3")
        assert 0.0 <= report.risk.overall <= 1.0

    def test_recommendations_not_empty(self):
        from warden.communities.intelligence import generate_report
        report = generate_report("intel-com-4")
        assert len(report.recommendations) > 0

    def test_empty_community_is_safe(self):
        from warden.communities.intelligence import generate_report
        report = generate_report("intel-new-empty")
        # No transfers, no anomalies, no charter → low/safe
        assert report.risk.label in ("SAFE", "LOW")

    def test_to_dict_serializable(self):
        import json

        from warden.communities.intelligence import generate_report
        report = generate_report("intel-serial-1")
        # Must not raise
        json.dumps(report.to_dict())


# ══════════════════════════════════════════════════════════════════════════════
# OAuth Agent Discovery
# ══════════════════════════════════════════════════════════════════════════════

class TestOAuthDiscovery:
    def test_register_grant_returns_record(self):
        from warden.communities.oauth_discovery import register_oauth_grant
        grant = register_oauth_grant("oauth-com-1", "mem-1", "zapier", ["read", "write"])
        assert grant.grant_id.startswith("OAG-")
        assert grant.community_id == "oauth-com-1"
        assert grant.provider == "zapier"

    def test_classify_chatgpt_is_critical(self):
        from warden.communities.oauth_discovery import classify_provider
        risk, verdict = classify_provider("chatgpt_plugin", ["read", "write", "admin"])
        assert risk == "CRITICAL"
        assert verdict == "BLOCK"

    def test_classify_grammarly_is_low(self):
        from warden.communities.oauth_discovery import classify_provider
        risk, verdict = classify_provider("grammarly", ["read"])
        assert risk == "LOW"
        assert verdict == "ALLOW"

    def test_admin_scope_escalates_risk(self):
        from warden.communities.oauth_discovery import classify_provider
        # notion_ai is MEDIUM; admin scope → HIGH
        risk, _ = classify_provider("notion_ai", ["read", "admin"])
        assert risk in ("HIGH", "CRITICAL")

    def test_revoke_grant(self):
        from warden.communities.oauth_discovery import register_oauth_grant, revoke_grant
        grant = register_oauth_grant("oauth-rev-1", "mem-2", "cohere", ["write"])
        revoked = revoke_grant(grant.grant_id)
        assert revoked.status == "REVOKED"
        assert revoked.revoked_at is not None

    def test_list_grants_active_only(self):
        from warden.communities.oauth_discovery import (
            list_grants,
            register_oauth_grant,
            revoke_grant,
        )
        g1 = register_oauth_grant("oauth-list-1", "m1", "make", ["read"])
        g2 = register_oauth_grant("oauth-list-1", "m2", "jasper", ["write"])
        revoke_grant(g1.grant_id)
        active = list_grants("oauth-list-1", status="ACTIVE")
        active_ids = {g.grant_id for g in active}
        assert g2.grant_id in active_ids
        assert g1.grant_id not in active_ids

    def test_risk_summary_shape(self):
        from warden.communities.oauth_discovery import get_risk_summary
        summary = get_risk_summary("oauth-sum-1")
        assert "total_active" in summary
        assert "blocked_agents" in summary
        assert "by_risk_level" in summary

    def test_provider_catalog_not_empty(self):
        from warden.communities.oauth_discovery import get_provider_catalog
        catalog = get_provider_catalog()
        assert len(catalog) >= 10
        assert all("provider" in p and "risk" in p for p in catalog)

    def test_unknown_provider_defaults_to_high(self):
        from warden.communities.oauth_discovery import classify_provider
        risk, _ = classify_provider("totally_unknown_ai_tool_xyz", [])
        assert risk == "HIGH"

    def test_grant_to_dict_serializable(self):
        import json

        from warden.communities.oauth_discovery import register_oauth_grant
        grant = register_oauth_grant("oauth-ser-1", "m1", "perplexity", ["search"])
        json.dumps(grant.to_dict())


# ══════════════════════════════════════════════════════════════════════════════
# Community Intel API (via TestClient)
# ══════════════════════════════════════════════════════════════════════════════

class TestCommunityIntelAPI:
    def test_report_requires_tenant(self, client):
        resp = client.get("/community-intel/com-1")
        assert resp.status_code == 401

    def test_report_returns_shape(self, client):
        resp = client.get(
            "/community-intel/api-test-com",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "risk" in data
        assert "transfers" in data
        assert "governance" in data

    def test_risk_endpoint(self, client):
        resp = client.get(
            "/community-intel/api-test-com/risk",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "label" in data
        assert "overall" in data

    def test_create_charter_via_api(self, client):
        resp = client.post(
            "/community-intel/api-charter-com/charter",
            headers={"X-Tenant-ID": "test-tenant"},
            json={"title": "API Test Charter"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "DRAFT"
        assert data["title"] == "API Test Charter"

    def test_no_active_charter_404(self, client):
        resp = client.get(
            "/community-intel/no-charter-com-xyz/charter",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert resp.status_code == 404

    def test_anomalies_endpoint(self, client):
        resp = client.get(
            "/community-intel/api-anomaly-com/anomalies",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert resp.status_code == 200
        assert "anomalies" in resp.json()

    def test_detect_anomaly_endpoint(self, client):
        resp = client.post(
            "/community-intel/api-detect-com/anomalies/detect",
            headers={"X-Tenant-ID": "test-tenant"},
            json={"event_type": "request", "value": 1.0},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "severity" in data
        assert "action" in data

    def test_oauth_list_requires_tenant(self, client):
        resp = client.get("/community-intel/com-1/oauth")
        assert resp.status_code == 401

    def test_oauth_register_via_api(self, client):
        resp = client.post(
            "/community-intel/api-oauth-com/oauth",
            headers={"X-Tenant-ID": "test-tenant"},
            json={"member_id": "m-1", "provider": "zapier", "scopes": ["read"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "zapier"
        assert data["grant_id"].startswith("OAG-")

    def test_oauth_catalog_endpoint(self, client):
        resp = client.get(
            "/community-intel/oauth/catalog",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert resp.status_code == 200
        assert "providers" in resp.json()

    def test_oauth_revoke_via_api(self, client):
        # Register first
        reg = client.post(
            "/community-intel/api-revoke-com/oauth",
            headers={"X-Tenant-ID": "test-tenant"},
            json={"member_id": "m-x", "provider": "cohere", "scopes": ["write"]},
        )
        grant_id = reg.json()["grant_id"]
        # Revoke
        rev = client.delete(
            f"/community-intel/oauth/{grant_id}",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert rev.status_code == 200
        assert rev.json()["status"] == "REVOKED"

    def test_charter_invalid_transparency_422(self, client):
        resp = client.post(
            "/community-intel/api-val-com/charter",
            headers={"X-Tenant-ID": "test-tenant"},
            json={"title": "Bad Charter", "transparency": "INVALID"},
        )
        assert resp.status_code == 422
