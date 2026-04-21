"""Tests for Community Business (SMB) tier, file scanner, and SMB presets."""
import io
import os

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("SEMANTIC_THRESHOLD", "0.72")
os.environ.setdefault("LOGS_PATH", "/tmp/warden_smb_test_logs.json")


# ══════════════════════════════════════════════════════════════════════════════
# community_business tier — feature_gate
# ══════════════════════════════════════════════════════════════════════════════

class TestCommunityBusinessTier:
    def test_tier_exists(self):
        from warden.billing.feature_gate import TIER_LIMITS
        assert "community_business" in TIER_LIMITS

    def test_smb_alias(self):
        from warden.billing.feature_gate import _normalize_tier
        assert _normalize_tier("smb") == "community_business"

    def test_tier_order_between_individual_and_pro(self):
        from warden.billing.feature_gate import _TIER_ORDER
        assert _TIER_ORDER["community_business"] > _TIER_ORDER["individual"]
        assert _TIER_ORDER["community_business"] < _TIER_ORDER["pro"]

    def test_features_enabled(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("community_business")
        assert gate.is_enabled("prompt_shield")
        assert gate.is_enabled("secret_redactor")
        assert gate.is_enabled("audit_trail")
        assert gate.is_enabled("file_scanner_enabled")
        assert gate.is_enabled("communities_enabled")
        assert gate.is_enabled("gdpr_purge_api")
        assert gate.is_enabled("smb_onboarding")
        assert gate.is_enabled("smb_allowlist_preset")
        assert gate.is_enabled("smb_compliance_report")

    def test_enterprise_features_disabled(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("community_business")
        assert not gate.is_enabled("pqc_enabled")
        assert not gate.is_enabled("sovereign_enabled")
        assert not gate.is_enabled("master_agent_enabled")
        assert not gate.is_enabled("siem_integration")
        assert not gate.is_enabled("shadow_ai_enabled")
        assert not gate.is_enabled("white_label")

    def test_community_limits(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("community_business")
        assert gate.get("max_communities") == 3
        assert gate.get("max_members_per_community") == 10

    def test_req_quota(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("community_business")
        assert gate.quota_req_per_month() == 10_000

    def test_meets_minimum_above_individual(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("community_business")
        assert gate.meets_minimum("individual") is True
        assert gate.meets_minimum("starter") is True

    def test_meets_minimum_below_pro(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("community_business")
        assert gate.meets_minimum("pro") is False
        assert gate.meets_minimum("enterprise") is False

    def test_as_dict_includes_tier(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("community_business")
        d = gate.as_dict()
        assert d["tier"] == "community_business"
        assert d["req_per_month"] == 10_000

    def test_shadow_ai_monitor_flag(self):
        from warden.billing.feature_gate import TIER_LIMITS
        limits = TIER_LIMITS["community_business"]
        assert limits.get("shadow_ai_monitor") is True

    def test_retention_days(self):
        from warden.billing.feature_gate import TIER_LIMITS
        limits = TIER_LIMITS["community_business"]
        assert limits["retention_days"] == 180


# ══════════════════════════════════════════════════════════════════════════════
# shadow_ai/smb_presets
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def clear_policy_store():
    import warden.shadow_ai.policy as pol
    pol._MEMORY_STORE.clear()
    yield
    pol._MEMORY_STORE.clear()


class TestSMBPresets:
    def test_approved_keys_not_empty(self):
        from warden.shadow_ai.smb_presets import SMB_APPROVED_KEYS
        assert len(SMB_APPROVED_KEYS) >= 10
        assert "openai" in SMB_APPROVED_KEYS
        assert "anthropic" in SMB_APPROVED_KEYS

    def test_denylist_not_empty(self):
        from warden.shadow_ai.smb_presets import SMB_DEFAULT_DENYLIST
        assert len(SMB_DEFAULT_DENYLIST) >= 3
        assert "huggingface" in SMB_DEFAULT_DENYLIST

    def test_apply_smb_preset_monitor(self):
        from warden.shadow_ai.smb_presets import apply_smb_preset
        policy = apply_smb_preset("smb-t1", mode="MONITOR")
        assert policy["mode"] == "MONITOR"
        assert "openai" in policy["allowlist"]
        assert "huggingface" in policy["denylist"]
        assert policy.get("smb_preset") is True

    def test_apply_smb_preset_allowlist_only(self):
        from warden.shadow_ai.smb_presets import apply_smb_preset
        policy = apply_smb_preset("smb-t2", mode="ALLOWLIST_ONLY")
        assert policy["mode"] == "ALLOWLIST_ONLY"

    def test_apply_smb_preset_block_denylist(self):
        from warden.shadow_ai.smb_presets import apply_smb_preset
        policy = apply_smb_preset("smb-t3", mode="BLOCK_DENYLIST")
        assert policy["mode"] == "BLOCK_DENYLIST"

    def test_get_smb_catalog_structure(self):
        from warden.shadow_ai.smb_presets import get_smb_catalog
        catalog = get_smb_catalog()
        assert len(catalog) >= 10
        for item in catalog:
            assert "key" in item
            assert "display" in item
            assert "risk" in item
            assert "category" in item
            assert item["approved"] is True

    def test_catalog_categories(self):
        from warden.shadow_ai.smb_presets import get_smb_catalog
        cats = {item["category"] for item in get_smb_catalog()}
        assert "llm" in cats
        assert "code" in cats
        assert "productivity" in cats

    def test_preset_allowlist_excludes_denylist(self):
        from warden.shadow_ai.smb_presets import SMB_APPROVED_KEYS, SMB_DEFAULT_DENYLIST
        overlap = set(SMB_APPROVED_KEYS) & set(SMB_DEFAULT_DENYLIST)
        assert len(overlap) == 0, f"Allowlist/denylist overlap: {overlap}"

    def test_apply_preset_updates_policy_in_memory(self):
        from warden.shadow_ai.smb_presets import apply_smb_preset
        from warden.shadow_ai.policy import get_policy
        apply_smb_preset("smb-t4", mode="MONITOR")
        policy = get_policy("smb-t4")
        assert policy["mode"] == "MONITOR"
        assert "openai" in policy["allowlist"]

    def test_preset_sets_timestamp(self):
        from warden.shadow_ai.smb_presets import apply_smb_preset
        policy = apply_smb_preset("smb-t5")
        assert "preset_applied" in policy
        assert policy["preset_applied"] != ""


# ══════════════════════════════════════════════════════════════════════════════
# api/file_scan — unit tests (no FastAPI server needed)
# ══════════════════════════════════════════════════════════════════════════════

class TestFileScanHelpers:
    def test_extract_text_plain(self):
        from warden.api.file_scan import _extract_text
        text = _extract_text(b"Hello world", "text/plain", "test.txt")
        assert "Hello world" in text

    def test_extract_text_utf8(self):
        from warden.api.file_scan import _extract_text
        content = "Привет мир".encode("utf-8")
        text = _extract_text(content, "text/plain", "test.txt")
        assert "Привет" in text

    def test_extract_text_latin1_fallback(self):
        from warden.api.file_scan import _extract_text
        content = b"\xff\xfe hello"  # invalid UTF-8, valid Latin-1
        text = _extract_text(content, "text/plain", "test.txt")
        assert text  # should not raise

    def test_line_of_match(self):
        from warden.api.file_scan import _line_of_match
        text = "line1\nline2\nline3"
        assert _line_of_match(text, 0)  == 1
        assert _line_of_match(text, 6)  == 2  # after first \n
        assert _line_of_match(text, 12) == 3

    def test_risk_level_safe(self):
        from warden.api.file_scan import _risk_level
        assert _risk_level([], False) == "SAFE"

    def test_risk_level_critical_injection(self):
        from warden.api.file_scan import _risk_level
        assert _risk_level([], True) == "CRITICAL"

    def test_risk_level_high_many_findings(self):
        from warden.api.file_scan import FileScanFinding, _risk_level
        findings = [FileScanFinding(kind="secret", label=f"Key {i}", excerpt="...", line=i) for i in range(10)]
        assert _risk_level(findings, False) == "HIGH"

    def test_risk_level_high_multiple_secrets(self):
        from warden.api.file_scan import FileScanFinding, _risk_level
        findings = [FileScanFinding(kind="secret", label=f"Key {i}", excerpt="...", line=i) for i in range(3)]
        assert _risk_level(findings, False) == "HIGH"

    def test_risk_level_medium_one_secret(self):
        from warden.api.file_scan import FileScanFinding, _risk_level
        findings = [FileScanFinding(kind="secret", label="Key", excerpt="...", line=1)]
        assert _risk_level(findings, False) == "MEDIUM"

    def test_risk_level_low_pii_only(self):
        from warden.api.file_scan import FileScanFinding, _risk_level
        findings = [FileScanFinding(kind="pii", label="Email", excerpt="...", line=1)]
        assert _risk_level(findings, False) == "LOW"


class TestFileScanEndpoint:
    """Integration-style tests using FastAPI TestClient."""

    @pytest.fixture()
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from warden.api.file_scan import router
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_scan_clean_text(self, client):
        resp = client.post(
            "/filter/file",
            data={"tenant_id": "test"},
            files={"file": ("hello.txt", b"Hello world, this is a safe document.", "text/plain")},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["filename"] == "hello.txt"
        assert body["risk_level"] in ("SAFE", "LOW")
        assert body["safe"] is True

    def test_scan_file_with_api_key(self, client):
        content = b"My OpenAI key is sk-abcdef1234567890abcdef1234567890abcdef12"
        resp = client.post(
            "/filter/file",
            data={"tenant_id": "test"},
            files={"file": ("creds.txt", content, "text/plain")},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert body["safe"] is False
        assert body["findings_count"] >= 1

    def test_scan_file_with_email_pii(self, client):
        content = b"Please send the report to john.doe@example.com by Friday."
        resp = client.post(
            "/filter/file",
            data={"tenant_id": "test"},
            files={"file": ("report.txt", content, "text/plain")},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["findings_count"] >= 1
        kinds = {f["kind"] for f in body["findings"]}
        assert "pii" in kinds

    def test_scan_file_returns_sanitized_text(self, client):
        content = b"Key: sk-abcdef1234567890abcdef1234567890abcdef12 use it."
        resp = client.post(
            "/filter/file",
            data={"tenant_id": "test"},
            files={"file": ("test.txt", content, "text/plain")},
        )
        body = resp.json()
        assert "sk-abcdef" not in body["sanitized_text"]

    def test_scan_file_too_large(self, client):
        big = b"x" * (10 * 1024 * 1024 + 1)
        resp = client.post(
            "/filter/file",
            data={"tenant_id": "test"},
            files={"file": ("big.txt", big, "text/plain")},
        )
        assert resp.status_code == 413

    def test_supported_types_endpoint(self, client):
        resp = client.get("/filter/file/supported-types")
        assert resp.status_code == 200
        body = resp.json()
        assert ".txt" in body["text"]
        assert ".pdf" in body["pdf"]
        assert body["max_size_mb"] == 10

    def test_scan_json_file(self, client):
        content = b'{"name": "John", "email": "john@example.com", "balance": 1000}'
        resp = client.post(
            "/filter/file",
            data={"tenant_id": "test"},
            files={"file": ("data.json", content, "application/json")},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "filename" in body
        assert body["size_bytes"] == len(content)

    def test_scan_with_strict_mode(self, client):
        content = b"Server IP: 192.168.1.1, connect to db on port 5432"
        resp = client.post(
            "/filter/file",
            data={"tenant_id": "test", "strict": "true"},
            files={"file": ("config.txt", content, "text/plain")},
        )
        assert resp.status_code == 200
        # strict mode may flag IPs
        assert "findings" in resp.json()

    def test_scan_processing_ms_present(self, client):
        resp = client.post(
            "/filter/file",
            data={"tenant_id": "test"},
            files={"file": ("t.txt", b"hello", "text/plain")},
        )
        body = resp.json()
        assert body["processing_ms"] >= 0

    def test_scan_unknown_filename(self, client):
        resp = client.post(
            "/filter/file",
            data={"tenant_id": "test"},
            files={"file": ("upload", b"some content", "text/plain")},
        )
        assert resp.status_code == 200
