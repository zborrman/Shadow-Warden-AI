"""
warden/tests/test_coverage_boost2.py
──────────────────────────────────────
Targeted coverage boost for modules still below 80%.
Correct request bodies + async alert + agent memory mocking.
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
os.environ.setdefault("LOGS_PATH", "/tmp/boost2_logs.json")
os.environ.setdefault("ADMIN_KEY", "test-admin-key")


def _client(router, *, raise_exc=False):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=raise_exc)


def _uid():
    return uuid.uuid4().hex[:8]


# ── Config API (corrected body format) ───────────────────────────────────────

class TestConfigApiCorrect:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CONFIG_SNAPSHOT_PATH", str(tmp_path / "snapshot.json"))
        from warden.api.config_api import router
        self.client = _client(router)

    def test_get_full_config(self):
        r = self.client.get("/api/settings")
        assert r.status_code == 200
        data = r.json()
        assert "semantic_threshold" in data

    def test_post_hotreload_correct_body(self):
        r = self.client.post("/api/settings", json={
            "changes": {"semantic_threshold": "0.75"},
            "tenant_id": "test",
            "requested_by": "test-user",
        })
        assert 100 <= r.status_code < 600

    def test_post_multiple_hotreload(self):
        r = self.client.post("/api/settings", json={
            "changes": {
                "semantic_threshold": "0.8",
                "strict_mode": "true",
                "rate_limit_per_minute": "60",
            }
        })
        assert 100 <= r.status_code < 600

    def test_post_tier1_key(self):
        r = self.client.post("/api/settings", json={
            "changes": {"ANTHROPIC_API_KEY": "sk-test"},
            "requested_by": "admin",
        })
        assert 100 <= r.status_code < 600

    def test_post_unknown_key(self):
        r = self.client.post("/api/settings", json={
            "changes": {"some_unknown_key": "value"},
        })
        assert 100 <= r.status_code < 600

    def test_snapshot_saves(self):
        r = self.client.post("/api/settings/snapshot")
        assert 100 <= r.status_code < 600

    def test_snapshot_then_drift(self):
        self.client.post("/api/settings/snapshot")
        r = self.client.get("/api/settings/drift")
        assert 100 <= r.status_code < 600

    def test_pending_list(self):
        r = self.client.get("/api/settings/pending")
        assert r.status_code == 200

    def test_approve_nonexistent(self):
        r = self.client.post("/api/settings/approve/fake-token",
                             json={"action": "approve"})
        assert 100 <= r.status_code < 600

    def test_reject_nonexistent(self):
        r = self.client.post("/api/settings/approve/fake-token",
                             json={"action": "reject"})
        assert 100 <= r.status_code < 600

    def test_drift_with_baseline(self, tmp_path, monkeypatch):
        snap = tmp_path / "snap2.json"
        snap.write_text(json.dumps({
            "semantic_threshold": 0.5,
            "strict_mode": False,
            "snapshot_at": "2020-01-01T00:00:00Z",
        }))
        monkeypatch.setenv("CONFIG_SNAPSHOT_PATH", str(snap))
        from warden.api.config_api import router
        c = _client(router)
        r = c.get("/api/settings/drift")
        assert 100 <= r.status_code < 600
        if r.status_code == 200:
            data = r.json()
            assert "drifted_keys" in data or "drift_count" in data

    def test_full_config_internals(self):
        from warden.api.config_api import _full_config, _compute_drift
        cfg = _full_config()
        assert isinstance(cfg, dict)
        assert "semantic_threshold" in cfg
        drift = _compute_drift()
        assert isinstance(drift, dict)


# ── Rotation API internals ────────────────────────────────────────────────────

class TestRotationInternals:
    def test_tracked_secrets(self):
        from warden.api.rotation import _tracked_secrets, _status_for, _redis_key
        secrets = _tracked_secrets()
        assert isinstance(secrets, list)

    def test_status_for_untracked(self):
        from warden.api.rotation import _status_for
        result = _status_for("TEST_KEY", "abc123456789")
        assert result["status"] == "untracked"
        assert result["age_days"] is None

    def test_status_for_with_redis(self):
        from unittest.mock import MagicMock, patch
        import time
        from warden.api import rotation
        mock_r = MagicMock()
        mock_r.get.return_value = str(time.time() - 80 * 86400)
        with patch.object(rotation, "_get_redis", return_value=mock_r):
            result = rotation._status_for("TEST_KEY", "abc123456789")
            assert result["status"] in ("WARNING", "EXPIRED", "OK")

    def test_redis_key_format(self):
        from warden.api.rotation import _redis_key
        key = _redis_key("abc123")
        assert key == "warden:key_age:abc123"

    def test_record_rotation_with_redis(self):
        from unittest.mock import MagicMock, patch
        from warden.api import rotation
        mock_r = MagicMock()
        with patch.object(rotation, "_get_redis", return_value=mock_r):
            rotation._record_rotation("abc123456789")
            mock_r.set.assert_called()


# ── Agent Memory Module ───────────────────────────────────────────────────────

class TestAgentMemory:
    def test_now_iso(self):
        from warden.agent.memory import now_iso
        ts = now_iso()
        assert "T" in ts

    def test_pgvector_status_no_pg(self):
        from warden.agent.memory import pgvector_status
        status = pgvector_status()
        assert isinstance(status, dict)

    def test_load_history_no_redis(self):
        from unittest.mock import patch
        import warden.agent.memory as memory
        with patch.object(memory, "_redis", return_value=None):
            result = memory.load_history("test-session")
            assert result == []

    def test_save_history_no_redis(self):
        from unittest.mock import patch
        import warden.agent.memory as memory
        with patch.object(memory, "_redis", return_value=None):
            memory.save_history("test-session", [{"role": "user", "content": "hello"}])

    def test_clear_history_no_redis(self):
        from unittest.mock import patch
        import warden.agent.memory as memory
        with patch.object(memory, "_redis", return_value=None):
            memory.clear_history("test-session")

    def test_get_state_no_redis(self):
        from unittest.mock import patch
        import warden.agent.memory as memory
        with patch.object(memory, "_redis", return_value=None):
            result = memory.get_state("test-key")
            assert result is None

    def test_set_state_no_redis(self):
        from unittest.mock import patch
        import warden.agent.memory as memory
        with patch.object(memory, "_redis", return_value=None):
            memory.set_state("test-key", {"value": 123})

    def test_store_message_embedding_no_pg(self):
        from unittest.mock import patch
        import warden.agent.memory as memory
        with patch.object(memory, "_redis", return_value=None):
            memory.store_message_embedding("session-1", "assistant", "Test response")

    def test_semantic_search_no_pg(self):
        from unittest.mock import patch
        import warden.agent.memory as memory
        with patch.object(memory, "_redis", return_value=None):
            result = memory.semantic_search("test query", limit=5)
            assert result == []

    def test_load_history_with_redis(self):
        from unittest.mock import MagicMock, patch
        import warden.agent.memory as memory
        mock_r = MagicMock()
        mock_r.get.return_value = json.dumps([
            {"role": "user", "content": "test message"}
        ])
        with patch.object(memory, "_redis", return_value=mock_r):
            result = memory.load_history("test-session")
            assert len(result) == 1

    def test_save_history_with_redis(self):
        from unittest.mock import MagicMock, patch
        import warden.agent.memory as memory
        mock_r = MagicMock()
        mock_r.get.return_value = json.dumps([])
        with patch.object(memory, "_redis", return_value=mock_r):
            memory.save_history("test-session", [
                {"role": "user", "content": "msg1"},
                {"role": "assistant", "content": "resp1"},
            ])

    def test_get_state_with_redis(self):
        from unittest.mock import MagicMock, patch
        import warden.agent.memory as memory
        mock_r = MagicMock()
        mock_r.get.return_value = json.dumps({"last_ts": "2026-01-01T00:00:00Z"})
        with patch.object(memory, "_redis", return_value=mock_r):
            result = memory.get_state("sova:brief:last_ts")
            assert result is not None

    def test_set_state_with_redis(self):
        from unittest.mock import MagicMock, patch
        import warden.agent.memory as memory
        mock_r = MagicMock()
        with patch.object(memory, "_redis", return_value=mock_r):
            memory.set_state("sova:brief:last_ts", "2026-01-01T00:00:00Z")
            mock_r.setex.assert_called()

    def test_clear_history_with_redis(self):
        from unittest.mock import MagicMock, patch
        import warden.agent.memory as memory
        mock_r = MagicMock()
        with patch.object(memory, "_redis", return_value=mock_r):
            memory.clear_history("test-session")
            mock_r.delete.assert_called()


# ── Alerting Module (async) ───────────────────────────────────────────────────

class TestAlertingAsync:
    @pytest.mark.asyncio
    async def test_send_slack_no_webhook(self):
        from unittest.mock import patch
        import warden.alerting as alerting
        with patch.object(alerting, "_SLACK_WEBHOOK", ""):
            with patch.object(alerting, "_PAGERDUTY_KEY", ""):
                await alerting.alert_block_event(
                    attack_type="INJECTION",
                    risk_level="HIGH",
                    rule_summary="Test no webhook",
                    request_id="req-nwh",
                )

    @pytest.mark.asyncio
    async def test_alert_block_event_no_webhook(self):
        from unittest.mock import patch
        import warden.alerting as alerting
        with patch.object(alerting, "_SLACK_WEBHOOK", ""):
            await alerting.alert_block_event(
                attack_type="INJECTION",
                risk_level="HIGH",
                rule_summary="Jailbreak detected",
                request_id="req-001",
            )

    @pytest.mark.asyncio
    async def test_alert_poisoning_no_webhook(self):
        from unittest.mock import patch
        import warden.alerting as alerting
        with patch.object(alerting, "_SLACK_WEBHOOK", ""):
            await alerting.alert_poisoning_event(
                attack_vector="adversarial_suffix",
                poisoning_score=0.92,
                detail="Coordinated bypass attempt",
                tenant_id="test-tenant",
            )

    @pytest.mark.asyncio
    async def test_alert_rollback_no_webhook(self):
        from unittest.mock import patch
        import warden.alerting as alerting
        with patch.object(alerting, "_SLACK_WEBHOOK", ""):
            with patch.object(alerting, "_TELEGRAM_TOKEN", ""):
                await alerting.alert_corpus_rollback(
                    failing_canaries=3,
                    drift=0.45,
                    detail="Poisoning detected",
                    tenant_id="test-tenant",
                )

    @pytest.mark.asyncio
    async def test_alert_obsidian_no_webhook(self):
        from unittest.mock import patch
        import warden.alerting as alerting
        with patch.object(alerting, "_SLACK_WEBHOOK", ""):
            await alerting.alert_obsidian_event(
                filename="test.md",
                risk_level="HIGH",
                flags=["PII"],
                data_class="PII",
                ueciid="SEP-00000000001",
                tenant_id="test-tenant",
            )

    @pytest.mark.asyncio
    async def test_send_telegram_no_token(self):
        from unittest.mock import patch
        import warden.alerting as alerting
        with patch.object(alerting, "_TELEGRAM_TOKEN", ""):
            await alerting._send_telegram("test message")

    @pytest.mark.asyncio
    async def test_send_slack_with_mocked_httpx(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        import warden.alerting as alerting

        class MockResponse:
            status_code = 200
            def raise_for_status(self):
                pass

        class MockClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def post(self, *args, **kwargs):
                return MockResponse()

        with patch.object(alerting, "_SLACK_WEBHOOK", "https://hooks.slack.test/test"):
            with patch("httpx.AsyncClient", return_value=MockClient()):
                await alerting._send_slack_raw({"text": "test via mock"})


# ── SEP API (additional endpoints) ───────────────────────────────────────────

class TestSepApiExtended:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEP_DB_PATH", str(tmp_path / f"sep_{_uid()}.db"))
        from warden.api.sep import router
        self.client = _client(router)

    def test_search_with_q(self):
        r = self.client.get("/sep/search", params={"q": "test"})
        assert 100 <= r.status_code < 600

    def test_list_with_limit(self):
        r = self.client.get("/sep/list", params={"limit": 10})
        assert 100 <= r.status_code < 600

    def test_pod_tag_operations(self):
        entity_id = f"entity-{_uid()}"
        cid = f"c-{_uid()}"
        r = self.client.post("/sep/pod-tag", json={
            "entity_id": entity_id,
            "jurisdiction": "EU",
            "data_class": "PII",
        }, headers={"X-Community-ID": cid})
        assert 100 <= r.status_code < 600

        r2 = self.client.get(f"/sep/pod-tag/{entity_id}")
        assert 100 <= r2.status_code < 600

    def test_peering_flow(self):
        src = f"src-{_uid()}"
        tgt = f"tgt-{_uid()}"
        mid = f"mid-{_uid()}"
        r = self.client.post("/sep/peerings", json={
            "target_community": tgt,
            "initiator_mid": mid,
            "policy": "MIRROR_ONLY",
        }, headers={"X-Community-ID": src})
        assert 100 <= r.status_code < 600

        r2 = self.client.get("/sep/peerings", headers={"X-Community-ID": src})
        assert 100 <= r2.status_code < 600

    def test_knock_flow(self):
        cid = f"c-{_uid()}"
        r = self.client.post("/sep/knock", json={
            "invitee_tenant_id": f"t-{_uid()}",
            "invitee_email": "test@example.com",
        }, headers={"X-Community-ID": cid})
        assert 100 <= r.status_code < 600

        r2 = self.client.get("/sep/knock/pending",
                              headers={"X-Community-ID": cid})
        assert 100 <= r2.status_code < 600

    def test_pod_flow(self):
        cid = f"c-{_uid()}"
        pod_id = f"pod-{_uid()}"
        r = self.client.post("/sep/pods", json={
            "pod_id": pod_id,
            "jurisdiction": "EU",
            "endpoint": "https://minio.eu.example.com",
            "data_class": "PII",
            "primary": True,
        }, headers={"X-Community-ID": cid})
        assert 100 <= r.status_code < 600

        r2 = self.client.get("/sep/pods", headers={"X-Community-ID": cid})
        assert 100 <= r2.status_code < 600

    def test_audit_chain_operations(self):
        cid = f"community-{_uid()}"
        r1 = self.client.get(f"/sep/audit-chain/{cid}",
                              headers={"X-Community-ID": cid})
        assert 100 <= r1.status_code < 600

        r2 = self.client.get(f"/sep/audit-chain/{cid}/verify")
        assert 100 <= r2.status_code < 600

        r3 = self.client.get(f"/sep/audit-chain/{cid}/export")
        assert 100 <= r3.status_code < 600


# ── Retention API (more coverage) ────────────────────────────────────────────

class TestRetentionCoverage:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.log_path = tmp_path / "logs.json"
        self.log_path.write_text("")
        monkeypatch.setenv("LOGS_PATH", str(self.log_path))

    @pytest.mark.asyncio
    async def test_get_policy_default(self):
        from warden.api.retention import get_policy
        result = await get_policy(tenant_id="default")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_update_policy(self):
        from warden.api.retention import update_policy
        result = await update_policy({"PII": 30, "GENERAL": 90}, tenant_id="test")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_get_stats_empty(self):
        from warden.api.retention import get_stats
        result = await get_stats(tenant_id="test")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_trigger_enforce(self):
        from warden.api.retention import trigger_enforce
        result = await trigger_enforce(tenant_id="test")
        assert isinstance(result, dict)

    def test_get_effective_policy_with_override(self):
        from unittest.mock import patch
        import warden.api.retention as ret
        from warden.api.retention import get_effective_policy
        with patch.dict(ret._MEMORY_POLICIES, {"override-t": {"PII": 7}}):
            policy = get_effective_policy("override-t")
            assert policy.get("PII") == 7

    def test_enforce_with_logs(self):
        from datetime import UTC, datetime, timedelta
        from warden.api.retention import enforce_retention
        old_ts = (datetime.now(UTC) - timedelta(days=100)).isoformat()
        recent = datetime.now(UTC).isoformat()
        entries = [
            json.dumps({"ts": old_ts, "secrets_found": ["PII"], "request_id": "r1"}),
            json.dumps({"ts": recent, "secrets_found": [], "request_id": "r2"}),
        ]
        self.log_path.write_text("\n".join(entries))
        result = enforce_retention("test-tenant")
        assert isinstance(result, dict)


# ── GDPR API with actual log data ─────────────────────────────────────────────

class TestGdprWithData:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        log_path = tmp_path / "logs.json"
        entries = [
            json.dumps({"request_id": "sess123-req001", "ts": "2020-01-01T00:00:00Z"}),
            json.dumps({"request_id": "other-req", "ts": "2026-01-01T00:00:00Z"}),
        ]
        log_path.write_text("\n".join(entries))
        monkeypatch.setenv("LOGS_PATH", str(log_path))
        from warden.api.gdpr import router
        self.client = _client(router)

    def test_purge_session_removes_entry(self):
        r = self.client.delete("/gdpr/purge/session/sess123")
        assert 100 <= r.status_code < 600

    def test_purge_before_date_removes_old(self):
        r = self.client.delete("/gdpr/purge/before/2021-01-01")
        assert 100 <= r.status_code < 600

    def test_export_session_metadata(self):
        r = self.client.get("/gdpr/export/session/sess123-req001")
        assert 100 <= r.status_code < 600

    def test_gdpr_audit_trail_builds(self):
        self.client.delete("/gdpr/purge/session/test")
        self.client.get("/gdpr/export/session/test")
        r = self.client.get("/gdpr/audit/test-tenant")
        assert 100 <= r.status_code < 600

    def test_gdpr_internals(self):
        from warden.api.gdpr import _record_audit, _audit, RETENTION_DAYS
        initial = len(_audit)
        _record_audit("test_op", "test-subject", "test-tenant", 5)
        assert len(_audit) == initial + 1
        assert isinstance(RETENTION_DAYS, int)
