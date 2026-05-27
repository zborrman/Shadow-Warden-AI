"""Tests for the Settings module — service layer + REST API."""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("LOGS_PATH", "/tmp/test_settings_logs.json")
os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/test_settings_rules.json")
os.environ.setdefault("MODEL_CACHE_DIR", "/tmp/warden-test-models")
os.environ.setdefault("SEMANTIC_THRESHOLD", "0.72")


def _tid() -> str:
    return f"test-{uuid.uuid4().hex[:8]}"


# ── Service layer ─────────────────────────────────────────────────────────────

class TestApiKeys:
    def test_create_returns_full_key_once(self):
        from warden.settings.service import create_api_key
        tid = _tid()
        result = create_api_key(tid, "prod-key")
        assert result["key"].startswith("sw_")
        assert len(result["key"]) > 20
        assert "key_hash" not in result  # hash must not be returned

    def test_list_keys_hides_key_value(self):
        from warden.settings.service import create_api_key, get_api_keys
        tid = _tid()
        create_api_key(tid, "my-key")
        keys = get_api_keys(tid)
        assert len(keys) == 1
        assert "key" not in keys[0]
        assert "key_hash" not in keys[0]
        assert keys[0]["label"] == "my-key"

    def test_prefix_stored(self):
        from warden.settings.service import create_api_key, get_api_keys
        tid = _tid()
        created = create_api_key(tid, "pfx-test")
        keys = get_api_keys(tid)
        assert keys[0]["prefix"] == created["key"][:10]

    def test_revoke_sets_active_false(self):
        from warden.settings.service import create_api_key, get_api_keys, revoke_api_key
        tid = _tid()
        created = create_api_key(tid, "to-revoke")
        assert revoke_api_key(tid, created["id"])
        keys = get_api_keys(tid)
        assert not keys[0]["active"]

    def test_revoke_unknown_returns_false(self):
        from warden.settings.service import revoke_api_key
        assert not revoke_api_key(_tid(), "does-not-exist")

    def test_multiple_keys(self):
        from warden.settings.service import create_api_key, get_api_keys
        tid = _tid()
        create_api_key(tid, "k1")
        create_api_key(tid, "k2")
        assert len(get_api_keys(tid)) == 2


class TestSecrets:
    def test_create_and_list(self):
        from warden.settings.service import create_secret, get_secrets
        tid = _tid()
        create_secret(tid, "MY_API_KEY", "supersecret")
        secs = get_secrets(tid)
        assert len(secs) == 1
        assert secs[0]["name"] == "MY_API_KEY"
        assert "encrypted_value" not in secs[0]

    def test_update_secret(self):
        from warden.settings.service import create_secret, get_secret_value, update_secret
        tid = _tid()
        sec = create_secret(tid, "DB_PASS", "old-value")
        result = update_secret(tid, sec["id"], "new-value")
        assert result is not None
        assert get_secret_value(tid, sec["id"]) == "new-value"

    def test_delete_secret(self):
        from warden.settings.service import create_secret, delete_secret, get_secrets
        tid = _tid()
        sec = create_secret(tid, "TEMP_KEY", "abc")
        assert delete_secret(tid, sec["id"])
        assert len(get_secrets(tid)) == 0

    def test_delete_unknown_returns_false(self):
        from warden.settings.service import delete_secret
        assert not delete_secret(_tid(), "nonexistent")

    def test_get_secret_value_returns_plaintext(self):
        from warden.settings.service import create_secret, get_secret_value
        tid = _tid()
        sec = create_secret(tid, "RAW_KEY", "plaintext-value")
        assert get_secret_value(tid, sec["id"]) == "plaintext-value"


class TestAgentConfig:
    def test_default_config(self):
        from warden.settings.service import get_agent_config
        cfg = get_agent_config(_tid())
        assert cfg["high_risk_threshold"] == 0.72
        assert cfg["sova_max_iterations"] == 10
        assert cfg["sova_enabled"] is True

    def test_update_config(self):
        from warden.settings.service import get_agent_config, update_agent_config
        tid = _tid()
        update_agent_config(tid, {"high_risk_threshold": 0.80, "sova_max_iterations": 5})
        cfg = get_agent_config(tid)
        assert cfg["high_risk_threshold"] == 0.80
        assert cfg["sova_max_iterations"] == 5

    def test_partial_update_preserves_other_keys(self):
        from warden.settings.service import get_agent_config, update_agent_config
        tid = _tid()
        update_agent_config(tid, {"master_agent_enabled": True})
        cfg = get_agent_config(tid)
        assert cfg["master_agent_enabled"] is True
        assert cfg["sova_enabled"] is True  # untouched


class TestNotificationChannels:
    def test_add_slack_channel(self):
        from warden.settings.service import add_notification_channel, get_notification_channels
        tid = _tid()
        add_notification_channel(tid, "slack", "Alerts", {"url": "https://hooks.slack.com/test"})
        channels = get_notification_channels(tid)
        assert len(channels) == 1
        assert channels[0]["type"] == "slack"
        assert "***" in channels[0]["config"]["url"]  # masked

    def test_delete_channel(self):
        from warden.settings.service import (
            add_notification_channel,
            delete_notification_channel,
            get_notification_channels,
        )
        tid = _tid()
        ch = add_notification_channel(tid, "webhook", "Ops", {"url": "https://example.com/hook"})
        assert delete_notification_channel(tid, ch["id"])
        assert len(get_notification_channels(tid)) == 0

    def test_test_channel_unknown_returns_false(self):
        from warden.settings.service import test_notification_channel
        result = test_notification_channel(_tid(), "nonexistent-id")
        assert not result["ok"]

    def test_test_channel_email_type_skips_live_send(self):
        from warden.settings.service import add_notification_channel, test_notification_channel
        tid = _tid()
        ch = add_notification_channel(tid, "email", "Email", {"email": "ops@example.com"})
        result = test_notification_channel(tid, ch["id"])
        assert result["ok"] is True   # email skipped in dev mode, returns ok


# ── REST API ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    from warden.main import app
    return TestClient(app, raise_server_exceptions=True)


class TestSettingsApi:
    def test_get_settings_summary(self, client):
        r = client.get("/settings")
        assert r.status_code == 200
        body = r.json()
        assert "api_key_count" in body
        assert "agent_config" in body

    def test_create_api_key_via_api(self, client):
        r = client.post("/settings/api-keys", json={"label": "ci-test-key"})
        assert r.status_code == 201
        body = r.json()
        assert body["key"].startswith("sw_")
        assert body["label"] == "ci-test-key"

    def test_list_api_keys_via_api(self, client):
        r = client.get("/settings/api-keys")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_revoke_api_key_via_api(self, client):
        create_r = client.post("/settings/api-keys", json={"label": "to-revoke"})
        key_id = create_r.json()["id"]
        r = client.delete(f"/settings/api-keys/{key_id}")
        assert r.status_code == 204

    def test_revoke_unknown_key_404(self, client):
        r = client.delete("/settings/api-keys/nonexistent-key-id")
        assert r.status_code == 404

    def test_create_secret_via_api(self, client):
        r = client.post("/settings/secrets", json={"name": "TEST_TOKEN", "value": "abc123"})
        assert r.status_code == 201
        body = r.json()
        assert body["name"] == "TEST_TOKEN"
        assert "value" not in body  # never returned

    def test_get_agent_config_via_api(self, client):
        r = client.get("/settings/agents")
        assert r.status_code == 200
        body = r.json()
        assert "high_risk_threshold" in body
        assert "sova_enabled" in body

    def test_update_agent_config_via_api(self, client):
        r = client.patch("/settings/agents", json={
            "high_risk_threshold": 0.75,
            "block_threshold": 0.92,
            "sova_max_iterations": 8,
            "sova_enabled": True,
            "master_agent_enabled": False,
            "evolution_engine_enabled": False,
            "scan_interval_minutes": 5,
            "causal_arbiter_enabled": True,
            "phish_guard_enabled": True,
        })
        assert r.status_code == 200
        assert r.json()["high_risk_threshold"] == 0.75

    def test_list_notifications_via_api(self, client):
        r = client.get("/settings/notifications")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_add_notification_channel_via_api(self, client):
        r = client.post("/settings/notifications/channels", json={
            "type": "slack",
            "label": "test-slack",
            "config": {"url": "https://hooks.slack.com/services/T00/B00/test"},
        })
        assert r.status_code == 201
        body = r.json()
        assert body["type"] == "slack"
        assert "***" in body["config"]["url"]

    def test_delete_channel_via_api(self, client):
        create_r = client.post("/settings/notifications/channels", json={
            "type": "webhook",
            "label": "del-test",
            "config": {"url": "https://example.com/hook"},
        })
        channel_id = create_r.json()["id"]
        r = client.delete(f"/settings/notifications/channels/{channel_id}")
        assert r.status_code == 204

    def test_delete_unknown_channel_404(self, client):
        r = client.delete("/settings/notifications/channels/nonexistent")
        assert r.status_code == 404

    def test_patch_unknown_section_400(self, client):
        r = client.patch("/settings/unknown-section", json={"key": "val"})
        assert r.status_code == 400
