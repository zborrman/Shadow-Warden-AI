"""
warden/tests/test_settings.py
───────────────────────────────
Settings Hub test suite (18 tests).

Sections covered: agents, notifications, commerce, semantic, API router.
Uses ALLOW_UNAUTHENTICATED=true (set in conftest.py).
Redis is replaced by the in-memory limiter, so all Redis ops fall back gracefully.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from warden.main import app
    return TestClient(app)


TENANT = "test_settings_tenant"
HEADERS = {"X-Tenant-ID": TENANT}


# ── 1. Module import ──────────────────────────────────────────────────────────

def test_settings_models_import():
    from warden.settings.models import (
        AgentSettings,
        CommerceSettings,
        SemanticSettings,
    )
    assert AgentSettings().sova_enabled is True
    assert CommerceSettings().enabled is False
    assert SemanticSettings().ai_query_enabled is True


def test_settings_service_import():
    from warden.settings.service import SettingsService
    svc = SettingsService()
    assert svc is not None


# ── 2. Service layer (in-process) ─────────────────────────────────────────────

def test_service_get_all_defaults():
    from warden.settings.models import AllSettings
    from warden.settings.service import SettingsService
    svc = SettingsService()
    result = svc.get_all("t_default")
    assert isinstance(result, AllSettings)
    assert result.tenant_id == "t_default"
    assert result.agents.sova_enabled is True


def test_service_agents_defaults():
    from warden.settings.service import SettingsService
    svc = SettingsService()
    agents = svc.get_agents("t_agents")
    assert agents.sova_max_iterations == 10
    assert agents.master_max_sub_iter == 5


def test_service_update_agents():
    from warden.settings.models import AgentSettingsPatch
    from warden.settings.service import SettingsService
    svc = SettingsService()
    patch = AgentSettingsPatch(sova_max_iterations=15, auto_approve_low_risk=True)
    updated = svc.update_agents("t_agents_upd", patch)
    assert updated.sova_max_iterations == 15
    assert updated.auto_approve_low_risk is True
    assert updated.sova_enabled is True  # unchanged


def test_service_notifications_crud():
    from warden.settings.models import NotificationChannel, NotificationChannelPatch
    from warden.settings.service import SettingsService
    svc = SettingsService()
    tid = "t_notif"

    ch = svc.add_notification(tid, NotificationChannel(kind="slack", label="Ops", url="https://hooks.slack.com/test"))
    assert ch.id != ""
    assert ch.kind == "slack"

    channels = svc.list_notifications(tid)
    assert any(c.id == ch.id for c in channels)

    updated = svc.update_notification(tid, ch.id, NotificationChannelPatch(label="Ops-v2", on_healer=True))
    assert updated.label == "Ops-v2"
    assert updated.on_healer is True

    svc.delete_notification(tid, ch.id)
    channels_after = svc.list_notifications(tid)
    assert all(c.id != ch.id for c in channels_after)


def test_service_notification_not_found_raises():
    from warden.settings.models import NotificationChannelPatch
    from warden.settings.service import SettingsService
    svc = SettingsService()
    with pytest.raises(KeyError):
        svc.update_notification("t_404", "nonexistent-id", NotificationChannelPatch(label="x"))


def test_service_commerce_defaults():
    from warden.settings.service import SettingsService
    svc = SettingsService()
    commerce = svc.get_commerce("t_commerce")
    assert commerce.enabled is False
    assert commerce.per_transaction_limit_usd == 50.0


def test_service_update_commerce():
    from warden.settings.models import CommerceSettingsPatch
    from warden.settings.service import SettingsService
    svc = SettingsService()
    patch = CommerceSettingsPatch(
        enabled=True,
        monthly_budget_usd=500.0,
        approved_stores=["store-a.com", "store-b.com"],
    )
    updated = svc.update_commerce("t_commerce_upd", patch)
    assert updated.enabled is True
    assert updated.monthly_budget_usd == 500.0
    assert "store-a.com" in updated.approved_stores


def test_service_semantic_defaults():
    from warden.settings.service import SettingsService
    svc = SettingsService()
    sem = svc.get_semantic("t_sem")
    assert sem.osi_export_enabled is False
    assert sem.default_row_limit == 1000


def test_service_update_semantic():
    from warden.settings.models import SemanticSettingsPatch
    from warden.settings.service import SettingsService
    svc = SettingsService()
    updated = svc.update_semantic("t_sem_upd", SemanticSettingsPatch(osi_export_enabled=True, default_row_limit=5000))
    assert updated.osi_export_enabled is True
    assert updated.default_row_limit == 5000


# ── 3. API layer ──────────────────────────────────────────────────────────────

def test_api_get_all(client: TestClient):
    r = client.get("/settings", headers=HEADERS)
    assert r.status_code == 200
    data = r.json()
    # canonical GET /settings returns SettingsSummary
    assert "agents" in data
    assert "api_key_count" in data or "channel_count" in data or "tenant_id" in data


def test_api_get_agents(client: TestClient):
    r = client.get("/settings/agents", headers=HEADERS)
    assert r.status_code == 200
    assert "sova_enabled" in r.json()


def test_api_patch_agents(client: TestClient):
    r = client.patch("/settings/agents", json={"sova_max_iterations": 7}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["sova_max_iterations"] == 7


def test_api_notifications_lifecycle(client: TestClient):
    # Add — canonical path is /settings/notifications/channels
    r = client.post(
        "/settings/notifications/channels",
        json={"type": "webhook", "label": "Test Webhook", "config": {"url": "https://example.com/hook"}},
        headers=HEADERS,
    )
    assert r.status_code == 201
    ch_id = r.json()["id"]
    assert ch_id

    # List
    r2 = client.get("/settings/notifications", headers=HEADERS)
    assert r2.status_code == 200

    # Delete
    r4 = client.delete(f"/settings/notifications/channels/{ch_id}", headers=HEADERS)
    assert r4.status_code == 204


def test_api_get_commerce(client: TestClient):
    r = client.get("/settings/commerce", headers=HEADERS)
    assert r.status_code == 200
    assert "enabled" in r.json()


def test_api_patch_commerce(client: TestClient):
    r = client.patch(
        "/settings/commerce",
        json={"enabled": True, "monthly_budget_usd": 100.0, "approved_stores": ["shop.example.com"]},
        headers=HEADERS,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["enabled"] is True
    assert "shop.example.com" in data["approved_stores"]


def test_api_get_semantic(client: TestClient):
    r = client.get("/settings/semantic", headers=HEADERS)
    assert r.status_code == 200
    assert "ai_query_enabled" in r.json()


def test_api_patch_semantic(client: TestClient):
    r = client.patch("/settings/semantic", json={"osi_export_enabled": True}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["osi_export_enabled"] is True


# ── 4. Module-level shim functions ───────────────────────────────────────────

def test_shim_get_settings_summary():
    from warden.settings import service as svc
    result = svc.get_settings_summary("t_shim_summary")
    assert result["tenant_id"] == "t_shim_summary"
    assert "api_key_count" in result
    assert "agents" in result


def test_shim_api_key_lifecycle():
    from warden.settings import service as svc
    tid = "t_shim_keys"

    # create
    created = svc.create_api_key(tid, "CI test key")
    assert created["id"]
    assert created["key"].startswith("sw_")
    assert created["label"] == "CI test key"
    assert created["active"] is True

    # list
    keys = svc.get_api_keys(tid)
    assert any(k["id"] == created["id"] for k in keys)

    # revoke
    ok = svc.revoke_api_key(tid, created["id"])
    assert ok is True

    # revoke non-existent
    assert svc.revoke_api_key(tid, "nonexistent") is False


def test_shim_secret_lifecycle():
    from warden.settings import service as svc
    tid = "t_shim_secrets"

    created = svc.create_secret(tid, "db_pass", "hunter2", "DB password")
    assert created["name"] == "db_pass"
    assert "value" not in created  # plaintext never returned

    secrets = svc.get_secrets(tid)
    assert any(s["name"] == "db_pass" for s in secrets)

    updated = svc.update_secret(tid, created["id"], "newpassword123", "Updated")
    assert updated is not None
    assert updated["description"] == "Updated"

    deleted = svc.delete_secret(tid, created["id"])
    assert deleted is True

    not_found = svc.delete_secret(tid, "nonexistent-id")
    assert not_found is False


def test_shim_agent_config():
    from warden.settings import service as svc
    tid = "t_shim_agents"

    cfg = svc.get_agent_config(tid)
    assert "sova_enabled" in cfg

    updated = svc.update_agent_config(tid, {"sova_max_iterations": 12})
    assert updated["sova_max_iterations"] == 12


def test_shim_notification_channels():
    from warden.settings import service as svc
    tid = "t_shim_notif"

    channels = svc.get_notification_channels(tid)
    assert isinstance(channels, list)

    ch = svc.add_notification_channel(tid, "slack", "Ops Alert", {"url": "https://hooks.slack.com/test"})
    assert ch["label"] == "Ops Alert"
    assert ch["id"]

    result = svc.test_notification_channel(tid, ch["id"])
    assert "ok" in result

    missing = svc.test_notification_channel(tid, "no-such-id")
    assert missing["ok"] is False

    ok = svc.delete_notification_channel(tid, ch["id"])
    assert ok is True


# ── 5. SemanticEngine registry coverage ──────────────────────────────────────

def test_semantic_engine_register_and_list():
    from warden.semantic_layer.engine import SemanticEngine
    from warden.semantic_layer.models import Metric, SemanticModel
    eng = SemanticEngine()
    m = SemanticModel(
        id="cov-test-1", name="Coverage Model", source_table="cov_table",
        metrics=[Metric(name="cnt", expression="COUNT(*)")],
    )
    eng.register_model(m)
    models = eng.list_models()
    assert any(x.id == "cov-test-1" for x in models)

    retrieved = eng.get_model("cov-test-1")
    assert retrieved.name == "Coverage Model"


def test_semantic_engine_access_rule_blocks():
    from warden.semantic_layer.engine import SemanticEngine
    from warden.semantic_layer.models import AccessRule, Metric, QueryObject, SemanticModel
    eng = SemanticEngine()
    m = SemanticModel(
        id="cov-access", name="Restricted", source_table="restricted_tbl",
        metrics=[
            Metric(name="secret_metric", expression="SUM(revenue)"),
            Metric(name="public_metric", expression="COUNT(*)"),
        ],
        access_rules=[
            # Global rule: only public_metric allowed
            AccessRule(tenant_id=None, allowed_metrics=["public_metric"]),
            # Specific tenant override: also allowed secret_metric
            AccessRule(tenant_id="allowed_tenant", allowed_metrics=["secret_metric", "public_metric"]),
        ],
    )
    eng.register_model(m)

    # Allowed tenant can access secret_metric via tenant-specific rule
    q_allowed = QueryObject(model_id="cov-access", metrics=["secret_metric"])
    result = eng.generate(q_allowed, tenant_id="allowed_tenant")
    assert "SUM(revenue)" in result.sql

    # Other tenant — global rule blocks secret_metric
    q_blocked = QueryObject(model_id="cov-access", metrics=["secret_metric"])
    with pytest.raises(PermissionError):
        eng.generate(q_blocked, tenant_id="other_tenant")


def test_semantic_engine_unknown_model_raises():
    from warden.semantic_layer.engine import SemanticEngine
    eng = SemanticEngine()
    with pytest.raises(KeyError):
        eng.get_model("does-not-exist")
