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
    assert "agents" in data
    assert "notifications" in data
    assert "commerce" in data
    assert "semantic" in data


def test_api_get_agents(client: TestClient):
    r = client.get("/settings/agents", headers=HEADERS)
    assert r.status_code == 200
    assert "sova_enabled" in r.json()


def test_api_patch_agents(client: TestClient):
    r = client.patch("/settings/agents", json={"sova_max_iterations": 7}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["sova_max_iterations"] == 7


def test_api_notifications_lifecycle(client: TestClient):
    # Add
    r = client.post(
        "/settings/notifications",
        json={"kind": "webhook", "label": "Test Webhook", "url": "https://example.com/hook"},
        headers=HEADERS,
    )
    assert r.status_code == 201
    ch_id = r.json()["id"]
    assert ch_id

    # List
    r2 = client.get("/settings/notifications", headers=HEADERS)
    assert any(c["id"] == ch_id for c in r2.json())

    # Patch
    r3 = client.patch(f"/settings/notifications/{ch_id}", json={"label": "Updated"}, headers=HEADERS)
    assert r3.status_code == 200
    assert r3.json()["label"] == "Updated"

    # Delete
    r4 = client.delete(f"/settings/notifications/{ch_id}", headers=HEADERS)
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
