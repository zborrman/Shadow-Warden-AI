"""
warden/tests/test_billing_usage_tenant_ownership.py — H-5 follow-up.

``GET /billing/{tenant_id}``, ``/daily`` and ``POST /billing/{tenant_id}/quota``
needed only a valid API key while acting on the tenant in the path. Any tenant's
key could read another tenant's usage and spend, and set or remove its monthly
cap: removing it is unlimited spend billed to the victim, and a tiny cap turns
every one of the victim's requests into a 402.

Same harness as ``test_onboarding_tenant_ownership.py``: a bare app with only this
router, ``require_api_key`` resolving a fixed tenant, a fake BillingStore — so a
refusal is the gate's 403 and an allowed call reaches the store.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.api import billing_usage as billing_api
from warden.auth_guard import AuthResult, require_api_key

_ADMIN = "op-admin-key-for-tests"


class _FakeConn:
    def __init__(self, owner: _FakeBilling) -> None:
        self._owner = owner

    def execute(self, sql: str, params: tuple) -> None:
        self._owner.removed.append(params[0])

    def commit(self) -> None:
        pass


class _FakeBilling:
    def __init__(self) -> None:
        self.quotas: dict[str, float] = {}
        self.removed: list[str] = []
        self._conn = _FakeConn(self)

    def get_usage(self, tenant_id, from_date=None, to_date=None) -> dict:
        return {"tenant_id": tenant_id, "cost_usd": 12.5}

    def get_daily_breakdown(self, tenant_id, from_date, to_date, limit) -> list:
        return [{"day": "2026-10-01", "cost_usd": 1.0}]

    def set_quota(self, tenant_id: str, quota: float) -> None:
        self.quotas[tenant_id] = quota


@pytest.fixture
def store(monkeypatch):
    fake = _FakeBilling()
    monkeypatch.setattr(billing_api, "_require_billing", lambda: fake)
    monkeypatch.setenv("ADMIN_KEY", _ADMIN)
    return fake


@pytest.fixture
def client(store):
    app = FastAPI()
    app.include_router(billing_api.router)
    app.dependency_overrides[require_api_key] = lambda: AuthResult(
        api_key="k", tenant_id="tenant-a"
    )
    return TestClient(app)


class TestAnotherTenantIsRefused:
    @pytest.mark.parametrize("path", ["/billing/tenant-b", "/billing/tenant-b/daily"])
    def test_reading_another_tenants_spend_is_403(self, client, path):
        resp = client.get(path)
        assert resp.status_code == 403
        assert "12.5" not in resp.text

    def test_capping_another_tenant_is_403_and_sets_nothing(self, client, store):
        resp = client.post("/billing/tenant-b/quota", json={"quota_usd": 0.0001})
        assert resp.status_code == 403
        assert store.quotas == {}, "the gate ran after the side effect"

    def test_uncapping_another_tenant_is_403_and_removes_nothing(self, client, store):
        resp = client.post("/billing/tenant-b/quota", json={"quota_usd": 0})
        assert resp.status_code == 403
        assert store.removed == []


class TestOwnTenantStillWorks:
    def test_a_tenant_reads_its_own_spend(self, client):
        resp = client.get("/billing/tenant-a")
        assert resp.status_code == 200
        assert resp.json()["cost_usd"] == 12.5

    def test_a_tenant_reads_its_own_daily_breakdown(self, client):
        assert client.get("/billing/tenant-a/daily").status_code == 200

    def test_a_tenant_caps_its_own_spend(self, client, store):
        resp = client.post("/billing/tenant-a/quota", json={"quota_usd": 50})
        assert resp.status_code == 200
        assert store.quotas == {"tenant-a": 50}


class TestTheOperator:
    def test_may_cap_any_tenant(self, client, store):
        resp = client.post(
            "/billing/tenant-b/quota", json={"quota_usd": 25},
            headers={"X-Admin-Key": _ADMIN},
        )
        assert resp.status_code == 200
        assert store.quotas == {"tenant-b": 25}

    def test_a_wrong_operator_key_is_still_403(self, client):
        assert client.get(
            "/billing/tenant-b", headers={"X-Admin-Key": "nope"}
        ).status_code == 403
