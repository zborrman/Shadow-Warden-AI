"""
warden/tests/test_onboarding_tenant_ownership.py — H-5 follow-up.

Every onboarding route used to need only a valid API key while acting on the
tenant named in the path. Tenant A's key could ``POST /onboard/B/rotate-key`` and
be handed B's new key — account takeover — and could list, create or suspend
every tenant. Found by the H-5 scanner (``warden/hooks/tenant_isolation.py``).

These tests watch the gate refuse, not just that a dependency is wired: a
dependency that is present and permits everyone is the defect this replaced.
The app is a bare FastAPI with only this router, ``require_api_key`` overridden
to resolve a fixed tenant (auth itself is tested elsewhere), and a fake
OnboardingEngine behind ``_require_onboarding`` — so a refused request is a 403 from the
gate, and an allowed one reaches the engine.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.api import onboarding as onboarding_api
from warden.auth_guard import AuthResult, require_api_key

_ADMIN = "op-admin-key-for-tests"


class _FakeOnboarding:
    def __init__(self) -> None:
        self.rotated: list[str] = []

    def get_tenant(self, tenant_id: str) -> dict:
        return {"tenant_id": tenant_id}

    def list_tenants(self) -> list[dict]:
        return [{"tenant_id": "tenant-a"}, {"tenant_id": "tenant-b"}]

    def rotate_key(self, tenant_id: str) -> str:
        self.rotated.append(tenant_id)
        return f"sk-new-{tenant_id}"

    def deactivate_tenant(self, tenant_id: str) -> bool:
        return True

    def reactivate_tenant(self, tenant_id: str) -> bool:
        return True


@pytest.fixture
def engine(monkeypatch):
    fake = _FakeOnboarding()
    monkeypatch.setattr(onboarding_api, "_require_onboarding", lambda: fake)
    monkeypatch.setenv("ADMIN_KEY", _ADMIN)
    return fake


@pytest.fixture
def client(engine):
    app = FastAPI()
    app.include_router(onboarding_api.router)
    app.dependency_overrides[require_api_key] = lambda: AuthResult(
        api_key="k", tenant_id="tenant-a"
    )
    return TestClient(app)


class TestAnotherTenantsKeyIsRefused:
    def test_rotating_another_tenants_key_is_403_and_rotates_nothing(self, client, engine):
        resp = client.post("/onboard/tenant-b/rotate-key")
        assert resp.status_code == 403
        assert "sk-new-tenant-b" not in resp.text
        assert engine.rotated == [], "the gate ran after the side effect"

    @pytest.mark.parametrize("method,path,body", [
        ("get", "/onboard/tenant-b", None),
        ("put", "/onboard/tenant-b/telegram", {"chat_id": "123"}),
        ("post", "/onboard/tenant-b/verify-telegram", {"chat_id": "123"}),
        ("get", "/msp/report/tenant-b", None),
    ])
    def test_reading_or_repointing_another_tenant_is_403(self, client, method, path, body):
        kwargs = {"json": body} if body is not None else {}
        assert getattr(client, method)(path, **kwargs).status_code == 403


class TestOwnTenantStillWorks:
    def test_a_tenant_can_rotate_its_own_key(self, client, engine):
        """A gate that also refuses the owner passes every denial test while
        protecting nothing usable."""
        resp = client.post("/onboard/tenant-a/rotate-key")
        assert resp.status_code == 200, resp.text
        assert resp.json()["api_key"] == "sk-new-tenant-a"
        assert engine.rotated == ["tenant-a"]

    def test_a_tenant_can_read_its_own_record(self, client):
        assert client.get("/onboard/tenant-a").status_code == 200


class TestFleetOperationsAreOperatorOnly:
    @pytest.mark.parametrize("method,path,kwargs", [
        ("get", "/tenants", {}),
        ("get", "/msp/overview", {}),
        ("put", "/onboard/tenant-a/status?active=true", {}),
        ("post", "/onboard", {"json": {"company_name": "Acme", "contact_email": "a@acme.io"}}),
    ])
    def test_a_tenant_key_alone_is_403(self, client, method, path, kwargs):
        assert getattr(client, method)(path, **kwargs).status_code == 403

    def test_a_suspended_tenant_cannot_reactivate_itself(self, client):
        """Its own tenant id in the path is not enough for /status."""
        assert client.put("/onboard/tenant-a/status?active=true").status_code == 403

    def test_the_operator_key_lists_tenants(self, client):
        resp = client.get("/tenants", headers={"X-Admin-Key": _ADMIN})
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    def test_the_operator_key_may_rotate_any_tenant(self, client, engine):
        resp = client.post("/onboard/tenant-b/rotate-key", headers={"X-Admin-Key": _ADMIN})
        assert resp.status_code == 200
        assert engine.rotated == ["tenant-b"]

    def test_a_wrong_operator_key_is_403(self, client):
        assert client.get("/tenants", headers={"X-Admin-Key": "nope"}).status_code == 403

    def test_unset_admin_key_never_authorises(self, client, monkeypatch):
        """Fail-closed: an empty configured key must not match an empty header."""
        monkeypatch.setenv("ADMIN_KEY", "")
        assert client.get("/tenants", headers={"X-Admin-Key": ""}).status_code == 403
