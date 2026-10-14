"""
warden/tests/test_billing_router_caller_tenant.py — H-5 follow-up.

Thirteen routes in ``warden/billing/router.py`` took the tenant from a bare
``X-Tenant-ID`` header and checked **no credential at all**. Probed against the
real app with ``WARDEN_API_KEY`` configured, an anonymous request carrying
``X-Tenant-ID: victim-tenant`` got 200 from ``/status``, ``/quota``, ``/margin``
(platform MRR and LLM cost), ``/addons/tenant``, ``/trial/status``,
``/referral/stats``, ``/overage/preview`` and ``/community-seats`` — and could
start a tenant's one-time trial on its behalf.

The tenant is now the one the API key resolves to. ``X-Tenant-ID`` is honoured
only alongside a valid ``X-Admin-Key``.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import warden.auth_guard as ag
from warden.auth_guard import AuthResult, require_api_key
from warden.billing import router as billing_router

_ADMIN = "billing-router-admin-key"

# Every route that used to read X-Tenant-ID. GET unless noted.
_TENANT_ROUTES = [
    ("get", "/billing/status"),
    ("get", "/billing/quota"),
    ("get", "/billing/margin"),
    ("get", "/billing/addons/tenant"),
    ("get", "/billing/trial/status"),
    ("get", "/billing/referral/stats"),
    ("get", "/billing/overage/preview"),
    ("get", "/billing/community-seats"),
    ("post", "/billing/referral/generate"),
]


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(billing_router.router)
    return app


class TestNoKeyNoAnswer:
    """With a key configured, the gate refuses a caller who presents none."""

    @pytest.fixture
    def client(self, monkeypatch):
        monkeypatch.setattr(ag, "_VALID_KEY", "the-real-key")
        monkeypatch.setattr(ag, "_KEYS_PATH", "")
        return TestClient(_app())

    @pytest.mark.parametrize("method,path", _TENANT_ROUTES)
    def test_anonymous_with_a_claimed_tenant_is_401(self, client, method, path):
        resp = getattr(client, method)(path, headers={"X-Tenant-ID": "victim-tenant"})
        assert resp.status_code == 401, resp.text
        assert "victim-tenant" not in resp.text

    def test_the_configured_key_is_accepted(self, client):
        """A gate that refuses its own credential protects nothing usable."""
        resp = client.get("/billing/status", headers={"X-API-Key": "the-real-key"})
        assert resp.status_code == 200
        assert resp.json()["tenant_id"] == "default"


class TestTheKeyDecidesTheTenant:
    @pytest.fixture
    def client(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", _ADMIN)
        app = _app()
        app.dependency_overrides[require_api_key] = lambda: AuthResult(
            api_key="k", tenant_id="tenant-a"
        )
        return TestClient(app)

    @pytest.mark.parametrize("path", ["/billing/status", "/billing/quota", "/billing/margin"])
    def test_a_claimed_tenant_is_ignored(self, client, path):
        resp = client.get(path, headers={"X-Tenant-ID": "tenant-b"})
        assert resp.status_code == 200
        assert resp.json()["tenant_id"] == "tenant-a"

    def test_a_wrong_admin_key_does_not_unlock_the_header(self, client):
        resp = client.get(
            "/billing/status", headers={"X-Tenant-ID": "tenant-b", "X-Admin-Key": "nope"}
        )
        assert resp.json()["tenant_id"] == "tenant-a"

    def test_the_operator_may_name_a_tenant(self, client):
        resp = client.get(
            "/billing/status", headers={"X-Tenant-ID": "tenant-b", "X-Admin-Key": _ADMIN}
        )
        assert resp.json()["tenant_id"] == "tenant-b"

    def test_an_unset_admin_key_never_unlocks_the_header(self, client, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "")
        resp = client.get(
            "/billing/status", headers={"X-Tenant-ID": "tenant-b", "X-Admin-Key": ""}
        )
        assert resp.json()["tenant_id"] == "tenant-a"
