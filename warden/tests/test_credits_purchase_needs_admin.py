"""
warden/tests/test_credits_purchase_needs_admin.py

`POST /marketplace/credits/purchase` grants spendable credits. It takes no
payment and verifies none, and no provider webhook calls it. Until audit S-3
any holder of an ordinary API key could grant itself credits for free.

These tests run with authentication ON and an admin key configured, which is
the production posture. The rest of the suite runs unauthenticated, where the
admin guard deliberately lets every caller through.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.marketplace import credits

_API_KEY = "tenant-" + "k" * 24
_ADMIN_KEY = "admin-" + "a" * 24
_URL = "/marketplace/credits/purchase"
_BODY = {"package_id": "credits_100"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from warden import auth_guard
    from warden.marketplace.api import router

    monkeypatch.setattr(credits, "_DB_PATH", str(tmp_path / "credits.db"))
    monkeypatch.setattr(auth_guard, "_VALID_KEY", _API_KEY)
    monkeypatch.setattr(auth_guard, "_KEYS_PATH", "")
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
    monkeypatch.setenv("ADMIN_KEY", _ADMIN_KEY)

    app = FastAPI()
    app.include_router(router, prefix="/marketplace")
    return TestClient(app, raise_server_exceptions=False)


def _headers(**extra: str) -> dict[str, str]:
    return {"X-API-Key": _API_KEY, "Idempotency-Key": "evt-1", **extra}


def test_an_api_key_alone_grants_nothing(client):
    r = client.post(_URL, json=_BODY, headers=_headers())
    assert r.status_code == 403
    assert credits.get_balance("default") == 0


def test_a_wrong_admin_key_grants_nothing(client):
    r = client.post(_URL, json=_BODY, headers=_headers(**{"X-Admin-Key": "nope"}))
    assert r.status_code == 403
    assert credits.get_balance("default") == 0


def test_no_admin_key_configured_disables_the_grant(client, monkeypatch):
    """An unset key must deny, never open the endpoint."""
    monkeypatch.delenv("ADMIN_KEY")
    r = client.post(_URL, json=_BODY, headers=_headers(**{"X-Admin-Key": _ADMIN_KEY}))
    assert r.status_code == 503
    assert credits.get_balance("default") == 0


def test_the_admin_key_does_not_replace_the_api_key(client):
    r = client.post(
        _URL, json=_BODY, headers={"Idempotency-Key": "evt-1", "X-Admin-Key": _ADMIN_KEY}
    )
    assert r.status_code in (401, 403)


def test_the_operator_grants_to_the_tenant_it_names(client):
    r = client.post(
        _URL,
        json=_BODY,
        headers=_headers(**{"X-Admin-Key": _ADMIN_KEY, "X-Tenant-ID": "acme"}),
    )
    assert r.status_code == 200
    assert r.json()["balance"] == 100
    assert credits.get_balance("acme") == 100


def test_a_tenant_cannot_name_another_tenant_without_the_admin_key(client):
    r = client.post(_URL, json=_BODY, headers=_headers(**{"X-Tenant-ID": "acme"}))
    assert r.status_code == 403
    assert credits.get_balance("acme") == 0
