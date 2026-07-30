"""
Tenant identity on /communities/* must be anchored to the API key (2026-07-30).

`warden/communities/router.py::_get_tenant()` is the auth helper for 19 call
sites — membership, clearance changes, break-glass signing, key rotation. It read
`X-Tenant-ID` from the request unconditionally, so any caller could name any
tenant and act as them, and `X-Tenant-Tier` let them pick their own plan tier.

Two other modules had already reached the correct rule and documented it:

  billing/quota_middleware.py::_get_tenant_id_from_scope
      "IDENTITY IS TRUST-ANCHORED TO THE API KEY, never to a client-supplied
       X-Tenant-ID header."
  billing/feature_gate.py::_get_tenant_tier
      X-Tenant-Tier honoured only when `auth_guard.tier_header_trusted()`.

This module was the outlier. The header is now honoured only when auth is not
enforced at all (dev / air-gapped / test), which is what `tier_header_trusted()`
already expresses.

Note the deployment context that makes the *severity* modest today and the fix
worth having anyway: production runs single-key (`WARDEN_API_KEY`, no
`WARDEN_API_KEYS_PATH`, see docker-compose.yml), so every authenticated caller
resolves to tenant "default" — there is no second tenant to impersonate yet. The
moment a multi-key file or portal JWT is introduced, this helper is on the path
for every community operation.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def _prod(monkeypatch):
    """Auth enforced, single key — the production posture."""
    import warden.auth_guard as ag
    from warden.config import settings

    monkeypatch.setattr(ag, "_VALID_KEY", "prod-key", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)
    monkeypatch.setattr(settings, "allow_unauthenticated", False, raising=False)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app, raise_server_exceptions=False)


@pytest.fixture
def _dev(monkeypatch):
    """No auth configured — dev / air-gapped, where the header is the only signal."""
    import warden.auth_guard as ag
    from warden.config import settings

    monkeypatch.setattr(ag, "_VALID_KEY", "", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)
    monkeypatch.setattr(settings, "allow_unauthenticated", True, raising=False)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app, raise_server_exceptions=False)


KEY = {"X-API-Key": "prod-key"}


def test_tenant_header_cannot_choose_an_identity(_prod):
    """
    A valid key plus X-Tenant-ID: victim must NOT act as `victim`. The key
    resolves to "default", so the request is judged on that tenant's plan.
    """
    resp = _prod.get(
        "/communities/c1/members", headers={**KEY, "X-Tenant-ID": "victim-tenant"}
    )
    assert resp.status_code != 200, (
        "a caller-supplied X-Tenant-ID selected the acting tenant"
    )
    assert "victim-tenant" not in resp.text


def test_tier_header_cannot_escalate_plan(_prod):
    """
    X-Tenant-Tier: mcp must not buy the caller a higher plan. The tier comes
    from the authenticated tenant's billing record.
    """
    resp = _prod.get(
        "/communities/c1/members", headers={**KEY, "X-Tenant-Tier": "mcp"}
    )
    assert resp.status_code == 403
    assert "STARTER" in resp.text.upper(), (
        "tier was taken from the header rather than the billing plan"
    )


def test_unauthenticated_caller_is_rejected(_prod):
    """A header alone, with no key, is not an identity."""
    assert (
        _prod.get(
            "/communities/c1/members", headers={"X-Tenant-ID": "victim-tenant"}
        ).status_code
        == 401
    )


def test_dev_mode_still_accepts_the_header(_dev):
    """
    With no auth configured the header is the only available signal, and gating
    it would make local development impossible. 404 here means the request got
    past auth and reached the handler.
    """
    resp = _dev.get(
        "/communities/c1/members",
        headers={"X-Tenant-ID": "t1", "X-Tenant-Tier": "mcp"},
    )
    assert resp.status_code != 401


def test_helper_matches_the_rule_used_by_billing():
    """
    Structural guard. If someone reintroduces a bare header read here, this
    fails rather than silently reopening tenant impersonation across all 19
    call sites.
    """
    import inspect

    from warden.communities import router as cr

    src = inspect.getsource(cr._get_tenant)
    assert "resolve_tenant_id" in src, (
        "_get_tenant no longer anchors identity to the API key"
    )
    assert "tier_header_trusted" in src, (
        "_get_tenant no longer guards the header behind dev/test"
    )
