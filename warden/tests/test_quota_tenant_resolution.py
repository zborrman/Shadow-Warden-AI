"""
QuotaMiddleware tenant resolution.

The middleware runs at the ASGI layer, before the route's require_api_key
dependency, and nothing populates request.state.tenant. A bare fallback to
"anonymous" therefore collapsed every authenticated caller (X-API-Key, no
X-Tenant-ID) into one shared bucket — which hard-blocked the whole /filter
endpoint once the shared starter cap was hit. These tests pin that the
middleware resolves the API key to a real tenant.
"""
from __future__ import annotations

from warden.billing import quota_middleware as qm


def _scope(headers: dict[str, str], *, state=None) -> dict:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    s = {"type": "http", "method": "POST", "path": "/filter", "headers": raw}
    if state is not None:
        s["state"] = state
    return s


class TestTenantResolution:
    def test_client_supplied_x_tenant_id_cannot_select_the_bucket(self):
        """A spoofable header must not choose whose quota is charged."""
        got = qm._get_tenant_id_from_scope(_scope({"X-Tenant-ID": "victim-tenant"}))
        assert got == "anonymous"
        assert got != "victim-tenant"

    def test_x_tenant_id_cannot_override_a_resolved_key(self, monkeypatch):
        monkeypatch.setattr(
            "warden.auth_guard.resolve_tenant_id",
            lambda key: "real-tenant",
            raising=True,
        )
        s = _scope({"X-API-Key": "k", "X-Tenant-ID": "enterprise-unlimited"})
        assert qm._get_tenant_id_from_scope(s) == "real-tenant"

    def test_populated_state_wins(self):
        s = _scope({"X-API-Key": "k"}, state={"tenant_id": "from-state"})
        assert qm._get_tenant_id_from_scope(s) == "from-state"

    def test_api_key_resolves_to_tenant(self, monkeypatch):
        monkeypatch.setattr(qm, "log", qm.log)

        def fake_resolve(key):
            return "tenant-for-key" if key == "sekret" else None

        monkeypatch.setattr(
            "warden.auth_guard.resolve_tenant_id", fake_resolve, raising=True
        )
        got = qm._get_tenant_id_from_scope(_scope({"X-API-Key": "sekret"}))
        assert got == "tenant-for-key"

    def test_api_key_is_not_lumped_into_anonymous(self, monkeypatch):
        """The regression: an authenticated caller must not become 'anonymous'."""
        monkeypatch.setattr(
            "warden.auth_guard.resolve_tenant_id",
            lambda key: "default",
            raising=True,
        )
        got = qm._get_tenant_id_from_scope(_scope({"X-API-Key": "any"}))
        assert got == "default"
        assert got != "anonymous"

    def test_no_key_no_header_falls_back_to_anonymous(self):
        assert qm._get_tenant_id_from_scope(_scope({})) == "anonymous"


class TestRealResolverContract:
    """Exercise the actual auth_guard.resolve_tenant_id, not a mock, so a change
    to its return contract would break this."""

    def test_single_key_deployment_resolves_to_default(self, monkeypatch):
        import warden.auth_guard as ag

        monkeypatch.setattr(ag, "_VALID_KEY", "s3cret-key", raising=False)
        monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

        # The real resolver maps the configured single key → "default".
        assert ag.resolve_tenant_id("s3cret-key") == "default"
        # A spoofed X-Tenant-ID alongside the key must not divert the bucket —
        # exercised through the real resolver path, not a mock.
        scope = _scope({"X-API-Key": "s3cret-key", "X-Tenant-ID": "unlimited-tenant"})
        assert qm._get_tenant_id_from_scope(scope) == "default"

    def test_wrong_key_is_anonymous(self, monkeypatch):
        import warden.auth_guard as ag

        monkeypatch.setattr(ag, "_VALID_KEY", "s3cret-key", raising=False)
        monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

        assert qm._get_tenant_id_from_scope(_scope({"X-API-Key": "wrong"})) == "anonymous"

    def test_resolver_failure_is_swallowed_to_anonymous(self, monkeypatch):
        def boom(key):
            raise RuntimeError("keystore down")

        monkeypatch.setattr(
            "warden.auth_guard.resolve_tenant_id", boom, raising=True
        )
        # Must not propagate — quota accounting is best-effort, never a 500.
        assert qm._get_tenant_id_from_scope(_scope({"X-API-Key": "x"})) == "anonymous"
