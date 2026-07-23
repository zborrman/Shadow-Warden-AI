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
    def test_explicit_x_tenant_id_header_wins(self):
        assert qm._get_tenant_id_from_scope(_scope({"X-Tenant-ID": "acme"})) == "acme"

    def test_populated_state_wins_over_everything(self):
        s = _scope({"X-Tenant-ID": "hdr"}, state={"tenant_id": "from-state"})
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

    def test_resolver_failure_is_swallowed_to_anonymous(self, monkeypatch):
        def boom(key):
            raise RuntimeError("keystore down")

        monkeypatch.setattr(
            "warden.auth_guard.resolve_tenant_id", boom, raising=True
        )
        # Must not propagate — quota accounting is best-effort, never a 500.
        assert qm._get_tenant_id_from_scope(_scope({"X-API-Key": "x"})) == "anonymous"
