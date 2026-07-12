"""Tier resolution must not trust the client X-Tenant-Tier header in production.

Phase 1.1: `_get_tenant_tier` honours the spoofable `X-Tenant-Tier` header only
when auth is not enforced (dev/test). When a real API key is configured and
`ALLOW_UNAUTHENTICATED` is off, the tier is derived from the authenticated
tenant's billing plan instead, so a low-tier tenant cannot escalate by sending
`X-Tenant-Tier: enterprise`.
"""
from __future__ import annotations

import warden.auth_guard as ag
from warden.billing import feature_gate as fg


class _Headers:
    """Case-insensitive header stub matching starlette's Headers.get semantics."""

    def __init__(self, data: dict[str, str]) -> None:
        self._d = {k.lower(): v for k, v in data.items()}

    def get(self, key: str, default: str | None = None):
        return self._d.get(key.lower(), default)


class _State:
    pass


class _Request:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = _Headers(headers)
        self.state = _State()


def test_tier_header_trusted_in_dev_and_test(monkeypatch):
    # ALLOW_UNAUTHENTICATED=true → header is honoured (test/dev default).
    monkeypatch.setattr(ag.settings, "allow_unauthenticated", True, raising=False)
    assert ag.tier_header_trusted() is True

    # No key configured at all → dev/air-gapped mode → header honoured.
    monkeypatch.setattr(ag.settings, "allow_unauthenticated", False, raising=False)
    monkeypatch.setattr(ag, "_VALID_KEY", "", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)
    assert ag.tier_header_trusted() is True


def test_tier_header_not_trusted_in_prod(monkeypatch):
    # A real key configured and ALLOW_UNAUTHENTICATED off → header ignored.
    monkeypatch.setattr(ag.settings, "allow_unauthenticated", False, raising=False)
    monkeypatch.setattr(ag, "_VALID_KEY", "prod-secret", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)
    assert ag.tier_header_trusted() is False


def test_resolve_tenant_id_none_in_dev(monkeypatch):
    monkeypatch.setattr(ag, "_VALID_KEY", "", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)
    assert ag.resolve_tenant_id("anything") is None


def test_resolve_tenant_id_single_key(monkeypatch):
    monkeypatch.setattr(ag, "_VALID_KEY", "prod-secret", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)
    assert ag.resolve_tenant_id("prod-secret") == "default"
    assert ag.resolve_tenant_id("wrong-key") is None
    assert ag.resolve_tenant_id("") is None


def test_get_tenant_tier_honours_header_in_test_mode(monkeypatch):
    monkeypatch.setattr(ag.settings, "allow_unauthenticated", True, raising=False)
    req = _Request({"X-Tenant-Tier": "enterprise"})
    assert fg._get_tenant_tier(req) == "enterprise"


def test_get_tenant_tier_ignores_header_in_prod_uses_billing(monkeypatch):
    # Prod mode: key configured, ALLOW_UNAUTHENTICATED off.
    monkeypatch.setattr(ag.settings, "allow_unauthenticated", False, raising=False)
    monkeypatch.setattr(ag, "_VALID_KEY", "prod-secret", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

    class _FakeBilling:
        def get_plan(self, tenant_id: str) -> str:
            return "starter"  # the tenant's REAL plan

    monkeypatch.setattr(
        "warden.lemon_billing.get_lemon_billing", lambda: _FakeBilling(), raising=False
    )

    # Attacker sends enterprise header with a valid (starter-tier) key → ignored.
    req = _Request({"X-Tenant-Tier": "enterprise", "X-API-Key": "prod-secret"})
    assert fg._get_tenant_tier(req) == "starter"


def test_get_tenant_tier_state_wins(monkeypatch):
    # Upstream auth-populated request.state.tenant is authoritative.
    monkeypatch.setattr(ag.settings, "allow_unauthenticated", False, raising=False)
    monkeypatch.setattr(ag, "_VALID_KEY", "prod-secret", raising=False)
    req = _Request({"X-Tenant-Tier": "enterprise"})
    req.state.tenant = {"tier": "pro"}
    assert fg._get_tenant_tier(req) == "pro"
