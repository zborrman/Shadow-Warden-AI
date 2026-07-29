"""
Anonymous-route audit ratchet (docs/anonymous-route-audit-2026-07-29.md).

Group A — tenant- and agent-scoped state that was reachable without credentials
in production — is now gated. Group B — marketplace reputation and protocol
schema — is deliberately left open: unauthenticated discovery is the premise of
the agentic marketplace, and gating it would break agent-to-agent lookup.

There is no global auth middleware in `warden/main.py` (only `attach_request_id`
and `security_headers`), so each router carries its own dependency and nothing
catches a regression except this file.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def _client(monkeypatch):
    """Auth genuinely enabled. Patch auth_guard's module globals rather than
    reloading — modules bind `require_api_key` by value at import."""
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", "audit-test-key", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app)


# Each returned 200 to an anonymous caller in production on 2026-07-29.
GROUP_A = [
    "/voice/sessions/probe-x",
    "/voice/x402/balance/probe-x",
    "/tokenomics/balance/probe-x",
    "/billing/usage-budgets/probe-x",
    "/whitelabel/probe-x",
    "/whitelabel/probe-x/css",
    "/whitelabel/probe-x/caddy-snippet",
    "/communities/probe-x/notifications/subscriptions",
]


@pytest.mark.parametrize("path", GROUP_A)
def test_group_a_requires_auth(_client, path):
    assert _client.get(path).status_code == 401, (
        f"{path} served without credentials. It returns tenant- or agent-scoped "
        f"state (balances, session history, budget or infrastructure config)."
    )


# Deliberately public: agents look each other up without credentials.
GROUP_B = [
    "/marketplace/agents/probe-x/trust",
    "/marketplace/readiness/probe-x",
    "/marketplace/protocol/schema/probe-x",
    "/kya/trust/probe-x",
]


@pytest.mark.parametrize("path", GROUP_B)
def test_group_b_stays_public(_client, path):
    """
    Guard the decision in both directions: someone gating these by reflex would
    break agent discovery. If that becomes intended, change it here first.
    """
    assert _client.get(path).status_code != 401, (
        f"{path} now requires auth. Marketplace reputation and protocol schema "
        f"are public by design — see docs/anonymous-route-audit-2026-07-29.md."
    )


_GATED_MODULES = [
    "warden.voice.api",
    "warden.tokenomics.api",
    "warden.api.usage_budgets",
    "warden.api.whitelabel",
    "warden.api.community_notifications",
    "warden.api.communities_v2",
    "warden.api.webhooks",
]


@pytest.mark.parametrize("mod_name", _GATED_MODULES)
def test_gated_routers_keep_their_dependency(mod_name):
    """
    Structural guard. These modules have no per-route auth — every route relies
    on the router-level dependency, so dropping it silently reopens the module.
    """
    import importlib

    router = importlib.import_module(mod_name).router
    assert router.dependencies, (
        f"{mod_name}.router lost its router-level dependencies; every route in "
        f"that module depends on it for authentication."
    )
