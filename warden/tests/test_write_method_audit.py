"""
Write-method audit ratchet (2026-07-29).

376 POST/PUT/PATCH/DELETE routes were probed locally with auth enabled and empty
bodies. Sixteen executed fully for an anonymous caller. The ones below mutate
gateway configuration or delete tenant data and are now gated.

The standout: `POST /api/config` writes SEMANTIC_THRESHOLD, STRICT_MODE, the
default rate limit and the uncertainty band into the *running* gateway. It
returned `{"ok":true}` to an unauthenticated request against production. Raising
`semantic_threshold` toward 1.0 stops the ML jailbreak detector flagging, so this
was a remote kill switch on the product's own protection.

Note on method: a `422` in that sweep means "no dependency-level auth", NOT
"unauthenticated" — a handler that checks auth imperatively in its body would
also 422 on an empty payload, before reaching the check. Only 200/204 is proof
the handler ran. These tests therefore pin the routes that demonstrably ran.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def _client(monkeypatch):
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", "write-audit-key", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app, raise_server_exceptions=False)


# (verb, path) that returned 200/204 anonymously and mutate config or data.
GATED = [
    ("get", "/api/config"),
    ("post", "/api/config"),
    ("post", "/retention/enforce"),
    ("put", "/retention/policy"),
    ("post", "/admin/rotation/rotate-alert"),
    ("post", "/admin/data-lifecycle/purge"),
]


@pytest.mark.parametrize("verb,path", GATED)
def test_admin_and_destructive_writes_require_auth(_client, verb, path):
    kwargs = {} if verb in ("get", "delete") else {"json": {}}
    assert getattr(_client, verb)(path, **kwargs).status_code == 401, (
        f"{verb.upper()} {path} executed without credentials."
    )


def test_config_update_cannot_be_tuned_anonymously(_client):
    """
    The specific attack: lift semantic_threshold so the ML jailbreak detector
    stops flagging. Must not be reachable without a key.
    """
    resp = _client.post("/api/config", json={"semantic_threshold": 0.99})
    assert resp.status_code == 401, (
        "detection tuning is reachable anonymously — this disables the filter"
    )


def test_valid_key_still_works(_client):
    resp = _client.post(
        "/api/config", json={}, headers={"X-API-Key": "write-audit-key"}
    )
    assert resp.status_code != 401, "the gate must not lock out legitimate operators"


def test_rate_limit_is_not_mistaken_for_auth():
    """
    warden/marketplace/data_lifecycle.py mounted /admin/* behind
    `dependencies=[Depends(marketplace_rate_limit)]` only. A limiter throttles an
    anonymous caller; it does not authenticate them.
    """
    from warden.marketplace.data_lifecycle import router

    names = [getattr(getattr(d, "dependency", None), "__name__", "") for d in router.dependencies]
    assert "require_api_key" in names, (
        "data_lifecycle lost its auth dependency; a rate limit alone is not "
        "authentication and this router purges data."
    )
