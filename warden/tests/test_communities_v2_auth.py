"""
`/communities/*` (Community Hub, warden/api/communities_v2.py) must require auth.

`communities_v2.py` declared ZERO dependencies across its 34 routes. Six are
shadowed by `warden/communities/router.py` (mounted first, and properly gated);
the other 28 were live and anonymously reachable in production — confirmed
2026-07-29 against api.shadow-warden-ai.com, where seven read endpoints returned
200 with no credentials, including community analytics, compliance posture, data
file listings and evolution bundles.

There is no global auth middleware to fall back on: `warden/main.py` registers
exactly two http middlewares (request id, security headers). A missing
dependency means no authentication at all.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def _authed_client(monkeypatch):
    """
    TestClient with auth genuinely on (conftest disables it globally).

    Patch auth_guard's module globals rather than reloading: modules bind
    `require_api_key` by value at import, so a reload leaves them holding the
    old function over the old globals. `_VALID_KEY` / `_KEYS_PATH` are read as
    module globals at call time, so setattr reaches the real code path.
    """
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", "hub-test-key", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app)


# Live, v2-served paths (not shadowed by warden/communities/router.py).
# Each returned 200 anonymously in production before this fix.
_V2_LIVE_READ_PATHS = [
    "/communities/networks/list",
    "/communities/member/some-tenant/memberships",
    "/communities/some-id/analytics",
    "/communities/some-id/compliance",
    "/communities/some-id/data",
    "/communities/some-id/peers",
    "/communities/some-id/evolution/bundles",
]


@pytest.mark.parametrize("path", _V2_LIVE_READ_PATHS)
def test_v2_read_routes_require_auth(_authed_client, path):
    assert _authed_client.get(path).status_code == 401, (
        f"{path} served without credentials. warden/api/communities_v2.py has no "
        f"global middleware behind it — the router-level Depends(require_api_key) "
        f"is the only thing gating it."
    )


_V2_LIVE_WRITE = [
    ("delete", "/communities/some-id"),
    ("patch", "/communities/some-id"),
    ("put", "/communities/some-id/settings"),
    ("post", "/communities/some-id/join"),
    ("put", "/communities/some-id/members/some-member"),
    ("delete", "/communities/some-id/data/some-file"),
]


@pytest.mark.parametrize("verb,path", _V2_LIVE_WRITE)
def test_v2_write_routes_require_auth(_authed_client, verb, path):
    """The write surface is the half that actually mutates state."""
    # httpx's .delete() takes no json= kwarg; only send a body where it applies.
    kwargs = {} if verb == "delete" else {"json": {}}
    resp = getattr(_authed_client, verb)(path, **kwargs)
    assert resp.status_code == 401, (
        f"{verb.upper()} {path} reachable without credentials — this endpoint "
        f"mutates community state."
    )


def test_valid_key_is_accepted(_authed_client):
    """The gate must not lock out legitimate callers."""
    resp = _authed_client.get(
        "/communities/networks/list", headers={"X-API-Key": "hub-test-key"}
    )
    assert resp.status_code != 401


def test_router_declares_the_auth_dependency():
    """
    Structural guard: a future edit that rebuilds the APIRouter must not drop
    the dependency. 34 routes rely on it; none carries its own.
    """
    from warden.api.communities_v2 import router

    assert router.dependencies, (
        "communities_v2 router lost its router-level dependencies. Every route "
        "in this module depends on it for authentication."
    )
