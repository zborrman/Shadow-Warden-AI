"""
/ws/events authentication + route-shadowing guard.

Background
──────────
`/ws/events` was registered TWICE:

  * `warden/api/ws_events.py`  — mounted by main.py (~line 1363), NO auth
  * `warden/main.py`           — inline `@app.websocket("/ws/events")`, WITH auth

Starlette resolves in registration order, so the router won and main.py's
authenticated handler was dead code. Verified against production on 2026-07-28:
an anonymous client completed the WebSocket handshake against
`wss://api.shadow-warden-ai.com/ws/events`.

It carried no data only because the two halves were split: main.py's filter
pipeline broadcast to a main.py-local `_EventBus` whose sole consumer was the
shadowed handler, while the live endpoint read a queue nothing fed. The stream
was broken at BOTH ends and still reported "connected" — which is why nobody
noticed for either half.

These tests pin the fix: one handler, authenticated, and actually wired to the
pipeline's producer.
"""

from __future__ import annotations

import collections
import os

import pytest

# ── helpers ──────────────────────────────────────────────────────────────────


def _flatten(routes, prefix: str = ""):
    """
    Yield ``(effective_path, route)`` for every leaf route.

    Two things make this non-obvious, and getting either wrong produces a
    confidently wrong answer:

    1. FastAPI keeps an included router as a single `_IncludedRouter` entry
       rather than flattening into `app.routes`, so a naive scan of `app.routes`
       misses every routed endpoint.
    2. The routes hanging off `_IncludedRouter.original_router` carry their
       path **as declared**, WITHOUT the prefix passed to `include_router()`.
       Reading `.path` directly reports `warden.portal_router.login` as
       `/auth/login` when it is really served at `/portal/auth/login` — which
       manufactures phantom "duplicates" against the real `/auth/login`.
       The prefix lives on `_IncludedRouter.include_context.prefix`.
    """
    for r in routes:
        original = getattr(r, "original_router", None)
        if original is not None:
            ctx = getattr(r, "include_context", None)
            yield from _flatten(original.routes, prefix + (getattr(ctx, "prefix", "") or ""))
            continue
        sub = getattr(r, "routes", None)
        if sub:
            yield from _flatten(sub, prefix + (getattr(r, "path", "") or ""))
            continue
        yield prefix + (getattr(r, "path", "") or ""), r


def _handlers_for(app, path: str) -> list[str]:
    out = []
    for full, r in _flatten(app.routes):
        if full == path:
            ep = getattr(r, "endpoint", None)
            out.append(f"{getattr(ep, '__module__', '?')}.{getattr(ep, '__name__', '?')}")
    return out


# ── one handler, not two ─────────────────────────────────────────────────────


def test_ws_events_registered_exactly_once():
    import warden.main as m

    handlers = _handlers_for(m.app, "/ws/events")
    assert len(handlers) == 1, (
        f"/ws/events is registered {len(handlers)} times: {handlers}. "
        f"Starlette serves the FIRST; the rest are dead code. This is exactly "
        f"how the authenticated handler got silently replaced by an "
        f"unauthenticated one."
    )
    assert handlers[0] == "warden.api.ws_events.ws_events"


# ── authentication ───────────────────────────────────────────────────────────


@pytest.fixture
def _authed_client(monkeypatch):
    """
    TestClient with auth genuinely enabled (conftest disables it globally).

    Patch `auth_guard`'s module globals rather than reloading the module:
    `warden/api/ws_events.py` does `from warden.auth_guard import
    require_api_key`, binding the function object **by value** at import time,
    so a reload swaps the module but leaves ws_events holding the old function
    over the old globals — the tests then pass alone and fail in-file.
    `require_api_key` reads `_VALID_KEY` / `_KEYS_PATH` as module globals at CALL
    time, so setattr reaches the real code path with no mocking.
    """
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", "ws-test-key", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app)


def test_ws_events_rejects_anonymous(_authed_client):
    """An anonymous listener must not get the stream."""
    with _authed_client.websocket_connect("/ws/events") as ws:
        msg = ws.receive_json()
    assert msg["type"] == "error"
    assert msg["code"] == 401


def test_ws_events_rejects_wrong_key(_authed_client):
    with _authed_client.websocket_connect("/ws/events?key=not-the-key") as ws:
        msg = ws.receive_json()
    assert msg["type"] == "error"
    assert msg["code"] in (401, 403)


def test_ws_events_accepts_valid_key(_authed_client):
    from warden.api.ws_events import subscriber_count

    with _authed_client.websocket_connect("/ws/events?key=ws-test-key"):
        assert subscriber_count() >= 1


# ── the producer is actually wired ───────────────────────────────────────────


def test_main_feeds_the_router_not_a_local_bus():
    """
    The filter pipeline must broadcast into the module that owns the live
    endpoint. Feeding a main.py-local bus is what broke this before.
    """
    import inspect

    import warden.main as m

    src = inspect.getsource(m)
    assert "_ws_broadcast_event(" in src, (
        "main.py no longer calls warden.api.ws_events.broadcast_event — the "
        "/ws/events stream would have no producer."
    )
    assert "_event_bus" not in src, (
        "main.py reintroduced a local _EventBus. Its only possible consumer is "
        "an inline /ws/events handler, which the mounted router shadows."
    )


@pytest.mark.asyncio
async def test_broadcast_reaches_a_subscriber():
    from warden.api.ws_events import _register, _unregister, broadcast_event

    q = _register()
    try:
        await broadcast_event({"type": "event", "verdict": "HIGH", "score": 0.9})
        assert q.get_nowait()["verdict"] == "HIGH"
    finally:
        _unregister(q)


def test_health_reports_live_subscriber_count():
    """`ws_clients` must count the real listeners, not a dead bus that is
    structurally always zero."""
    import inspect

    import warden.main as m

    src = inspect.getsource(m)
    assert '"ws_clients":       _ws_subscriber_count()' in src or \
           "_ws_subscriber_count()" in src, "GET /health must report the router's count"


# ── app-wide shadowing ratchet ───────────────────────────────────────────────
#
# SEVEN shadowed (verb, path) pairs exist today:
#
#   GET  /.well-known/agent.json                      live marketplace.api.agent_discovery_alias
#                                                     DEAD protocols.a2a.api.agent_card
#   GET/POST/DELETE /communities[/...]  (6 routes)    live communities.router.*
#                                                     DEAD api.communities_v2.*
#
# i.e. the whole communities_v2 API is unreachable, plus one A2A agent-card
# handler. Pre-existing and out of scope for the /ws/events fix, but the count
# must not grow: every one is a handler someone believes is running.
#
# NOTE: the first version of this ratchet reported TWELVE, and named
# `POST /auth/login` (warden.auth.router vs warden.portal_router) as the
# headline case. That was wrong. `_flatten` was reading `.path` off the
# included router's own routes, which omits the `include_router(prefix=...)`
# value — so `/portal/auth/login`, `/portal/auth/logout` and three `/stats`
# variants were compared as if they were mounted at the root. Applying the
# prefix (see `_flatten`) removes all five phantoms. Any future change here
# must keep the prefix accumulation, or the baseline becomes meaningless.

_SHADOWED_BASELINE = 7


def _shadowed_pairs(app) -> dict[tuple[str, str], list[str]]:
    seen: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for full_path, r in _flatten(app.routes):
        if not full_path:
            continue
        for verb in sorted(getattr(r, "methods", None) or ["WEBSOCKET"]):
            if verb in ("HEAD", "OPTIONS"):
                continue
            ep = getattr(r, "endpoint", None)
            seen[(verb, full_path)].append(
                f"{getattr(ep, '__module__', '?')}.{getattr(ep, '__name__', '?')}"
            )
    return {k: v for k, v in seen.items() if len(v) > 1}


def test_prefixed_routes_are_not_reported_as_duplicates():
    """
    Regression guard for the bug this ratchet itself shipped with.

    `warden/portal_router.py` declares `@router.post("/auth/login")` on a
    prefix-less APIRouter and is included with `prefix="/portal"`. It must
    resolve to `/portal/auth/login` and must NOT collide with
    `warden/auth/router.py`'s real `/auth/login`.
    """
    import warden.main as m

    assert _handlers_for(m.app, "/portal/auth/login") == ["warden.portal_router.login"]
    assert _handlers_for(m.app, "/auth/login") == ["warden.auth.router.login"]


def test_no_new_shadowed_routes():
    import warden.main as m

    dups = _shadowed_pairs(m.app)
    detail = "\n".join(
        f"  {v} {p}\n" + "\n".join(
            f"      {'LIVE' if i == 0 else 'DEAD'}  {e}" for i, e in enumerate(eps)
        )
        for (v, p), eps in sorted(dups.items())
    )
    assert len(dups) <= _SHADOWED_BASELINE, (
        f"shadowed route count rose: {len(dups)} > baseline {_SHADOWED_BASELINE}.\n"
        f"A path registered twice means the second handler NEVER RUNS — and the "
        f"tests for it still pass, because they import it directly.\n{detail}"
    )


def test_ws_events_is_no_longer_shadowed():
    import warden.main as m

    dups = _shadowed_pairs(m.app)
    assert ("WEBSOCKET", "/ws/events") not in dups


@pytest.mark.skipif(
    os.getenv("CI") is None, reason="informational; only noisy in local runs"
)
def test_report_remaining_shadowed_routes():
    """Not a failure — surfaces the remaining duplicates in CI output."""
    import warden.main as m

    for (verb, path), eps in sorted(_shadowed_pairs(m.app).items()):
        print(f"SHADOWED {verb} {path}: live={eps[0]} dead={eps[1:]}")
