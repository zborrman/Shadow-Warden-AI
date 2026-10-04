"""
warden/tests/test_ws_monitor.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for the WebSocket `/ws/monitor/{monitor_id}` endpoint.

Why this file exists
────────────────────
`/ws/monitor` shipped with the uptime monitor and had **no test of any kind** —
it was the only one of the four sockets with none. P-2 moved it out of
`main.py`, and a move you cannot verify is a rewrite, so the behaviour is
pinned here first: the Redis-unavailable reply, the channel it subscribes to,
and that a published probe result reaches the client.

The forwarding tests drive the handler directly rather than through
`TestClient`. The send loop waits on its queue with a hardcoded 30-second
timeout, so a socket closed from the client side does not interrupt it — a
`TestClient` context exit would block for that full timeout. A fake socket
whose `send_text` raises `WebSocketDisconnect` ends the loop the same way a
real disconnect does, in milliseconds.
"""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi import WebSocketDisconnect

from warden.api import ws_stream

# ── fakes ─────────────────────────────────────────────────────────────────────

class _FakeWebSocket:
    """Records what the handler sent; disconnects after `disconnect_after` sends."""

    def __init__(self, disconnect_after: int = 1) -> None:
        self.accepted = False
        self.closed = False
        self.sent_text: list[str] = []
        self.sent_json: list[dict] = []
        self._disconnect_after = disconnect_after

    async def accept(self) -> None:
        self.accepted = True

    async def close(self, code: int = 1000) -> None:
        self.closed = True

    async def send_json(self, data: dict) -> None:
        self.sent_json.append(data)

    async def send_text(self, data: str) -> None:
        self.sent_text.append(data)
        if len(self.sent_text) >= self._disconnect_after:
            raise WebSocketDisconnect(code=1000)


class _FakePubSub:
    def __init__(self, messages: list[dict]) -> None:
        self._messages = messages
        self.subscribed: list[str] = []
        self.unsubscribed: list[str] = []

    def subscribe(self, channel: str) -> None:
        self.subscribed.append(channel)

    def unsubscribe(self, channel: str) -> None:
        self.unsubscribed.append(channel)

    def listen(self):
        yield from self._messages


class _FakeRedis:
    def __init__(self, messages: list[dict]) -> None:
        self.ps = _FakePubSub(messages)

    def pubsub(self) -> _FakePubSub:
        return self.ps


_RESULT = {
    "is_up": True, "latency_ms": 12.5, "status_code": 200,
    "error": None, "ts": "2026-10-04T00:00:00Z",
}


# ══════════════════════════════════════════════════════════════════════════════
# Redis unavailable
# ══════════════════════════════════════════════════════════════════════════════

class TestRedisUnavailable:
    async def test_it_says_so_and_closes(self, monkeypatch):
        """No Redis means no pubsub: say why and hang up, never leave it open."""
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: None)
        ws = _FakeWebSocket()

        await ws_stream.ws_monitor_stream(ws, "mon-1")

        assert ws.accepted
        assert ws.sent_json == [{"error": "Redis unavailable"}]
        assert ws.closed, "a socket with nothing to stream must be closed"
        assert ws.sent_text == []


# ══════════════════════════════════════════════════════════════════════════════
# Forwarding
# ══════════════════════════════════════════════════════════════════════════════

class TestForwarding:
    async def test_a_published_result_reaches_the_client(self, monkeypatch):
        payload = json.dumps(_RESULT)
        fake = _FakeRedis([{"type": "message", "data": payload}])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        ws = _FakeWebSocket()

        await ws_stream.ws_monitor_stream(ws, "mon-42")

        assert ws.sent_text == [payload]
        assert json.loads(ws.sent_text[0])["status_code"] == 200

    async def test_it_subscribes_to_that_monitor_only(self, monkeypatch):
        """The channel carries the id, so a typo here is a cross-monitor leak."""
        fake = _FakeRedis([{"type": "message", "data": json.dumps(_RESULT)}])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)

        await ws_stream.ws_monitor_stream(_FakeWebSocket(), "mon-7")

        assert fake.ps.subscribed == ["monitor:mon-7:result"]

    async def test_subscribe_control_frames_are_not_forwarded(self, monkeypatch):
        """pubsub emits its own `subscribe` confirmation — only `message` is data."""
        payload = json.dumps(_RESULT)
        fake = _FakeRedis([
            {"type": "subscribe", "data": 1},
            {"type": "message", "data": payload},
        ])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        ws = _FakeWebSocket()

        await ws_stream.ws_monitor_stream(ws, "mon-9")

        assert ws.sent_text == [payload], "a control frame was relayed as a probe result"

    async def test_a_listener_error_does_not_crash_the_handler(self, monkeypatch):
        """The reader thread runs sync Redis; its failure must not escape."""

        class _Boom(_FakePubSub):
            def listen(self):
                raise RuntimeError("pubsub died")

        fake = _FakeRedis([])
        fake.ps = _Boom([])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        # Nothing is ever queued, so the send loop waits on its 30s timeout.
        # Shorten the wait so the test measures the error handling, not the clock.
        real_wait_for = asyncio.wait_for
        monkeypatch.setattr(
            ws_stream.asyncio, "wait_for",
            lambda coro, timeout: real_wait_for(coro, 0.25),
        )
        ws = _FakeWebSocket()

        await ws_stream.ws_monitor_stream(ws, "mon-boom")   # must not raise

        assert ws.sent_text == []


# ══════════════════════════════════════════════════════════════════════════════
# Authentication — characterisation, not endorsement
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthentication:
    def test_it_takes_no_api_key_today(self):
        """
        `/ws/stream` and `/ws/filter` both call `require_api_key` on the `?key=`
        query param before doing any work. `/ws/monitor` calls nothing: anyone
        who holds a monitor id streams that monitor's probe results, with no
        key, no tenant check and no audit.

        This records the current shape rather than asserting it is correct, so
        the gap is visible in the suite instead of only in the source, and
        whoever closes it has to come here and say so deliberately. P-2 moved
        this handler unchanged; adding auth inside a 500-line move would have
        been an unreviewable behaviour change.
        """
        import inspect

        src = inspect.getsource(ws_stream.ws_monitor_stream)
        assert "require_api_key" not in src, (
            "/ws/monitor now authenticates — good. Replace this characterisation "
            "test with one that asserts an unauthenticated connect is refused."
        )
        # The sibling sockets, for contrast: they do gate.
        for guarded in (ws_stream.ws_stream, ws_stream.ws_filter_stream):
            assert "require_api_key" in inspect.getsource(guarded), (
                f"{guarded.__name__} lost its auth gate"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Route registration
# ══════════════════════════════════════════════════════════════════════════════

def test_the_route_is_registered_once():
    """Two handlers for one path is how /ws/events ran unauthenticated (PR #237)."""
    from warden.main import app

    paths: list[str] = []

    def walk(route, prefix: str = "") -> None:
        if type(route).__name__ == "_IncludedRouter":
            ctx = getattr(route, "include_context", None)
            orig = getattr(route, "original_router", None)
            if orig is not None:
                for child in orig.routes:
                    walk(child, prefix + (getattr(ctx, "prefix", "") or ""))
            return
        endpoint = getattr(route, "endpoint", None)
        path = getattr(route, "path", None)
        if endpoint is None and getattr(route, "routes", None):
            for child in route.routes:
                walk(child, prefix)
            return
        if path and not getattr(route, "methods", None):
            paths.append(prefix + path)

    for route in app.routes:
        walk(route)

    assert paths.count("/ws/monitor/{monitor_id}") == 1, paths
    for expected in ("/ws/stream", "/ws/filter", "/ws/events"):
        assert paths.count(expected) == 1, f"{expected}: {paths}"


@pytest.mark.parametrize("name", ["ws_stream", "ws_monitor_stream", "ws_filter_stream"])
def test_the_handlers_live_in_the_router_module(name):
    """P-2: no socket is defined inline in main.py any more."""
    import warden.main as main_mod

    assert hasattr(ws_stream, name)
    assert not hasattr(main_mod, name), (
        f"{name} is back in main.py — Starlette matches in registration order, "
        "so an inline duplicate silently shadows the router's handler"
    )
