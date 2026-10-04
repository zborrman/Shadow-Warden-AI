"""
warden/tests/test_ws_monitor.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for the WebSocket `/ws/monitor/{monitor_id}` endpoint.

History
───────
This route shipped with the uptime monitor and had **no test of any kind** — the
only one of the four sockets with none. P-2 (#555) moved it into a router and
pinned its behaviour; writing those tests surfaced two defects, fixed here:

  * **SR-9** — it authenticated nobody. No key, no tenant check; anyone holding
    a monitor id streamed its probe results.
  * **SR-10** — its reader thread blocked in `pubsub.listen()` and nothing told
    it to stop, so every connection stranded a thread and a Redis connection.

The auth tests enable authentication explicitly. `conftest.py` leaves
`WARDEN_API_KEY` blank, which puts `require_api_key` in dev mode where every
request passes — so a gate test that did not patch `auth_guard`'s globals would
pass without ever exercising the gate.

The forwarding tests drive the handler directly rather than through
`TestClient`. The send loop waits on its queue with a hardcoded 30-second
timeout that a client-side close does not interrupt, so a `TestClient` context
exit would block for the full timeout. A fake socket whose `send_text` raises
`WebSocketDisconnect` ends the loop the way a real disconnect does.
"""
from __future__ import annotations

import asyncio
import json
import time

import pytest
from fastapi import HTTPException, WebSocketDisconnect

import warden.api.monitor as monitor_mod
import warden.auth_guard as ag
from warden.api import ws_stream

_CHANNEL_ID = "mon-42"
_RESULT = {
    "is_up": True, "latency_ms": 12.5, "status_code": 200,
    "error": None, "ts": "2026-10-04T00:00:00Z",
}


# ── fakes ─────────────────────────────────────────────────────────────────────

class _FakeWebSocket:
    """Records what the handler sent; disconnects after `disconnect_after` sends."""

    def __init__(self, disconnect_after: int = 1) -> None:
        self.accepted = False
        self.closed = False
        self.close_code: int | None = None
        self.sent_text: list[str] = []
        self.sent_json: list[dict] = []
        self._disconnect_after = disconnect_after
        self.query_params: dict[str, str] = {}

    async def accept(self) -> None:
        self.accepted = True

    async def close(self, code: int = 1000) -> None:
        self.closed = True
        self.close_code = code

    async def send_json(self, data: dict) -> None:
        self.sent_json.append(data)

    async def send_text(self, data: str) -> None:
        self.sent_text.append(data)
        if len(self.sent_text) >= self._disconnect_after:
            raise WebSocketDisconnect(code=1000)


class _FakePubSub:
    def __init__(self, messages: list[dict] | None = None) -> None:
        self._messages = list(messages or [])
        self.subscribed: list[str] = []
        self.unsubscribed: list[str] = []
        self.closed = False

    def subscribe(self, channel: str) -> None:
        self.subscribed.append(channel)

    def unsubscribe(self, channel: str) -> None:
        self.unsubscribed.append(channel)

    def close(self) -> None:
        self.closed = True

    def get_message(self, timeout: float = 0.0):
        if self._messages:
            return self._messages.pop(0)
        time.sleep(0.01)          # stand in for the blocking poll
        return None


class _FakeRedis:
    def __init__(self, messages: list[dict] | None = None) -> None:
        self.ps = _FakePubSub(messages)

    def pubsub(self) -> _FakePubSub:
        return self.ps


def _msg(payload: dict) -> dict:
    return {"type": "message", "data": json.dumps(payload)}


def _code_of(fn) -> str:
    """The function's executable source, with the docstring and comments gone.

    A plain `inspect.getsource` check reads the prose too. The first version of
    `test_it_polls_rather_than_blocking_in_listen` asserted `pubsub.listen()`
    was absent and failed against its own docstring, which names the call while
    explaining why it was removed — a guard that matches the comment describing
    a bug cannot tell you the bug is gone. `ast.unparse` drops both.
    """
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    func = tree.body[0]
    # Narrowed rather than ignored: `tree.body[0]` is an `ast.stmt`, which has no
    # `.body`, and mypy is right to say so. An assert also means a caller that
    # passes something other than a function fails here instead of silently
    # comparing against an empty string, which every `in` check would pass.
    assert isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)), fn
    body: list[ast.stmt] = func.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    return "\n".join(ast.unparse(node) for node in body)


def _await_listener_exit(ps: _FakePubSub, timeout: float = 5.0) -> None:
    """Wait for the reader thread to finish.

    `unsubscribe`/`close` run only in `_listen`'s `finally`, so observing them is
    how a test proves the thread actually terminated. The handler returns as soon
    as it sets the stop event; the thread notices within one poll interval.
    """
    deadline = time.time() + timeout
    while time.time() < deadline and not ps.closed:
        time.sleep(0.02)


@pytest.fixture
def _auth_on(monkeypatch):
    """Authentication genuinely enabled.

    Patch `auth_guard`'s module globals rather than reloading: `require_api_key`
    reads them at call time, while importers bind the function by value.
    """
    monkeypatch.setattr(ag, "_VALID_KEY", "monitor-test-key", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)


@pytest.fixture
def _owned(monkeypatch):
    """The tenant owns the monitor (the ownership query succeeds)."""
    async def _ok(monitor_id: str, tenant_id: str) -> dict:
        return {"id": monitor_id, "tenant_id": tenant_id}

    monkeypatch.setattr(monitor_mod, "_get_monitor", _ok)


@pytest.fixture
def _fast_idle(monkeypatch):
    """Shorten the 30s idle wait so tests measure behaviour, not the clock."""
    real_wait_for = asyncio.wait_for
    monkeypatch.setattr(
        ws_stream.asyncio, "wait_for",
        lambda coro, timeout: real_wait_for(coro, 0.25),
    )


# ══════════════════════════════════════════════════════════════════════════════
# SR-9 — authentication and authorization
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthentication:
    async def test_no_key_is_refused(self, monkeypatch, _auth_on):
        """Was the whole defect: this connected anyone. Now it needs ?key=."""
        touched: list[str] = []
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: touched.append("redis"))
        ws = _FakeWebSocket()

        await ws_stream.ws_monitor_stream(ws, _CHANNEL_ID)

        assert ws.closed and ws.close_code == 1008, "an unauthenticated socket stayed open"
        assert ws.sent_json and ws.sent_json[0]["code"] == 401
        assert ws.sent_text == []
        assert touched == [], "Redis was reached before the caller was authenticated"

    async def test_a_valid_key_gets_through(self, monkeypatch, _auth_on, _owned, _fast_idle):
        fake = _FakeRedis([_msg(_RESULT)])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        ws = _FakeWebSocket()

        await _call_with_key(ws_stream, ws, _CHANNEL_ID, "monitor-test-key")

        assert ws.sent_text == [json.dumps(_RESULT)]
        _await_listener_exit(fake.ps)


class TestAuthorization:
    async def test_another_tenants_monitor_is_refused(self, monkeypatch, _auth_on):
        """Holding a key is not holding *this* monitor — the IDOR half of SR-9."""
        async def _not_found(monitor_id: str, tenant_id: str) -> dict:
            raise HTTPException(status_code=404, detail="Monitor not found.")

        monkeypatch.setattr(monitor_mod, "_get_monitor", _not_found)
        touched: list[str] = []
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: touched.append("redis"))
        ws = _FakeWebSocket()

        await _call_with_key(ws_stream, ws, _CHANNEL_ID, "monitor-test-key")

        assert ws.closed and ws.close_code == 1008
        assert ws.sent_json and ws.sent_json[0]["code"] == 404
        assert touched == [], "subscribed before proving the tenant owns the monitor"

    async def test_an_unavailable_lookup_fails_closed(self, monkeypatch, _auth_on):
        """An authorization check that cannot run has not passed."""
        async def _db_down(monitor_id: str, tenant_id: str) -> dict:
            raise RuntimeError("connection refused")

        monkeypatch.setattr(monitor_mod, "_get_monitor", _db_down)
        touched: list[str] = []
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: touched.append("redis"))
        ws = _FakeWebSocket()

        await _call_with_key(ws_stream, ws, _CHANNEL_ID, "monitor-test-key")

        assert ws.closed and ws.close_code == 1011, "a failed ownership check let the socket live"
        assert ws.sent_json and ws.sent_json[0]["code"] == 503
        assert touched == [], "streamed despite being unable to authorize"

    def test_both_siblings_still_gate(self):
        """The gate that /ws/monitor was missing must not go missing elsewhere."""
        for guarded in (ws_stream.ws_stream, ws_stream.ws_filter_stream,
                        ws_stream.ws_monitor_stream):
            assert "require_api_key" in _code_of(guarded), (
                f"{guarded.__name__} lost its auth gate"
            )

    def test_ownership_is_checked_before_subscribing(self):
        """Order matters: a check after `subscribe` has already leaked the stream."""
        code = _code_of(ws_stream.ws_monitor_stream)
        assert "_get_monitor" in code, "the tenant-ownership check is gone"
        assert code.index("_get_monitor") < code.index("_get_redis()"), (
            "the ownership check moved after Redis was reached"
        )


# ══════════════════════════════════════════════════════════════════════════════
# SR-10 — the reader thread stops
# ══════════════════════════════════════════════════════════════════════════════

class TestListenerLifecycle:
    async def test_the_thread_stops_when_the_client_disconnects(
        self, monkeypatch, _auth_on, _owned
    ):
        fake = _FakeRedis([_msg(_RESULT)])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        ws = _FakeWebSocket()                      # disconnects on first send

        await _call_with_key(ws_stream, ws, _CHANNEL_ID, "monitor-test-key")
        _await_listener_exit(fake.ps)

        assert fake.ps.unsubscribed == [f"monitor:{_CHANNEL_ID}:result"]
        assert fake.ps.closed, "the reader thread outlived the handler (SR-10)"

    async def test_the_thread_stops_on_the_idle_timeout(
        self, monkeypatch, _auth_on, _owned, _fast_idle
    ):
        """The leak needed no disconnect: an idle monitor was enough."""
        fake = _FakeRedis([])                      # nothing ever published
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        ws = _FakeWebSocket()

        await _call_with_key(ws_stream, ws, _CHANNEL_ID, "monitor-test-key")
        _await_listener_exit(fake.ps)

        assert ws.sent_text == []
        assert fake.ps.closed, "an idle socket stranded its reader thread (SR-10)"

    async def test_no_thread_is_left_running(self, monkeypatch, _auth_on, _owned, _fast_idle):
        """Count threads, not just cleanup calls — the leak was a thread."""
        import threading

        fake = _FakeRedis([])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        before = threading.active_count()

        for _ in range(3):
            await _call_with_key(ws_stream, _FakeWebSocket(), _CHANNEL_ID, "monitor-test-key")
        _await_listener_exit(fake.ps)

        deadline = time.time() + 5
        while time.time() < deadline and threading.active_count() > before:
            time.sleep(0.05)
        assert threading.active_count() <= before, (
            "reader threads accumulated across connections"
        )

    def test_it_polls_rather_than_blocking_in_listen(self):
        """`listen()` is a blocking generator and cannot be told to stop."""
        code = _code_of(ws_stream.ws_monitor_stream)
        assert "pubsub.listen()" not in code, (
            "back on the blocking generator — the stop event cannot interrupt it"
        )
        assert "get_message" in code, "nothing polls the subscription"
        assert "stop.set()" in code, "nothing signals the reader thread to stop"


class TestBackpressure:
    async def test_a_full_queue_drops_instead_of_raising(
        self, monkeypatch, _auth_on, _owned, _fast_idle
    ):
        """QueueFull inside a call_soon_threadsafe callback reaches nobody."""
        fake = _FakeRedis([_msg({**_RESULT, "status_code": n}) for n in range(150)])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        # Never drains: every send disconnects only after 200, so the 100-slot
        # queue overflows while the consumer is still alive.
        ws = _FakeWebSocket(disconnect_after=200)

        await _call_with_key(ws_stream, ws, _CHANNEL_ID, "monitor-test-key")
        _await_listener_exit(fake.ps)

        # The point is that nothing raised out of the loop callback.
        assert fake.ps.closed


# ══════════════════════════════════════════════════════════════════════════════
# Behaviour preserved from #555
# ══════════════════════════════════════════════════════════════════════════════

class TestRedisUnavailable:
    async def test_it_says_so_and_closes(self, monkeypatch, _auth_on, _owned):
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: None)
        ws = _FakeWebSocket()

        await _call_with_key(ws_stream, ws, _CHANNEL_ID, "monitor-test-key")

        assert ws.accepted
        assert ws.sent_json == [{"error": "Redis unavailable"}]
        assert ws.closed
        assert ws.sent_text == []


class TestForwarding:
    async def test_a_published_result_reaches_the_client(
        self, monkeypatch, _auth_on, _owned
    ):
        payload = json.dumps(_RESULT)
        fake = _FakeRedis([{"type": "message", "data": payload}])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        ws = _FakeWebSocket()

        await _call_with_key(ws_stream, ws, _CHANNEL_ID, "monitor-test-key")

        assert ws.sent_text == [payload]
        assert json.loads(ws.sent_text[0])["status_code"] == 200
        _await_listener_exit(fake.ps)

    async def test_it_subscribes_to_that_monitor_only(self, monkeypatch, _auth_on, _owned):
        """The channel carries the id, so a typo here is a cross-monitor leak."""
        fake = _FakeRedis([_msg(_RESULT)])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)

        await _call_with_key(ws_stream, _FakeWebSocket(), "mon-7", "monitor-test-key")
        _await_listener_exit(fake.ps)

        assert fake.ps.subscribed == ["monitor:mon-7:result"]

    async def test_subscribe_control_frames_are_not_forwarded(
        self, monkeypatch, _auth_on, _owned
    ):
        """pubsub emits its own `subscribe` confirmation — only `message` is data."""
        payload = json.dumps(_RESULT)
        fake = _FakeRedis([
            {"type": "subscribe", "data": 1},
            {"type": "message", "data": payload},
        ])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        ws = _FakeWebSocket()

        await _call_with_key(ws_stream, ws, _CHANNEL_ID, "monitor-test-key")
        _await_listener_exit(fake.ps)

        assert ws.sent_text == [payload], "a control frame was relayed as a probe result"

    async def test_a_listener_error_does_not_crash_the_handler(
        self, monkeypatch, _auth_on, _owned, _fast_idle
    ):
        """The reader thread runs sync Redis; its failure must not escape."""
        class _Boom(_FakePubSub):
            def subscribe(self, channel: str) -> None:
                raise RuntimeError("pubsub died")

        fake = _FakeRedis([])
        fake.ps = _Boom([])
        monkeypatch.setattr(ws_stream, "_get_redis", lambda: fake)
        ws = _FakeWebSocket()

        await _call_with_key(ws_stream, ws, _CHANNEL_ID, "monitor-test-key")  # must not raise

        assert ws.sent_text == []
        _await_listener_exit(fake.ps)
        assert fake.ps.closed, "a failing subscribe skipped the cleanup"


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


# ── helper ────────────────────────────────────────────────────────────────────

async def _call_with_key(mod, ws, monitor_id: str, key: str | None):
    """Invoke the handler with `?key=` set on the fake socket."""
    ws.query_params = {"key": key} if key else {}
    return await mod.ws_monitor_stream(ws, monitor_id)
