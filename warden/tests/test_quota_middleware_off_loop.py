"""warden/tests/test_quota_middleware_off_loop.py

The second P99 cause, attributed and fixed.

A ~5.03s stall sat between the request span opening and the app reading the
body — on requests that were otherwise clean and fast. Per-layer middleware
spans (#396) named it on the first reproduction:

    mw.QuotaMiddleware      own = 5067.9ms
    mw.RegionMiddleware     own =      0.5ms    the next layer down
    every layer above it    own =  0.0-0.5ms

Two defects, both in `QuotaMiddleware`:

1. `_redis()` called `from_url` per request. That builds a new ConnectionPool
   every time, so each request opened and discarded its own TCP connection. When
   a connect stalls, the client burns its whole retry budget (connect 2s +
   socket 1s, retried) before failing.

2. The `incr`/`expire` calls are synchronous redis-py, and sat directly inside an
   async ASGI `__call__`. So a slow Redis operation did not merely delay its own
   request — it pinned the event loop, and every request in flight stalled for
   the same duration. That is why the stalls showed up on unrelated requests
   before their bodies had been read.

Reproduced deliberately before the fix: 42 requests (10 sequential, then 4
concurrent bursts of 8) produced 3 stalls of 5096-5159ms.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from warden.billing import quota_middleware as qm


@pytest.fixture(autouse=True)
def _clear_client_cache():
    qm._reset_client()
    yield
    qm._reset_client()


def test_the_client_is_built_once_not_per_request() -> None:
    """A new ConnectionPool per request is a new TCP connect per request."""
    calls = []

    class _FakeRedis:
        def incr(self, *_a):
            return 1

        def expire(self, *_a):
            return True

    def _from_url(*_a, **_kw):
        calls.append(1)
        return _FakeRedis()

    import sys
    import types

    fake = types.ModuleType("redis")
    fake.from_url = _from_url          # type: ignore[attr-defined]
    prev = sys.modules.get("redis")
    sys.modules["redis"] = fake
    try:
        for _ in range(5):
            qm._redis()
    finally:
        if prev is not None:
            sys.modules["redis"] = prev
        else:
            del sys.modules["redis"]

    assert len(calls) == 1, (
        f"the Redis client was constructed {len(calls)} times for 5 calls; "
        "from_url builds a fresh ConnectionPool each time, so this is a new TCP "
        "connection per request"
    )


_SLOW = 0.30


async def _loop_lag(stop: asyncio.Event, out: list[float]) -> None:
    while not stop.is_set():
        t0 = time.perf_counter()
        await asyncio.sleep(0.005)
        out.append((time.perf_counter() - t0 - 0.005) * 1000)


class _SlowRedis:
    """Stands in for redis-py: synchronous, and slow the way a stalled connect is."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.incr_calls: list[str] = []
        self.expire_calls: list[tuple] = []

    def incr(self, key):
        time.sleep(self.delay)
        self.incr_calls.append(key)
        return len(self.incr_calls)

    def expire(self, key, ttl):
        self.expire_calls.append((key, ttl))
        return True


async def _drive(app_seen: list) -> None:
    """Send one counted request through the real QuotaMiddleware."""
    async def _downstream(scope, receive, send):
        app_seen.append(scope["path"])

    mw = qm.QuotaMiddleware(_downstream)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/filter",
        "headers": [(b"x-api-key", b"test-key"), (b"x-tenant-id", b"loop-test")],
        "client": ("127.0.0.1", 5555),
    }
    await mw(scope, None, lambda _m: None)


@pytest.mark.asyncio
async def test_a_slow_quota_check_does_not_pin_the_loop(monkeypatch) -> None:
    """Drive the real ASGI path, not a copy of it.

    The first version of this test defined its own `_bump` and ran it through
    asyncio.to_thread — which tested the standard library, not this middleware.
    A regression could have called the Redis client directly and kept an
    unrelated `to_thread` nearby, and both that test and its source-inspecting
    companion would still have passed. Injecting a slow client and invoking
    QuotaMiddleware.__call__ is what actually holds the invariant.
    """
    # Warm-up first. _get_tenant_id_from_scope resolves the API key through a
    # lazily-imported key store: 370ms on first call in a fresh process, 0.0ms
    # after. That is a one-time import cost, not a per-request one (production
    # p50 for /filter is 11-25ms), and it is not what this test is about — but
    # unwarmed it lands inside the measurement window and reads as loop lag.
    warm = _SlowRedis(0.0)
    monkeypatch.setattr(qm, "_redis", lambda: warm)
    await _drive([])

    fake = _SlowRedis(_SLOW)
    monkeypatch.setattr(qm, "_redis", lambda: fake)

    stop = asyncio.Event()
    lags: list[float] = []
    sampler = asyncio.create_task(_loop_lag(stop, lags))
    await asyncio.sleep(0.02)

    seen: list = []
    await _drive(seen)

    stop.set()
    await sampler

    assert seen == ["/filter"], (
        f"the request never reached the app: {seen} — the middleware short-"
        "circuited before the Redis branch, so nothing here was measured"
    )
    assert len(fake.incr_calls) == 1, f"expected one incr, got {fake.incr_calls}"
    assert len(fake.expire_calls) == 1, (
        f"first use must set a TTL or the key leaks forever: {fake.expire_calls}"
    )

    worst = max(lags)
    assert worst < _SLOW * 1000 * 0.5, (
        f"the event loop stalled {worst:.0f}ms during a {_SLOW*1000:.0f}ms quota "
        "check — the Redis call is back on the loop, and every in-flight request "
        "pays for it"
    )


@pytest.mark.asyncio
async def test_a_second_request_does_not_re_expire(monkeypatch) -> None:
    """expire is first-use only; re-arming it every request would slide the TTL."""
    fake = _SlowRedis(0.0)
    monkeypatch.setattr(qm, "_redis", lambda: fake)
    seen: list = []
    await _drive(seen)
    await _drive(seen)
    assert len(fake.incr_calls) == 2, fake.incr_calls
    assert len(fake.expire_calls) == 1, (
        f"expire ran {len(fake.expire_calls)} times; it must only run on the "
        "first increment"
    )


def test_the_middleware_awaits_the_threaded_call() -> None:
    """The fix only counts at the call site."""
    import inspect

    src = inspect.getsource(qm.QuotaMiddleware.__call__)
    assert "await asyncio.to_thread(" in src, (
        "QuotaMiddleware no longer runs its Redis work off the loop; a slow "
        "quota check will stall every concurrent request again"
    )
    assert "r.incr(" not in src.split("def _bump")[0], (
        "a synchronous incr is back on the async path"
    )


def test_a_failed_client_is_not_cached() -> None:
    """Fail-open must not be permanent.

    The first version of this fix put `@lru_cache` on `_redis()`, which cached
    the `None` returned when construction fails. The caller reads `None` as
    "Redis unavailable — fail open" and skips the quota check, so a single
    transient failure would have disabled quota enforcement for every request
    until the process restarted. A cost control that switches itself off
    permanently on one error is worse than one that is slow.
    """
    import sys
    import types

    attempts = []

    class _Ok:
        def incr(self, *_a):
            return 1

        def expire(self, *_a):
            return True

    def _from_url(*_a, **_kw):
        attempts.append(1)
        if len(attempts) == 1:
            raise ConnectionError("redis down at construction")
        return _Ok()

    fake = types.ModuleType("redis")
    fake.from_url = _from_url          # type: ignore[attr-defined]
    prev = sys.modules.get("redis")
    sys.modules["redis"] = fake
    try:
        first = qm._redis()
        assert first is None, "construction failed, so this must be None (fail-open)"

        second = qm._redis()
        assert second is not None, (
            "the failure was cached — quota enforcement would stay off for the "
            "life of the process after one transient Redis error"
        )

        third = qm._redis()
        assert third is second, "the successful client should be cached"
        assert len(attempts) == 2, (
            f"from_url was called {len(attempts)} times; expected one failure "
            "then one success that is then reused"
        )
    finally:
        if prev is not None:
            sys.modules["redis"] = prev
        else:
            del sys.modules["redis"]
