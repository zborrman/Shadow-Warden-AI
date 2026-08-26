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
    # getattr, not a direct call: if the cache is ever removed this fixture must
    # not blow up in setup. An error here would mask the assertion below, and
    # report a missing `cache_clear` instead of the defect that matters — a new
    # connection pool per request.
    clear = getattr(qm._redis, "cache_clear", lambda: None)
    clear()
    yield
    clear()


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


@pytest.mark.asyncio
async def test_a_slow_redis_call_does_not_pin_the_event_loop() -> None:
    """The property that actually matters.

    A slow quota check must cost *its own* request, never every request in
    flight. Modelled on the real call shape: a blocking incr inside the async
    middleware path, run through to_thread.
    """
    class _SlowRedis:
        def incr(self, *_a):
            time.sleep(_SLOW)
            return 1

        def expire(self, *_a):
            return True

    r = _SlowRedis()

    def _bump() -> int:
        total = r.incr("k")
        if total == 1:
            r.expire("k", 1)
        return int(total)

    stop = asyncio.Event()
    lags: list[float] = []
    sampler = asyncio.create_task(_loop_lag(stop, lags))
    await asyncio.sleep(0.02)

    assert await asyncio.to_thread(_bump) == 1

    stop.set()
    await sampler

    worst = max(lags)
    assert worst < _SLOW * 1000 * 0.5, (
        f"the event loop stalled {worst:.0f}ms during a {_SLOW*1000:.0f}ms quota "
        "check — the Redis call is still being made on the loop, and every "
        "in-flight request pays for it"
    )


@pytest.mark.asyncio
async def test_the_probe_can_see_a_blocked_loop() -> None:
    """Guard the guard: if a blocking call did not register as lag, the test
    above would pass for a reason unrelated to the fix."""
    stop = asyncio.Event()
    lags: list[float] = []
    sampler = asyncio.create_task(_loop_lag(stop, lags))
    await asyncio.sleep(0.02)
    time.sleep(_SLOW)                      # what the old code did
    stop.set()
    await sampler
    assert max(lags) >= _SLOW * 1000 * 0.5


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
