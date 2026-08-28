"""warden/tests/test_quota_prelude_off_loop.py

The half of the second P99 cause that #401 missed.

#401 moved `QuotaMiddleware`'s Redis INCR off the event loop and the stalls got
better, so the fix was reported as complete. It was not. Three synchronous calls
still ran on the loop *before* that `to_thread`, in the same function:

    _get_tenant_id_from_scope()   -> lazy import of warden.auth_guard (~370ms once)
    _get_plan_from_scope()        -> get_plan(): a SQLite query on lemon.db
    get_bonus_requests()          -> referral._redis(): from_url PER CALL

The third is the same defect #401 fixed, in the module next door:
`warden/billing/referral.py` built a fresh ConnectionPool -- and so a fresh TCP
connect -- on every invocation, and `QuotaMiddleware` calls it on every POST
/filter. Fixing one of the two connects in a single function and declaring the
cause closed is what these tests exist to prevent.

Post-#401 production evidence that something was left: a burst against a
2-minute-old container still produced three 5.1s stalls, with
`mw.QuotaMiddleware` owning 5032.7ms.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from warden.billing import quota_middleware as qm
from warden.billing import referral as ref

_SLOW = 0.30


def _reset_all() -> None:
    # getattr, not a direct call: if a regression removes _reset_client the
    # fixture must not ERROR, because a setup error reads as "test caught the
    # regression" while the assertion it exists for never ran.
    for mod in (qm, ref):
        getattr(mod, "_reset_client", lambda: None)()


@pytest.fixture(autouse=True)
def _clear_client_caches():
    _reset_all()
    yield
    _reset_all()


class _FastRedis:
    def incr(self, *_a):
        return 1

    def expire(self, *_a):
        return True


async def _loop_lag(stop: asyncio.Event, out: list[float]) -> None:
    while not stop.is_set():
        t0 = time.perf_counter()
        await asyncio.sleep(0.005)
        out.append((time.perf_counter() - t0 - 0.005) * 1000)


async def _drive(seen: list) -> None:
    """One counted request through the real QuotaMiddleware."""
    async def _downstream(scope, receive, send):
        seen.append(scope["path"])

    mw = qm.QuotaMiddleware(_downstream)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/filter",
        "headers": [(b"x-api-key", b"test-key")],
        "client": ("127.0.0.1", 5555),
    }
    await mw(scope, None, lambda _m: None)


@pytest.mark.asyncio
async def test_a_slow_bonus_lookup_does_not_pin_the_loop(monkeypatch) -> None:
    """get_bonus_requests is a Redis GET on the request path of every /filter."""
    monkeypatch.setattr(qm, "_redis", lambda: _FastRedis())

    # Warm-up: the first request pays a one-time lazy import inside the tenant
    # resolver. It is not per-request cost, but unwarmed it lands in the window.
    monkeypatch.setattr(ref, "get_bonus_requests", lambda _t: 0)
    await _drive([])

    def _slow_bonus(_tenant_id: str) -> int:
        time.sleep(_SLOW)
        return 0

    monkeypatch.setattr(ref, "get_bonus_requests", _slow_bonus)

    stop = asyncio.Event()
    lags: list[float] = []
    sampler = asyncio.create_task(_loop_lag(stop, lags))
    await asyncio.sleep(0.02)

    seen: list = []
    await _drive(seen)

    stop.set()
    await sampler

    assert seen == ["/filter"], (
        f"the request never reached the app: {seen} -- the middleware short-"
        "circuited before the bonus lookup, so nothing here was measured"
    )
    worst = max(lags)
    assert worst < _SLOW * 1000 * 0.5, (
        f"the event loop stalled {worst:.0f}ms during a {_SLOW*1000:.0f}ms bonus "
        "lookup -- the quota prelude is back on the loop, and every in-flight "
        "request pays for it"
    )


@pytest.mark.asyncio
async def test_a_slow_plan_query_does_not_pin_the_loop(monkeypatch) -> None:
    """get_plan() is a SQLite query, and SQLite blocks the thread it runs on."""
    monkeypatch.setattr(qm, "_redis", lambda: _FastRedis())
    monkeypatch.setattr(ref, "get_bonus_requests", lambda _t: 0)
    await _drive([])

    class _SlowBilling:
        def get_plan(self, _tenant_id):
            time.sleep(_SLOW)
            return "starter"

    import warden.lemon_billing as lb
    monkeypatch.setattr(lb, "get_lemon_billing", lambda: _SlowBilling())

    stop = asyncio.Event()
    lags: list[float] = []
    sampler = asyncio.create_task(_loop_lag(stop, lags))
    await asyncio.sleep(0.02)

    seen: list = []
    await _drive(seen)

    stop.set()
    await sampler

    assert seen == ["/filter"], f"the request never reached the app: {seen}"
    worst = max(lags)
    assert worst < _SLOW * 1000 * 0.5, (
        f"the event loop stalled {worst:.0f}ms during a {_SLOW*1000:.0f}ms plan "
        "query -- the SQLite read is back on the loop"
    )


def test_the_referral_client_is_built_once_not_per_call() -> None:
    """The #401 defect, in the module next door."""
    import sys
    import types

    calls = []

    class _Ok:
        def get(self, *_a):
            return None

    def _from_url(*_a, **_kw):
        calls.append(1)
        return _Ok()

    fake = types.ModuleType("redis")
    fake.from_url = _from_url          # type: ignore[attr-defined]
    prev = sys.modules.get("redis")
    sys.modules["redis"] = fake
    try:
        for _ in range(5):
            ref._redis()
    finally:
        if prev is not None:
            sys.modules["redis"] = prev
        else:
            del sys.modules["redis"]

    assert len(calls) == 1, (
        f"referral built its Redis client {len(calls)} times for 5 calls; "
        "from_url makes a fresh ConnectionPool, so that is a TCP connect on "
        "every POST /filter"
    )


def test_a_failed_referral_client_is_not_cached() -> None:
    """Fail-open must not be permanent -- the same trap as in quota_middleware."""
    import sys
    import types

    attempts = []

    class _Ok:
        def get(self, *_a):
            return None

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
        assert ref._redis() is None, "construction failed, so this must be None"
        second = ref._redis()
        assert second is not None, (
            "the failure was cached -- referral bonuses would stay unreadable "
            "for the life of the process after one transient Redis error"
        )
        assert ref._redis() is second, "the successful client should be cached"
        assert len(attempts) == 2, f"expected one failure then one success: {attempts}"
    finally:
        if prev is not None:
            sys.modules["redis"] = prev
        else:
            del sys.modules["redis"]


def test_the_prelude_is_not_inlined_back_into_the_call_path() -> None:
    """The fix only counts at the call site."""
    import inspect

    src = inspect.getsource(qm.QuotaMiddleware.__call__)
    assert "_resolve_quota_context" in src, (
        "QuotaMiddleware no longer routes tenant/plan/bonus resolution through "
        "the threaded resolver"
    )
    assert "_get_plan_from_scope(" not in src, (
        "the SQLite plan query is called directly from the async path again"
    )
    assert "get_bonus_requests(" not in src, (
        "the Redis bonus lookup is called directly from the async path again"
    )
