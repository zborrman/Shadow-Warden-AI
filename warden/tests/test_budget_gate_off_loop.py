"""warden/tests/test_budget_gate_off_loop.py

The P99 tail, finally attributed.

`process_blocked()` held the event loop for ~1.9s per blocked request. Traced on
production (efb6736a): `spawn.process_blocked` ran 1972ms while `evo.llm_call`
inside it took 133ms, and no span from any request started during the first
1.84s. The cost was entirely *before* the LLM call, in the daily-budget gate:

    _is_over_daily_budget()
      -> get_cost_since()  ->  _conn()  ->  open_db()  ->  Turso REMOTE
           _ensure_columns   521.2 ms     one statement, one round-trip
           SELECT 1          540.9 ms     pure latency, not query cost
           SUM(cost_usd)     421.7 ms
           end to end       1778-1942 ms

`staff` is a Turso-backed logical DB in production, so each statement is a
network round-trip — made synchronously from a coroutine. And the answer is
always 0.0: `staff_action_costs` holds 0 rows because evolution spend is never
recorded there (the FM-7 finding). ~1.8s of blocked loop to read a constant.

Detaching the call in #389 could not help: a detached task still runs *on* the
loop. The fix has to take the work off the loop, not off the caller.
"""
from __future__ import annotations

import asyncio
import time

import pytest

import warden.brain.evolve as evolve


@pytest.fixture(autouse=True)
def _clear_cache():
    evolve._BUDGET_CACHE = (0.0, 0.0)
    yield
    evolve._BUDGET_CACHE = (0.0, 0.0)


_SLOW = 0.30


async def _loop_lag(stop: asyncio.Event, out: list) -> None:
    while not stop.is_set():
        t0 = time.perf_counter()
        await asyncio.sleep(0.005)
        out.append((time.perf_counter() - t0 - 0.005) * 1000)


@pytest.mark.asyncio
async def test_the_gate_does_not_block_the_event_loop(monkeypatch) -> None:
    """The whole point. A slow spend read must not stall unrelated work."""
    monkeypatch.setattr(evolve, "EVOLUTION_DAILY_BUDGET_USD", 5.0)
    def _slow_read() -> float:
        time.sleep(_SLOW)
        return 0.0

    monkeypatch.setattr(evolve, "_read_daily_spend", _slow_read)

    stop = asyncio.Event()
    lags: list[float] = []
    sampler = asyncio.create_task(_loop_lag(stop, lags))
    await asyncio.sleep(0.02)

    over = await evolve._is_over_daily_budget_async()

    stop.set()
    await sampler
    assert over is False

    worst = max(lags)
    assert worst < _SLOW * 1000 * 0.5, (
        f"the event loop stalled {worst:.0f}ms while the budget gate ran; the "
        f"read is {_SLOW*1000:.0f}ms, so it is still being made on the loop"
    )


@pytest.mark.asyncio
async def test_the_sync_variant_still_blocks(monkeypatch) -> None:
    """Guard the guard.

    If the sync path stopped blocking, the test above would pass for a reason
    that has nothing to do with to_thread, and would keep passing if the fix
    were reverted.
    """
    monkeypatch.setattr(evolve, "EVOLUTION_DAILY_BUDGET_USD", 5.0)

    def _slow_tracker():
        time.sleep(_SLOW)
        raise RuntimeError("unreachable in this test")

    monkeypatch.setattr(evolve, "_read_daily_spend", _slow_tracker)

    stop = asyncio.Event()
    lags: list[float] = []
    sampler = asyncio.create_task(_loop_lag(stop, lags))
    await asyncio.sleep(0.02)
    time.sleep(_SLOW)          # what the old code did, from a coroutine
    stop.set()
    await sampler
    assert max(lags) >= _SLOW * 1000 * 0.5, (
        "a blocking sleep inside a coroutine did not show up as loop lag — the "
        "measurement above cannot detect the defect it exists to detect"
    )


@pytest.mark.asyncio
async def test_the_read_is_cached(monkeypatch) -> None:
    """Without a TTL every blocked request still pays 1.8s, just in a thread —
    and a burst then exhausts the pool and the stall returns by another route."""
    monkeypatch.setattr(evolve, "EVOLUTION_DAILY_BUDGET_USD", 5.0)
    calls: list[int] = []

    def _counted_read() -> float:
        calls.append(1)
        return 0.0

    monkeypatch.setattr(evolve, "_read_daily_spend", _counted_read)

    for _ in range(5):
        await evolve._is_over_daily_budget_async()
    assert len(calls) == 1, f"spend was read {len(calls)} times for 5 requests"


@pytest.mark.asyncio
async def test_the_cache_expires(monkeypatch) -> None:
    monkeypatch.setattr(evolve, "EVOLUTION_DAILY_BUDGET_USD", 5.0)
    monkeypatch.setattr(evolve, "_BUDGET_CACHE_TTL_S", 0.05)
    calls: list[int] = []

    def _counted_read() -> float:
        calls.append(1)
        return 0.0

    monkeypatch.setattr(evolve, "_read_daily_spend", _counted_read)

    await evolve._is_over_daily_budget_async()
    await asyncio.sleep(0.08)
    await evolve._is_over_daily_budget_async()
    assert len(calls) == 2, "the cache never expires — spend would go stale all day"


@pytest.mark.asyncio
async def test_the_ceiling_still_stops_spending(monkeypatch) -> None:
    """It is a cost guard. Making it cheap must not make it inert."""
    monkeypatch.setattr(evolve, "EVOLUTION_DAILY_BUDGET_USD", 5.0)
    monkeypatch.setattr(evolve, "_read_daily_spend", lambda: 5.01)
    assert await evolve._is_over_daily_budget_async() is True


@pytest.mark.asyncio
async def test_fail_open_on_an_unreadable_store(monkeypatch) -> None:
    """Detection must not depend on the FinOps database being up."""
    monkeypatch.setattr(evolve, "EVOLUTION_DAILY_BUDGET_USD", 5.0)

    def _boom() -> float:
        raise RuntimeError("turso unreachable")

    monkeypatch.setattr(evolve, "_read_daily_spend", _boom)
    assert await evolve._is_over_daily_budget_async() is False


@pytest.mark.asyncio
async def test_disabled_ceiling_reads_nothing(monkeypatch) -> None:
    monkeypatch.setattr(evolve, "EVOLUTION_DAILY_BUDGET_USD", 0.0)
    calls: list[int] = []

    def _counted_read() -> float:
        calls.append(1)
        return 0.0

    monkeypatch.setattr(evolve, "_read_daily_spend", _counted_read)
    assert await evolve._is_over_daily_budget_async() is False
    assert not calls, "a disabled ceiling still paid for a remote round-trip"


def test_process_blocked_uses_the_async_gate() -> None:
    """The fix only counts at the call site."""
    import inspect

    src = inspect.getsource(evolve.EvolutionEngine.process_blocked)
    assert "await _is_over_daily_budget_async()" in src, (
        "process_blocked no longer awaits the off-loop gate — the synchronous "
        "variant blocks for ~1.8s in production"
    )
