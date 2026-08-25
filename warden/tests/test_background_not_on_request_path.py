"""warden/tests/test_background_not_on_request_path.py

FastAPI's ``BackgroundTasks`` runs after the response *only* when the middleware
stack is pure ASGI. This app has five ``BaseHTTPMiddleware`` instances in it, and
``BaseHTTPMiddleware`` awaits the inner call — background tasks included — before
releasing the response. ``add_task()`` therefore put the Evolution Engine and the
outbound alerts squarely on the request path.

Traced on production 2026-08-24/25 (visible only once #383 gave the histogram
buckets and #385 made request spans work at all)::

    +  77.2ms   decision                       ← filter finished
    +  81.2ms   BackgroundTask process_blocked  1736.7ms
    +1728.9ms   POST /filter http send          ← client waited 1730 ms

and on organic traffic, the corpus canary at 20:45:00Z / 21:45:00Z / 00:00:01Z:
2488ms, 2485ms, 2338ms, each ~2.0 s of it ``process_blocked``.

The first test reproduces that with a real middleware stack and a real client, so
it fails if anyone reaches for ``add_task`` on a slow path again. It is written
against Starlette's actual behaviour rather than a mock of it — if upstream ever
changes, this test says so instead of quietly passing.
"""
from __future__ import annotations

import asyncio
import time

import pytest
from fastapi import BackgroundTasks, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from warden.background import inflight_count, spawn

_SLOW = 0.40   # long enough to measure, short enough to keep the suite quick


class _Passthrough(BaseHTTPMiddleware):
    """The shape of MTLSMiddleware / RegionMiddleware / _ExtensionCORSMiddleware."""

    async def dispatch(self, request, call_next):
        return await call_next(request)


async def _slow_job(marker: list) -> None:
    await asyncio.sleep(_SLOW)
    marker.append("done")


def _app(use_spawn: bool, marker: list) -> FastAPI:
    app = FastAPI()
    app.add_middleware(_Passthrough)

    @app.post("/go")
    async def go(background_tasks: BackgroundTasks) -> dict:
        if use_spawn:
            spawn(_slow_job, marker, name="slow_job")
        else:
            background_tasks.add_task(_slow_job, marker)
        return {"ok": True}

    return app


def _time_request(app: FastAPI) -> float:
    with TestClient(app) as c:
        t0 = time.perf_counter()
        assert c.post("/go").status_code == 200
        return time.perf_counter() - t0


def test_add_task_under_base_http_middleware_blocks_the_response() -> None:
    """The defect, pinned to Starlette's real behaviour.

    If this starts failing, upstream changed and `add_task` became safe again —
    at which point `spawn` is no longer load-bearing for *this* reason and the
    module docstring needs revisiting. It is not a licence to delete it.
    """
    marker: list = []
    elapsed = _time_request(_app(use_spawn=False, marker=marker))
    assert elapsed >= _SLOW * 0.8, (
        f"add_task returned in {elapsed*1000:.0f}ms, faster than the "
        f"{_SLOW*1000:.0f}ms task it scheduled — BaseHTTPMiddleware no longer "
        "holds the response, so the premise of warden/background.py has changed"
    )


def test_spawn_releases_the_response_immediately() -> None:
    """The fix: the caller does not wait for the work."""
    marker: list = []
    elapsed = _time_request(_app(use_spawn=True, marker=marker))
    assert elapsed < _SLOW * 0.5, (
        f"spawn() held the response for {elapsed*1000:.0f}ms — the work is "
        "still on the request path"
    )


@pytest.mark.asyncio
async def test_spawned_work_actually_runs() -> None:
    """Detaching must not mean dropping. A task nobody holds can be
    garbage-collected mid-flight; background.py keeps a strong reference."""
    marker: list = []
    task = spawn(_slow_job, marker, name="slow_job")
    assert task is not None
    assert inflight_count() >= 1, "spawn() did not retain a reference to the task"
    await asyncio.wait_for(task, timeout=5)
    assert marker == ["done"], "spawned work did not complete"
    assert inflight_count() == 0, "finished task was not released"


@pytest.mark.asyncio
async def test_a_failing_task_is_logged_and_counted_not_swallowed(caplog) -> None:
    """Moving work off the request path removes the caller that would have seen
    the exception. That silence is a new failure surface, so it is instrumented."""
    async def boom() -> None:
        raise RuntimeError("kaboom")

    with caplog.at_level("ERROR", logger="warden.background"):
        task = spawn(boom, name="boom")
        assert task is not None
        with pytest.raises(RuntimeError):
            await task
        await asyncio.sleep(0)   # let the done-callback run

    assert any("kaboom" in r.message or "kaboom" in r.getMessage()
               for r in caplog.records), (
        "a spawned task failed without producing an ERROR log — exactly the "
        "silent-failure pattern this helper is supposed to avoid"
    )


def test_spawn_without_a_running_loop_is_a_noop() -> None:
    """Sync call sites and loop-less tests must not blow up."""
    async def never() -> None:  # pragma: no cover - never awaited
        raise AssertionError("must not run")

    assert spawn(never, name="never") is None


def test_the_slow_block_path_tasks_do_not_use_add_task() -> None:
    """Guard the actual call sites, not just the helper.

    Measured cost of each of these on the request path: process_blocked ~2.0s,
    alert_block_event up to 1.8s, plus the push and Telegram alerts.
    """
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8")
    offenders = []
    for name in ("_evolve.process_blocked", "alert_block_event",
                 "alert_push_verdict", "_tg_block_alert"):
        idx = 0
        while (idx := src.find(name, idx)) != -1:
            window = src[max(0, idx - 220):idx]
            if "background_tasks.add_task(" in window.split("spawn(")[-1]:
                offenders.append(name)
                break
            idx += len(name)
    assert not offenders, (
        f"{sorted(set(offenders))} are scheduled with background_tasks.add_task(). "
        "Under BaseHTTPMiddleware that runs on the request path — use "
        "warden.background.spawn() instead."
    )
