"""
The anonymous `/health/pipeline?deep=true` must not run the canary corpus once
per request.

The route is unauthenticated and has no rate limit (the zone's one free
Cloudflare rate-limit slot guards login/signup). An uncached call runs four full
pipeline passes, so before this guard any caller could buy ~1.25 s of CPU per
request. These tests pin the three properties that stop that: concurrent calls
share one run, a verdict is reused within the TTL, and an unavailable verdict is
not cached (so the first call after startup still runs for real).
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from warden import observability as obs

_HEALTHY = {"available": True, "caught": 3, "missed": 0,
            "false_positive": 0, "healthy": True}


@pytest.fixture(autouse=True)
def _fresh_cache():
    obs.reset_canary_cache()
    yield
    obs.reset_canary_cache()


def _counting(verdict: dict, delay: float = 0.0):
    calls = {"n": 0}

    async def _fake() -> dict:
        calls["n"] += 1
        if delay:
            await asyncio.sleep(delay)
        return dict(verdict)

    return _fake, calls


def test_concurrent_callers_share_one_run() -> None:
    fake, calls = _counting(_HEALTHY, delay=0.05)

    async def _burst() -> list[dict]:
        return await asyncio.gather(*(obs.cached_pipeline_canary() for _ in range(20)))

    with patch.object(obs, "run_pipeline_canary", fake):
        results = asyncio.run(_burst())
    assert calls["n"] == 1
    assert all(r["healthy"] is True for r in results)


def test_verdict_is_reused_within_ttl_and_rerun_after() -> None:
    fake, calls = _counting(_HEALTHY)

    async def _three() -> None:
        await obs.cached_pipeline_canary()
        await obs.cached_pipeline_canary()
        await obs.cached_pipeline_canary(ttl_s=0.0)

    with patch.object(obs, "run_pipeline_canary", fake):
        asyncio.run(_three())
    assert calls["n"] == 2


def test_result_reports_its_age() -> None:
    fake, _ = _counting(_HEALTHY)
    with patch.object(obs, "run_pipeline_canary", fake):
        first = asyncio.run(obs.cached_pipeline_canary())
    assert first["age_s"] == 0.0
    assert {k: v for k, v in first.items() if k != "age_s"} == _HEALTHY


def test_unavailable_verdict_is_not_cached() -> None:
    fake, calls = _counting({"available": False, "healthy": False})

    async def _two() -> None:
        await obs.cached_pipeline_canary()
        await obs.cached_pipeline_canary()

    with patch.object(obs, "run_pipeline_canary", fake):
        asyncio.run(_two())
    assert calls["n"] == 2


def test_route_uses_the_shared_verdict() -> None:
    """The handler must call the cached wrapper, not the raw corpus run."""
    import inspect

    from warden.api import system

    src = inspect.getsource(system.health_pipeline)
    assert "cached_pipeline_canary" in src
    assert "await run_pipeline_canary" not in src
