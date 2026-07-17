"""
S4 — in-process agent-tool resource + timeout budget (modernization-plan-v8 §6d).

Most SOVA / MasterAgent tools are thin HTTP calls to ``localhost:8001`` and are already
bounded by the httpx client timeout. A few run **in-process** with no such boundary — the
browser visual tools (``visual_assert_page``, ``visual_diff``) launch a headless Chromium
and call the Anthropic vision API inside the event loop. A hung page load, a wedged
renderer, or a stalled upstream call would otherwise block the dispatch coroutine
indefinitely, and a burst of visual-tool calls could spawn unbounded concurrent Chromium
processes and exhaust host memory / file handles.

Every tool dispatch is wrapped in:

* a **timeout budget** (``asyncio.wait_for``) — a handler that overruns its wall-clock
  budget is cancelled and the caller gets a structured, observable ``tool_timeout`` error
  instead of a hang. Cancelling the coroutine runs ``BrowserSandbox.__aexit__``, so
  Chromium / Playwright is torn down rather than leaked.
* a **concurrency budget** for the heavyweight in-process browser tools — an
  ``asyncio.Semaphore`` caps simultaneous Chromium launches.

This is **fail-safe, not fail-open**: exceeding the budget is a bounded, logged denial,
never a silent pass. Pure asyncio — no new dependency. Budgets are env-tunable so an
operator can widen them for a slow patrol target without a code change.
"""
from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger("warden.agent.tool_budget")


def _env_float(name: str, default: float) -> float:
    try:
        v = float(os.getenv(name, "").strip() or default)
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        v = int(os.getenv(name, "").strip() or default)
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


# Wall-clock budgets (seconds). The default is generous — the HTTP tools' own httpx
# timeout fires first — so it only ever catches a genuinely wedged handler. The browser
# tools get a larger budget: they launch Chromium, navigate, and call Claude Vision
# in-process.
_DEFAULT_TIMEOUT_S = _env_float("SOVA_TOOL_TIMEOUT_S", 60.0)
_BROWSER_TIMEOUT_S = _env_float("SOVA_BROWSER_TOOL_TIMEOUT_S", 120.0)

# Tools that drive a real in-process browser — they share the concurrency budget as well
# as the longer timeout. Keep in sync with the in-process handlers in tools.py.
_IN_PROCESS_BROWSER_TOOLS: frozenset[str] = frozenset(
    {"visual_assert_page", "visual_diff"}
)

# Cap simultaneous in-process Chromium launches (default 2).
_BROWSER_MAX_CONCURRENCY = _env_int("SOVA_BROWSER_MAX_CONCURRENCY", 2)

# Lazily bound to the running loop — module import can precede loop creation in workers
# and tests. asyncio.Semaphore in 3.10+ no longer captures a loop at construction, but we
# still defer so a re-created loop (pytest per-test loops) gets a fresh semaphore.
_browser_semaphore: asyncio.Semaphore | None = None
_browser_semaphore_loop: asyncio.AbstractEventLoop | None = None


def _browser_gate() -> asyncio.Semaphore:
    global _browser_semaphore, _browser_semaphore_loop
    loop = asyncio.get_running_loop()
    if _browser_semaphore is None or _browser_semaphore_loop is not loop:
        _browser_semaphore = asyncio.Semaphore(_BROWSER_MAX_CONCURRENCY)
        _browser_semaphore_loop = loop
    return _browser_semaphore


def timeout_for(tool_name: str) -> float:
    """Wall-clock budget (seconds) for *tool_name*."""
    return _BROWSER_TIMEOUT_S if tool_name in _IN_PROCESS_BROWSER_TOOLS else _DEFAULT_TIMEOUT_S


def is_browser_tool(tool_name: str) -> bool:
    return tool_name in _IN_PROCESS_BROWSER_TOOLS


async def run_within_budget(
    tool_name: str,
    coro_factory: Callable[[], Awaitable[Any]],
) -> Any:
    """
    Run ``coro_factory()`` under *tool_name*'s timeout budget, and — for the heavyweight
    in-process browser tools — under the shared concurrency budget too.

    ``coro_factory`` is a zero-arg callable that returns the handler awaitable, so the
    concurrency gate is acquired **before** the browser coroutine is created. On timeout
    the coroutine is cancelled (which runs BrowserSandbox teardown) and a structured,
    fail-safe error dict is returned — never a silent hang, never an unbounded wait.
    """
    if tool_name in _IN_PROCESS_BROWSER_TOOLS:
        gate = _browser_gate()
        async with gate:
            return await _await_with_timeout(tool_name, coro_factory)
    return await _await_with_timeout(tool_name, coro_factory)


async def _await_with_timeout(
    tool_name: str,
    coro_factory: Callable[[], Awaitable[Any]],
) -> Any:
    budget = timeout_for(tool_name)
    try:
        return await asyncio.wait_for(coro_factory(), timeout=budget)
    except TimeoutError:
        # Fail-SAFE: bounded, observable denial. The wedged handler coroutine has already
        # been cancelled by wait_for (running any async-context teardown, e.g. Chromium).
        log.warning(
            "tool %s exceeded its %.0fs budget — cancelled (fail-safe)", tool_name, budget
        )
        return {
            "error": "tool_timeout",
            "tool": tool_name,
            "budget_s": budget,
            "detail": f"{tool_name} exceeded its {budget:.0f}s in-process budget and was cancelled",
        }
