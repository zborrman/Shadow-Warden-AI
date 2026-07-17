"""
S4 — tests for the in-process agent-tool resource + timeout budget
(``warden/agent/tool_budget.py``).

The budget is fail-SAFE: a wedged handler is cancelled and a structured ``tool_timeout``
error is returned (never a hang), and concurrent in-process browser tools are capped by a
semaphore. These are pure-asyncio tests — no Chromium, no network.
"""
from __future__ import annotations

import asyncio

from warden.agent import tool_budget

# ── timeout_for / classification ────────────────────────────────────────────────

def test_browser_tools_get_the_longer_budget():
    assert tool_budget.timeout_for("visual_assert_page") == tool_budget._BROWSER_TIMEOUT_S
    assert tool_budget.timeout_for("visual_diff") == tool_budget._BROWSER_TIMEOUT_S
    assert tool_budget.is_browser_tool("visual_assert_page")


def test_non_browser_tools_get_the_default_budget():
    assert tool_budget.timeout_for("filter_request") == tool_budget._DEFAULT_TIMEOUT_S
    assert tool_budget.timeout_for("get_stats") == tool_budget._DEFAULT_TIMEOUT_S
    assert not tool_budget.is_browser_tool("filter_request")


# ── happy path ──────────────────────────────────────────────────────────────────

async def test_returns_handler_result_on_success():
    async def handler():
        return {"ok": True, "value": 42}

    result = await tool_budget.run_within_budget("get_stats", handler)
    assert result == {"ok": True, "value": 42}


async def test_factory_is_called_exactly_once():
    calls = 0

    async def handler():
        nonlocal calls
        calls += 1
        return "done"

    await tool_budget.run_within_budget("get_stats", handler)
    assert calls == 1


# ── timeout → fail-safe ─────────────────────────────────────────────────────────

async def test_overrun_returns_structured_timeout_error(monkeypatch):
    monkeypatch.setattr(tool_budget, "_DEFAULT_TIMEOUT_S", 0.05)

    async def slow_handler():
        await asyncio.sleep(5)
        return {"never": "reached"}

    result = await tool_budget.run_within_budget("get_stats", slow_handler)
    assert result["error"] == "tool_timeout"
    assert result["tool"] == "get_stats"
    assert result["budget_s"] == 0.05


async def test_overrun_cancels_the_handler_coroutine(monkeypatch):
    """The wedged coroutine must be cancelled, so async-context teardown runs
    (this is what tears Chromium down instead of leaking it)."""
    monkeypatch.setattr(tool_budget, "_DEFAULT_TIMEOUT_S", 0.05)
    torn_down = False

    async def handler_with_teardown():
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            nonlocal torn_down
            torn_down = True
            raise
        return {"never": "reached"}

    result = await tool_budget.run_within_budget("get_stats", handler_with_teardown)
    # give the cancelled task a tick to run its except/finally
    await asyncio.sleep(0)
    assert result["error"] == "tool_timeout"
    assert torn_down is True


async def test_browser_tool_uses_browser_budget_on_timeout(monkeypatch):
    monkeypatch.setattr(tool_budget, "_BROWSER_TIMEOUT_S", 0.05)

    async def slow_handler():
        await asyncio.sleep(5)

    result = await tool_budget.run_within_budget("visual_diff", slow_handler)
    assert result["error"] == "tool_timeout"
    assert result["budget_s"] == 0.05  # browser budget, not the default


# ── concurrency budget ──────────────────────────────────────────────────────────

async def test_browser_tools_are_concurrency_capped(monkeypatch):
    # Reset the lazily-bound semaphore so the patched cap takes effect on this loop.
    monkeypatch.setattr(tool_budget, "_BROWSER_MAX_CONCURRENCY", 2)
    monkeypatch.setattr(tool_budget, "_browser_semaphore", None)
    monkeypatch.setattr(tool_budget, "_browser_semaphore_loop", None)

    live = 0
    peak = 0

    async def handler():
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.05)
        live -= 1
        return "ok"

    await asyncio.gather(
        *[tool_budget.run_within_budget("visual_assert_page", handler) for _ in range(6)]
    )
    assert peak <= 2, f"concurrency cap breached: peak={peak}"


async def test_non_browser_tools_are_not_concurrency_capped(monkeypatch):
    monkeypatch.setattr(tool_budget, "_BROWSER_MAX_CONCURRENCY", 1)
    monkeypatch.setattr(tool_budget, "_browser_semaphore", None)
    monkeypatch.setattr(tool_budget, "_browser_semaphore_loop", None)

    live = 0
    peak = 0

    async def handler():
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.05)
        live -= 1
        return "ok"

    await asyncio.gather(
        *[tool_budget.run_within_budget("get_stats", handler) for _ in range(5)]
    )
    assert peak == 5, "non-browser tools must not share the browser concurrency gate"


# ── env parsing helpers ─────────────────────────────────────────────────────────

def test_env_float_rejects_nonpositive_and_garbage(monkeypatch):
    monkeypatch.setenv("X_BUDGET", "-3")
    assert tool_budget._env_float("X_BUDGET", 60.0) == 60.0
    monkeypatch.setenv("X_BUDGET", "not-a-number")
    assert tool_budget._env_float("X_BUDGET", 60.0) == 60.0
    monkeypatch.setenv("X_BUDGET", "12.5")
    assert tool_budget._env_float("X_BUDGET", 60.0) == 12.5


def test_env_int_rejects_nonpositive_and_garbage(monkeypatch):
    monkeypatch.setenv("X_CAP", "0")
    assert tool_budget._env_int("X_CAP", 2) == 2
    monkeypatch.setenv("X_CAP", "abc")
    assert tool_budget._env_int("X_CAP", 2) == 2
    monkeypatch.setenv("X_CAP", "4")
    assert tool_budget._env_int("X_CAP", 2) == 4
