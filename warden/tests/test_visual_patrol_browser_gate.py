"""
The nightly visual patrol must not launch a browser the image does not have.

The runtime image is python:3.11-slim with no Chromium, and BROWSER_ENABLED
defaults to false. sova_visual_patrol ignored the flag, so every 03:00 run failed
with "BrowserType.launch: Executable doesn't exist" and logged an ERROR: a feature
switched off on purpose read as a broken one.
"""
from __future__ import annotations

import logging

import pytest

from warden.agent import scheduler
from warden.config import settings


@pytest.mark.asyncio
async def test_patrol_skips_without_touching_the_browser(monkeypatch, caplog):
    monkeypatch.setattr(settings, "browser_enabled", False)

    import warden.agent.tools as tools

    async def _boom(*a, **k):  # pragma: no cover - must not be reached
        raise AssertionError("visual_assert_page called with the browser disabled")

    monkeypatch.setattr(tools, "visual_assert_page", _boom)
    with caplog.at_level(logging.INFO, logger=scheduler.log.name):
        result = await scheduler.sova_visual_patrol({})

    assert result == {"status": "skipped", "reason": "browser_disabled"}
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_browser_flag_defaults_off(monkeypatch):
    monkeypatch.delenv("BROWSER_ENABLED", raising=False)
    from warden.config import Settings

    assert Settings().browser_enabled is False


def test_browser_flag_reads_env(monkeypatch):
    monkeypatch.setenv("BROWSER_ENABLED", "true")
    from warden.config import Settings

    assert Settings().browser_enabled is True
