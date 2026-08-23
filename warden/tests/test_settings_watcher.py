"""
warden/tests/test_settings_watcher.py

The config-drift watchdog had two states where it needed three, and production
showed what that costs: `WARDEN_INTERNAL_URL` was unset in the arq-worker, every
canary probe died on `localhost:8001`, and the job paged `A known jailbreak was
NOT blocked by the filter pipeline` 35 times in 24 hours — for a payload that was
never sent. The one alert that must never be ignored spent a day and a half
crying about a connection error.

These tests pin the distinction: unreachable is not the same as not-blocked, and
a drift check with no baseline is not the same as a drift check that found
nothing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


@pytest.fixture()
def watcher(monkeypatch, tmp_path):
    """The module with Slack, the counter and the snapshot path captured."""
    from warden.workers import settings_watcher as sw

    sent: list[str] = []
    counted: list[tuple[str, str]] = []

    async def _fake_slack(msg: str) -> None:
        sent.append(msg)

    async def _fake_live() -> dict:
        return {"semantic_threshold": 0.72}

    monkeypatch.setattr(sw, "_slack", _fake_slack)
    monkeypatch.setattr(sw, "_get_live_config", _fake_live)
    monkeypatch.setattr(sw, "record_failopen",
                        lambda stage, reason, exc=None: counted.append((stage, reason)))
    monkeypatch.setattr(sw, "_SNAPSHOT_PATH", Path(tmp_path / "no_such_snapshot.json"))
    return sw, sent, counted


def _probe(result: dict):
    async def _p() -> dict:
        return result
    return _p


class TestCanaryOutcomes:
    @pytest.mark.asyncio
    async def test_unreachable_is_not_reported_as_a_detection_failure(
        self, watcher, monkeypatch
    ):
        sw, sent, counted = watcher
        monkeypatch.setattr(sw, "_canary_probe",
                            _probe({"blocked": None, "error": "All connection attempts failed"}))

        out = await sw.watch_config_drift({})

        assert out["canary_reachable"] is False
        joined = "\n".join(sent)
        assert "CANARY UNREACHABLE" in joined
        assert "NOT blocked by the filter pipeline" not in joined, (
            "a connection error was reported as the filter passing a jailbreak"
        )
        assert ("settings_watcher_canary", sw.Reason.NETWORK_ERROR) in counted

    @pytest.mark.asyncio
    async def test_reachable_but_allowed_is_the_critical_alert(self, watcher, monkeypatch):
        sw, sent, _counted = watcher
        monkeypatch.setattr(sw, "_canary_probe",
                            _probe({"blocked": False, "risk_level": "LOW"}))

        out = await sw.watch_config_drift({})

        assert out["canary_ok"] is False
        assert out["canary_reachable"] is True
        assert "NOT blocked by the filter pipeline" in "\n".join(sent)

    @pytest.mark.asyncio
    async def test_blocked_canary_alerts_nobody(self, watcher, monkeypatch):
        sw, sent, _counted = watcher
        monkeypatch.setattr(sw, "_canary_probe",
                            _probe({"blocked": True, "risk_level": "CRITICAL"}))

        out = await sw.watch_config_drift({})

        assert out["canary_ok"] is True
        assert not [m for m in sent if "CANARY" in m]


class TestDriftBaseline:
    @pytest.mark.asyncio
    async def test_missing_baseline_is_counted_and_marked_unchecked(
        self, watcher, monkeypatch
    ):
        """`drift_count: 0` with no baseline reads exactly like "no drift"."""
        sw, _sent, counted = watcher
        monkeypatch.setattr(sw, "_canary_probe", _probe({"blocked": True}))

        out = await sw.watch_config_drift({})

        assert out["drift_checked"] is False, (
            "a check that never ran must be distinguishable from one that passed"
        )
        assert out["drift_count"] == 0
        assert ("settings_watcher_drift", sw.Reason.MODEL_NOT_LOADED) in counted, (
            f"expected the skip to be counted with its own reason, got {counted}"
        )

    @pytest.mark.asyncio
    async def test_present_baseline_is_compared(self, watcher, monkeypatch, tmp_path):
        sw, sent, _counted = watcher
        snap = tmp_path / "config_snapshot.json"
        snap.write_text('{"semantic_threshold": 0.50, "snapshot_at": "2026-08-01"}')
        monkeypatch.setattr(sw, "_SNAPSHOT_PATH", snap)
        monkeypatch.setattr(sw, "_canary_probe", _probe({"blocked": True}))

        out: dict[str, Any] = await sw.watch_config_drift({})

        assert out["drift_count"] == 1
        assert out["drifted_keys"] == ["semantic_threshold"]
        assert "Config Drift Detected" in "\n".join(sent)
