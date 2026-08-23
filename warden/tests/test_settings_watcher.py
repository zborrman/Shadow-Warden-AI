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

import json
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

    async def _fake_live() -> tuple[dict, str | None]:
        return {"semantic_threshold": 0.72}, None

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
    async def test_refused_is_not_reported_as_unreachable(self, watcher, monkeypatch):
        """A gateway that answers 401 is not a gateway you could not reach.

        Measured on production 2026-08-23: WARDEN_API_KEY was never passed to the
        arq-worker container, so every probe since this watchdog shipped came
        back 401 — and the operator was told the probe "could not reach
        http://warden:8001", about a host it had just talked to successfully.
        The canary is the only continuous check that the filter still blocks a
        known jailbreak in production, and it had never once completed.
        """
        sw, sent, counted = watcher
        monkeypatch.setattr(sw, "_canary_probe", _probe({
            "blocked": None, "fault": "rejected", "status": 401,
            "error": "HTTP 401 from http://warden:8001/filter",
        }))

        out = await sw.watch_config_drift({})

        assert out["canary_reachable"] is False
        joined = "\n".join(sent)
        assert "CANARY REFUSED" in joined
        assert "CANARY UNREACHABLE" not in joined, (
            "an auth rejection was reported as a connectivity fault"
        )
        assert "NOT blocked by the filter pipeline" not in joined, (
            "an auth rejection was reported as the filter passing a jailbreak"
        )
        assert "WARDEN_API_KEY" in joined, "the alert must name its own fix"
        assert ("settings_watcher_canary", sw.Reason.BACKEND_ERROR) in counted
        assert ("settings_watcher_canary", sw.Reason.NETWORK_ERROR) not in counted

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


class TestDriftFetchFailure:
    @pytest.mark.asyncio
    async def test_unreadable_live_config_is_not_reported_as_drift(
        self, watcher, monkeypatch, tmp_path
    ):
        """A config we could not read is not a config that changed.

        Measured on production 2026-08-23: `_get_live_config` 401'd and returned
        `{}`, so every baseline key compared against `None` and the watchdog
        announced "24 drifted keys" — naming each one and its supposed old and
        new value in Slack. Not one had changed. A drift alert is a claim that
        somebody altered production; fabricating it from a failed request is
        worse than silence, because it is specific enough that someone acts on it.
        """
        sw, sent, counted = watcher
        snap = tmp_path / "snapshot.json"
        snap.write_text(json.dumps({
            "semantic_threshold": 0.72, "strict_mode": False, "rate_limit_per_minute": 60,
        }), encoding="utf-8")
        monkeypatch.setattr(sw, "_SNAPSHOT_PATH", snap)

        async def _broken_live() -> tuple[dict, str | None]:
            return {}, "Client error '401 Unauthorized'"

        monkeypatch.setattr(sw, "_get_live_config", _broken_live)
        monkeypatch.setattr(sw, "_canary_probe", _probe({"blocked": True, "fault": None}))

        out = await sw.watch_config_drift({})

        assert out["drift_checked"] is False
        assert out["drift_count"] == 0
        joined = "\n".join(sent)
        assert "DRIFT CHECK SKIPPED" in joined
        assert "drifted" not in joined.lower(), (
            "an unreadable config was reported as changed keys"
        )
        assert ("settings_watcher_drift", sw.Reason.BACKEND_ERROR) in counted


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
