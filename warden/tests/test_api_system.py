"""
warden/tests/test_api_system.py
───────────────────────────────
`GET /api/stats` + `GET /health/pipeline` + `GET`/`POST /api/config` — extracted
from main.py to `warden/api/system.py` (P-2), plus
`warden.cache.check_redis_health` (Redis probe → the leaf it probes) and the
live-tunable knobs in `warden.gateway_state`. Exercised on a minimal app with
just the router mounted — no ML boot / lifespan; the journal reads, the Redis
probe and the runtime singletons are patched.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.api import system as system_mod
from warden.api.system import router
from warden.gateway_state import gateway_state


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _entry(**over) -> dict:
    base = {
        "ts": datetime.now(UTC).isoformat(),
        "request_id": "req-1",
        "allowed": True,
        "risk_level": "LOW",
        "flags": [],
        "secrets_found": [],
        "elapsed_ms": 5.0,
        "payload_len": 12,
    }
    base.update(over)
    return base


def test_stats_empty_journal(client: TestClient) -> None:
    with patch("warden.api.system.event_logger.load_entries", return_value=[]):
        resp = client.get("/api/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == body["allowed"] == body["blocked"] == 0
    assert body["avg_latency_ms"] == 0.0
    assert body["p99_latency_ms"] == 0.0
    assert len(body["time_series"]) == 60
    assert body["recent"] == []


def test_stats_aggregates_and_buckets(client: TestClient) -> None:
    now = datetime.now(UTC)
    entries = [
        _entry(request_id="a", allowed=True, risk_level="LOW", elapsed_ms=10.0,
               flags=["OBFUSCATION"], ts=now.isoformat()),
        _entry(request_id="b", allowed=False, risk_level="HIGH", elapsed_ms=30.0,
               flags=["JAILBREAK", "OBFUSCATION"], secrets_found=["AWS_KEY"],
               ts=(now - timedelta(minutes=5)).isoformat()),
        _entry(request_id="c", allowed=False, risk_level="HIGH", elapsed_ms=20.0,
               ts=(now - timedelta(minutes=90)).isoformat()),  # outside the 60-min window
    ]
    with patch("warden.api.system.event_logger.load_entries", return_value=entries):
        resp = client.get("/api/stats", params={"hours": 6})
    body = resp.json()

    assert body["period_hours"] == 6
    assert body["total"] == 3
    assert body["allowed"] == 1
    assert body["blocked"] == 2
    assert body["by_risk"] == {"LOW": 1, "HIGH": 2}
    assert dict(body["top_flags"])["OBFUSCATION"] == 2
    assert body["secrets_found"] == {"AWS_KEY": 1}
    assert body["avg_latency_ms"] == 20.0
    # only the two entries inside the last 60 minutes land in the buckets
    assert sum(p["total"] for p in body["time_series"]) == 2
    assert sum(p["blocked"] for p in body["time_series"]) == 1
    assert [r["request_id"] for r in body["recent"]] == ["c", "b", "a"]
    # GDPR: the recent feed is metadata only — never content or decoded payloads.
    # A new field slipping into event_logger.build_entry must not flow through here.
    assert all(
        set(r) <= {"ts", "request_id", "allowed", "risk_level",
                   "flags", "elapsed_ms", "payload_len"}
        for r in body["recent"]
    )


def test_stats_tolerates_unparseable_timestamps(client: TestClient) -> None:
    entries = [_entry(request_id="bad", ts="not-a-timestamp")]
    with patch("warden.api.system.event_logger.load_entries", return_value=entries):
        resp = client.get("/api/stats")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


# ── check_redis_health (warden.cache) ─────────────────────────────────────────


def test_redis_health_disabled_reports_unavailable(monkeypatch) -> None:
    import warden.cache as cache
    monkeypatch.setattr(cache, "_REDIS_URL", "memory://", raising=False)
    assert cache.check_redis_health() == {"status": "unavailable", "latency_ms": None}


def test_redis_health_configured_but_unreachable(monkeypatch) -> None:
    import warden.cache as cache
    monkeypatch.setattr(cache, "_REDIS_URL", "redis://x:6379", raising=False)
    monkeypatch.setattr(cache, "_get_client", lambda: None, raising=False)
    out = cache.check_redis_health()
    assert out["status"].startswith("degraded")
    assert out["latency_ms"] is None


def test_redis_health_ok(monkeypatch) -> None:
    import warden.cache as cache

    class _FakeClient:
        def ping(self) -> bool:
            return True

    monkeypatch.setattr(cache, "_REDIS_URL", "redis://x:6379", raising=False)
    monkeypatch.setattr(cache, "_get_client", lambda: _FakeClient(), raising=False)
    out = cache.check_redis_health()
    assert out["status"] == "ok"
    assert isinstance(out["latency_ms"], float)


# ── /health/pipeline ──────────────────────────────────────────────────────────


def test_pipeline_health_shape(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(system_mod, "check_redis_health",
                        lambda: {"status": "unavailable", "latency_ms": None})
    with patch("warden.api.system.event_logger.journal_stats", return_value={"bounded": True}):
        resp = client.get("/health/pipeline")
    assert resp.status_code == 200
    body = resp.json()
    for key in ("status", "stages", "turso", "pqc", "journal", "degraded_stages"):
        assert key in body
    # the five import-probed stages plus brain/ers/decision are always reported
    assert {"topology", "obfuscation", "secrets", "semantic_rules",
            "brain", "causal", "phish", "ers", "decision"} <= set(body["stages"])
    assert "canary" not in body  # deep=false


def test_pipeline_health_deep_runs_canary(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(system_mod, "check_redis_health",
                        lambda: {"status": "ok", "latency_ms": 1.0})

    async def _fake_canary() -> dict:
        return {"available": True, "healthy": False}

    with patch("warden.observability.run_pipeline_canary", _fake_canary), \
         patch("warden.api.system.event_logger.journal_stats", return_value={"bounded": True}):
        resp = client.get("/health/pipeline", params={"deep": "true"})
    body = resp.json()
    assert body["canary"] == {"available": True, "healthy": False}
    assert "canary" in body["degraded_stages"]
    assert body["status"] == "degraded"


# ── /api/config ───────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _restore_state():
    """Config tests mutate the process-wide gateway_state + runtime singletons —
    snapshot and restore so a full-suite run isn't affected."""
    saved = dict(system_mod.runtime._slots)
    yield
    gateway_state.reset()
    system_mod.runtime._slots.update(saved)


def test_config_get_reports_live_knobs(client: TestClient) -> None:
    system_mod.runtime.publish(evolve=object())
    gateway_state.fail_strategy = "closed"
    gateway_state.set_uncertainty_lower(0.61)
    resp = client.get("/api/config")
    assert resp.status_code == 200
    body = resp.json()
    assert body["evolution_enabled"] is True
    assert body["fail_strategy"] == "closed"
    assert body["uncertainty_lower_threshold"] == 0.61
    assert "semantic_threshold" in body and "model_cache_dir" in body


def test_config_post_updates_uncertainty_and_rate_limit(client: TestClient) -> None:
    calls: list[int] = []
    with patch("warden.api.system.set_default_rate_limit", calls.append):
        resp = client.post("/api/config", json={
            "uncertainty_lower_threshold": 5.0,   # clamps to 0.99
            "rate_limit_per_minute": 120,
        })
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert gateway_state.uncertainty_lower == 0.99
    assert calls == [120]


def test_config_post_sets_guard_attributes_when_published(client: TestClient) -> None:
    class _Brain:
        threshold = 0.0

    class _Guard:
        strict = False

    brain, guard = _Brain(), _Guard()
    system_mod.runtime.publish(brain_guard=brain, guard=guard)
    resp = client.post("/api/config", json={"semantic_threshold": 2.0, "strict_mode": True})
    assert resp.status_code == 200
    assert brain.threshold == 1.0   # clamped to [0.1, 1.0]
    assert guard.strict is True


def test_config_post_empty_body_is_noop(client: TestClient) -> None:
    before = gateway_state.uncertainty_lower
    resp = client.post("/api/config", json={})
    assert resp.status_code == 200
    assert gateway_state.uncertainty_lower == before
