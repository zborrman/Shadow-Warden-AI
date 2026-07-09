"""GSAM PR 4 — agent quarantine (GSAM-04).

No Docker/Redis: quarantine uses the in-process fallback under REDIS_URL=memory://,
and the log persists to a tmp_path SQLite ``gsam`` DB. Also verifies the drift
trigger, the marketplace + staff dispatch gates, and that the STAFF-01/02
boundary + velocity checks still run when an agent is quarantined.
"""
from __future__ import annotations

import sqlite3

import pytest

from warden.config import settings
from warden.gsam import drift as _drift
from warden.gsam import quarantine as _q


@pytest.fixture()
def gsam_env(tmp_path, monkeypatch):
    db = tmp_path / "gsam.db"
    monkeypatch.setattr(settings, "gsam_db_path", str(db))
    monkeypatch.setattr(settings, "gsam_quarantine_ttl_s", 3600)
    monkeypatch.setattr(settings, "gsam_drift_lambda", 0.2)
    monkeypatch.setattr(settings, "gsam_drift_quarantine_threshold", 0.85)
    _q._mem.clear()
    _drift._mem.clear()
    yield str(db)
    _q._mem.clear()
    _drift._mem.clear()


# ── core flag lifecycle ──────────────────────────────────────────────────────────

def test_quarantine_and_check(gsam_env) -> None:
    assert _q.is_quarantined("agent-a") is False
    assert _q.quarantine("agent-a", reason="test") is True
    assert _q.is_quarantined("agent-a") is True


def test_release_clears_flag(gsam_env) -> None:
    _q.quarantine("agent-b", reason="test")
    assert _q.is_quarantined("agent-b") is True
    _q.release("agent-b")
    assert _q.is_quarantined("agent-b") is False


def test_quarantine_empty_agent_noop(gsam_env) -> None:
    assert _q.quarantine("") is False
    assert _q.is_quarantined("") is False


def test_quarantine_ttl_expiry(gsam_env) -> None:
    _q.quarantine("agent-c", reason="test", ttl_s=0)
    # ttl 0 → immediately expired in the in-process fallback
    assert _q.is_quarantined("agent-c") is False


def test_quarantine_logged_to_sqlite(gsam_env) -> None:
    _q.quarantine("agent-d", reason="drift_threshold", drift_score=0.92)
    con = sqlite3.connect(gsam_env)
    row = con.execute(
        "SELECT reason, drift_score, released_at FROM gsam_quarantine_log "
        "WHERE agent_id = ?", ("agent-d",)
    ).fetchone()
    con.close()
    assert row is not None
    assert row[0] == "drift_threshold"
    assert row[1] == pytest.approx(0.92)
    assert row[2] == ""  # not released


def test_release_marks_log(gsam_env) -> None:
    _q.quarantine("agent-e", reason="test")
    _q.release("agent-e")
    con = sqlite3.connect(gsam_env)
    released = con.execute(
        "SELECT released_at FROM gsam_quarantine_log WHERE agent_id = ?", ("agent-e",)
    ).fetchone()[0]
    con.close()
    assert released != ""


def test_list_active(gsam_env) -> None:
    _q.quarantine("agent-f", reason="test")
    _q.quarantine("agent-g", reason="test")
    _q.release("agent-g")
    active = _q.list_active()
    ids = {a["agent_id"] for a in active}
    assert "agent-f" in ids
    assert "agent-g" not in ids


def test_is_quarantined_fail_open(gsam_env, monkeypatch) -> None:
    """A Redis client that raises on exists() must yield False, not an error."""
    class _BoomRedis:
        def exists(self, *_a):
            raise RuntimeError("redis down")

    monkeypatch.setattr(_q, "_redis", lambda: _BoomRedis())
    # No in-process flag set → fail-open to False
    assert _q.is_quarantined("agent-h") is False


# ── drift trigger ────────────────────────────────────────────────────────────────

def test_drift_threshold_triggers_quarantine(gsam_env) -> None:
    agent = "drift-agent"
    # Establish a baseline.
    _drift.update_drift(agent, [{"event": "mcp_call"}] * 10)
    assert _q.is_quarantined(agent) is False
    # Present novel behaviour every round so the weighted-cosine distance stays
    # maximal (each label is unseen → orthogonal); EWMA climbs past 0.85.
    for i in range(30):
        _drift.update_drift(agent, [{"event": f"novel_event_{i}"}] * 10)
        if _q.is_quarantined(agent):
            break
    assert _q.is_quarantined(agent) is True


# ── marketplace dispatch gate ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_marketplace_gate_blocks_quarantined(gsam_env, monkeypatch) -> None:
    from fastapi import BackgroundTasks
    from starlette.requests import Request

    from warden.marketplace import api as mkt

    _q.quarantine("bad-buyer", reason="test")

    body = mkt.MarketAction(action_type="search", payload={"agent_id": "bad-buyer", "query": "x"})
    scope = {"type": "http", "headers": [], "method": "POST", "path": "/marketplace/action"}
    req = Request(scope)
    resp = await mkt.dispatch_action(body, req, BackgroundTasks())
    assert resp.get("gsam_quarantined") is True
    assert resp["agent_id"] == "bad-buyer"


# ── staff dispatch gate + STAFF invariant regression ─────────────────────────────

@pytest.mark.asyncio
async def test_staff_dispatch_refuses_quarantined(gsam_env, monkeypatch) -> None:
    from warden.staff import dispatcher

    calls = {"boundary": 0, "velocity": 0}

    class _FakeBoundary:
        max_calls_per_hour = 100
        loop_detection_window_s = 60
        loop_detection_max = 10

    class _FakeRegistry:
        def check_and_dispatch(self, agent_id, tool_name):
            calls["boundary"] += 1
            return _FakeBoundary()

    def _fake_velocity_init(self, redis=None):
        pass

    def _fake_record_and_check(self, *a, **k):
        calls["velocity"] += 1
        return None

    monkeypatch.setattr(dispatcher, "get_registry", lambda redis=None: _FakeRegistry())
    monkeypatch.setattr(dispatcher.VelocityGuard, "__init__", _fake_velocity_init)
    monkeypatch.setattr(dispatcher.VelocityGuard, "record_and_check", _fake_record_and_check)

    _q.quarantine("staff-agent", reason="test")

    result = await dispatcher.staff_dispatch("staff-agent", "get_ticket", {"ticket_id": "1"})
    assert result.get("gsam_quarantined") is True
    # STAFF-01/02 invariants: boundary + velocity checks still ran (added, not replaced)
    assert calls["boundary"] == 1
    assert calls["velocity"] == 1


# ── REST endpoints ───────────────────────────────────────────────────────────────

def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.gsam.api import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


_PRO_HEADERS = {"X-Tenant-Tier": "pro"}


def test_list_quarantine_endpoint(gsam_env) -> None:
    _q.quarantine("api-agent", reason="test")
    resp = _client().get("/gsam/quarantine", headers=_PRO_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] >= 1
    assert any(a["agent_id"] == "api-agent" for a in data["agents"])


def test_release_endpoint_requires_admin(gsam_env, monkeypatch) -> None:
    monkeypatch.setenv("ADMIN_KEY", "secret-admin")
    _q.quarantine("api-agent-2", reason="test")
    client = _client()

    # Missing / wrong admin key → 403
    bad = client.post("/gsam/quarantine/api-agent-2/release", headers=_PRO_HEADERS)
    assert bad.status_code == 403
    assert _q.is_quarantined("api-agent-2") is True

    # Correct admin key → released
    ok = client.post(
        "/gsam/quarantine/api-agent-2/release",
        headers={**_PRO_HEADERS, "X-Admin-Key": "secret-admin"},
    )
    assert ok.status_code == 200
    assert ok.json()["released"] is True
    assert _q.is_quarantined("api-agent-2") is False
