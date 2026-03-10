"""
warden/tests/test_analytics_api.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for analytics/main.py — the standalone analytics HTTP service.

All tests mock ``analytics.main._load`` so no real log file is needed.
Coverage targets:
  • /health
  • /api/v1/events         (empty, filtered, paginated)
  • /api/v1/events/{id}    (found, 404)
  • /api/v1/stats          (empty log, with mixed entries)
  • /api/v1/attack-cost    (empty, no-blocked, with costs, by_risk, by_day)
  • /api/v1/threats        (empty, with flags, limit param)
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import analytics.main as _analytics_module
from analytics.main import app

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def aclient():
    """TestClient for the analytics FastAPI app."""
    with TestClient(app) as c:
        yield c


def _make_entry(
    *,
    request_id: str = "req-001",
    allowed: bool = True,
    risk_level: str = "low",
    elapsed_ms: float = 10.0,
    payload_tokens: int = 100,
    attack_cost_usd: float = 0.0,
    flags: list[str] | None = None,
    ts: str = "2026-03-09T12:00:00+00:00",
) -> dict:
    return {
        "request_id":    request_id,
        "allowed":       allowed,
        "risk_level":    risk_level,
        "elapsed_ms":    elapsed_ms,
        "payload_tokens": payload_tokens,
        "attack_cost_usd": attack_cost_usd,
        "flags":         flags or [],
        "ts":            ts,
    }


# ── /health ───────────────────────────────────────────────────────────────────


def test_health(aclient) -> None:
    resp = aclient.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "warden-analytics"


# ── /api/v1/events ────────────────────────────────────────────────────────────


def test_events_empty_log(aclient) -> None:
    with patch.object(_analytics_module, "_load", return_value=[]):
        resp = aclient.get("/api/v1/events")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["events"] == []


def test_events_returns_entries(aclient) -> None:
    entries = [_make_entry(request_id=f"req-{i:03d}") for i in range(5)]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/events")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["events"]) == 5


def test_events_limit(aclient) -> None:
    entries = [_make_entry(request_id=f"req-{i:03d}") for i in range(20)]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/events?limit=3")
    data = resp.json()
    assert data["total"] == 20
    assert len(data["events"]) == 3


def test_events_filter_allowed_true(aclient) -> None:
    entries = [
        _make_entry(request_id="r1", allowed=True),
        _make_entry(request_id="r2", allowed=False),
        _make_entry(request_id="r3", allowed=True),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/events?allowed=true")
    data = resp.json()
    assert data["total"] == 2
    assert all(e["allowed"] for e in data["events"])


def test_events_filter_allowed_false(aclient) -> None:
    entries = [
        _make_entry(request_id="r1", allowed=True),
        _make_entry(request_id="r2", allowed=False),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/events?allowed=false")
    data = resp.json()
    assert data["total"] == 1
    assert not data["events"][0]["allowed"]


def test_events_sorted_newest_first(aclient) -> None:
    entries = [
        _make_entry(request_id="old", ts="2026-03-01T00:00:00+00:00"),
        _make_entry(request_id="new", ts="2026-03-09T00:00:00+00:00"),
        _make_entry(request_id="mid", ts="2026-03-05T00:00:00+00:00"),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/events")
    events = resp.json()["events"]
    assert events[0]["request_id"] == "new"
    assert events[-1]["request_id"] == "old"


# ── /api/v1/events/{request_id} ───────────────────────────────────────────────


def test_get_event_found(aclient) -> None:
    entries = [
        _make_entry(request_id="abc-123"),
        _make_entry(request_id="xyz-999"),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/events/abc-123")
    assert resp.status_code == 200
    assert resp.json()["request_id"] == "abc-123"


def test_get_event_not_found(aclient) -> None:
    with patch.object(_analytics_module, "_load", return_value=[]):
        resp = aclient.get("/api/v1/events/no-such-id")
    assert resp.status_code == 404
    assert "no-such-id" in resp.json()["detail"]


# ── /api/v1/stats ─────────────────────────────────────────────────────────────


def test_stats_empty_log(aclient) -> None:
    with patch.object(_analytics_module, "_load", return_value=[]):
        resp = aclient.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["allowed"] == 0
    assert data["blocked"] == 0
    assert data["avg_latency_ms"] == 0.0


def test_stats_with_entries(aclient) -> None:
    entries = [
        _make_entry(request_id="r1", allowed=True,  elapsed_ms=10.0),
        _make_entry(request_id="r2", allowed=False, elapsed_ms=20.0),
        _make_entry(request_id="r3", allowed=True,  elapsed_ms=30.0),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/stats")
    data = resp.json()
    assert data["total"]   == 3
    assert data["allowed"] == 2
    assert data["blocked"] == 1
    assert data["avg_latency_ms"] == 20.0
    assert data["block_rate_pct"] == pytest.approx(33.33, abs=0.1)


def test_stats_by_day_grouping(aclient) -> None:
    entries = [
        _make_entry(request_id="a", allowed=True,  ts="2026-03-09T10:00:00+00:00"),
        _make_entry(request_id="b", allowed=False, ts="2026-03-09T11:00:00+00:00"),
        _make_entry(request_id="c", allowed=True,  ts="2026-03-08T09:00:00+00:00"),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/stats")
    by_day = resp.json()["by_day"]
    assert "2026-03-09" in by_day
    assert "2026-03-08" in by_day
    assert by_day["2026-03-09"]["total"] == 2
    assert by_day["2026-03-09"]["blocked"] == 1
    assert by_day["2026-03-08"]["blocked"] == 0


# ── /api/v1/attack-cost — empty / zero states ─────────────────────────────────


def test_attack_cost_empty_log(aclient) -> None:
    with patch.object(_analytics_module, "_load", return_value=[]):
        resp = aclient.get("/api/v1/attack-cost")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_blocked"] == 0
    assert data["total_attack_cost_usd"] == 0.0
    assert data["avg_cost_per_attack"]   == 0.0
    assert data["total_tokens_blocked"]  == 0
    assert data["costliest_attack_usd"]  == 0.0
    assert data["by_risk_level"] == {}
    assert data["by_day"]        == {}


def test_attack_cost_only_allowed_no_cost(aclient) -> None:
    """All entries allowed → blocked = 0, all cost fields are zero."""
    entries = [
        _make_entry(request_id="r1", allowed=True, attack_cost_usd=0.05),
        _make_entry(request_id="r2", allowed=True, attack_cost_usd=0.10),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/attack-cost")
    data = resp.json()
    assert data["total_requests"] == 2
    assert data["total_blocked"]  == 0
    assert data["total_attack_cost_usd"] == 0.0


# ── /api/v1/attack-cost — cost calculations ───────────────────────────────────


def test_attack_cost_totals(aclient) -> None:
    """total_attack_cost_usd, avg_cost_per_attack, costliest_attack_usd."""
    entries = [
        _make_entry(request_id="b1", allowed=False, attack_cost_usd=0.000400, payload_tokens=400),
        _make_entry(request_id="b2", allowed=False, attack_cost_usd=0.000200, payload_tokens=200),
        _make_entry(request_id="b3", allowed=False, attack_cost_usd=0.000100, payload_tokens=100),
        _make_entry(request_id="a1", allowed=True,  attack_cost_usd=0.001000, payload_tokens=999),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/attack-cost")
    data = resp.json()

    assert data["total_requests"]   == 4
    assert data["total_blocked"]    == 3
    assert data["total_tokens_blocked"] == 700   # 400 + 200 + 100

    total = 0.000400 + 0.000200 + 0.000100
    # The endpoint rounds to 8 decimal places; use abs=1e-6 to absorb that
    assert data["total_attack_cost_usd"] == pytest.approx(total,        abs=1e-6)
    assert data["avg_cost_per_attack"]   == pytest.approx(total / 3,    abs=1e-6)
    assert data["costliest_attack_usd"]  == pytest.approx(0.000400,     abs=1e-6)


def test_attack_cost_missing_fields_fallback(aclient) -> None:
    """Entries without attack_cost_usd / payload_tokens default to 0."""
    entries = [
        {"request_id": "x1", "allowed": False, "ts": "2026-03-09T00:00:00+00:00"},
        {"request_id": "x2", "allowed": False, "ts": "2026-03-09T01:00:00+00:00",
         "attack_cost_usd": 0.0005, "payload_tokens": 500},
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/attack-cost")
    data = resp.json()
    assert data["total_blocked"] == 2
    assert data["total_tokens_blocked"] == 500
    assert data["total_attack_cost_usd"] == pytest.approx(0.0005, abs=1e-9)


# ── /api/v1/attack-cost — by_risk_level breakdown ────────────────────────────


def test_attack_cost_by_risk_level(aclient) -> None:
    entries = [
        _make_entry(request_id="h1", allowed=False, risk_level="high",  attack_cost_usd=0.001, payload_tokens=100),
        _make_entry(request_id="h2", allowed=False, risk_level="high",  attack_cost_usd=0.002, payload_tokens=200),
        _make_entry(request_id="b1", allowed=False, risk_level="block", attack_cost_usd=0.003, payload_tokens=300),
        _make_entry(request_id="a1", allowed=True,  risk_level="low",   attack_cost_usd=0.999),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/attack-cost")
    by_risk = resp.json()["by_risk_level"]

    assert set(by_risk.keys()) == {"high", "block"}
    assert by_risk["high"]["count"] == 2
    assert by_risk["high"]["total_tokens"] == 300
    assert by_risk["high"]["total_cost_usd"] == pytest.approx(0.003, abs=1e-9)
    assert by_risk["block"]["count"] == 1
    assert by_risk["block"]["total_tokens"] == 300
    assert by_risk["block"]["total_cost_usd"] == pytest.approx(0.003, abs=1e-9)


def test_attack_cost_by_risk_level_single(aclient) -> None:
    entries = [
        _make_entry(request_id="h1", allowed=False, risk_level="high", attack_cost_usd=0.0005),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/attack-cost")
    by_risk = resp.json()["by_risk_level"]
    assert "high" in by_risk
    assert by_risk["high"]["count"] == 1


# ── /api/v1/attack-cost — by_day time-series ─────────────────────────────────


def test_attack_cost_by_day(aclient) -> None:
    entries = [
        _make_entry(request_id="d1", allowed=False, attack_cost_usd=0.001,
                    ts="2026-03-07T10:00:00+00:00"),
        _make_entry(request_id="d2", allowed=False, attack_cost_usd=0.002,
                    ts="2026-03-07T11:00:00+00:00"),
        _make_entry(request_id="d3", allowed=False, attack_cost_usd=0.004,
                    ts="2026-03-09T08:00:00+00:00"),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/attack-cost")
    by_day = resp.json()["by_day"]

    assert "2026-03-07" in by_day
    assert "2026-03-09" in by_day
    assert by_day["2026-03-07"]["count"] == 2
    assert by_day["2026-03-07"]["total_cost_usd"] == pytest.approx(0.003, abs=1e-9)
    assert by_day["2026-03-09"]["count"] == 1
    assert by_day["2026-03-09"]["total_cost_usd"] == pytest.approx(0.004, abs=1e-9)


def test_attack_cost_by_day_sorted(aclient) -> None:
    """by_day keys must be returned in ascending chronological order."""
    entries = [
        _make_entry(request_id="z", allowed=False, ts="2026-03-09T00:00:00+00:00"),
        _make_entry(request_id="a", allowed=False, ts="2026-03-07T00:00:00+00:00"),
        _make_entry(request_id="m", allowed=False, ts="2026-03-08T00:00:00+00:00"),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/attack-cost")
    days = list(resp.json()["by_day"].keys())
    assert days == sorted(days)


def test_attack_cost_days_param(aclient) -> None:
    """days query parameter must be forwarded to _load."""
    captured = {}

    def fake_load(days=None):
        captured["days"] = days
        return []

    with patch.object(_analytics_module, "_load", side_effect=fake_load):
        aclient.get("/api/v1/attack-cost?days=14")

    assert captured["days"] == 14


# ── /api/v1/threats ───────────────────────────────────────────────────────────


def test_threats_empty_log(aclient) -> None:
    with patch.object(_analytics_module, "_load", return_value=[]):
        resp = aclient.get("/api/v1/threats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_flags"] == 0
    assert data["threats"] == []


def test_threats_counts(aclient) -> None:
    entries = [
        _make_entry(request_id="r1", flags=["jailbreak", "prompt_injection"]),
        _make_entry(request_id="r2", flags=["jailbreak"]),
        _make_entry(request_id="r3", flags=["shell_cmd"]),
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/threats")
    data = resp.json()
    assert data["total_flags"] == 4
    # Top threat should be jailbreak (count 2)
    assert data["threats"][0]["flag"] == "jailbreak"
    assert data["threats"][0]["count"] == 2


def test_threats_limit(aclient) -> None:
    entries = [
        _make_entry(request_id=f"r{i}", flags=[f"threat_{i}"]) for i in range(10)
    ]
    with patch.object(_analytics_module, "_load", return_value=entries):
        resp = aclient.get("/api/v1/threats?limit=3")
    data = resp.json()
    assert len(data["threats"]) == 3
