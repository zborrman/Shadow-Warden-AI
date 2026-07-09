"""
GSAM PR 2 — ingest taps + API tests (GSAM-02).

Covers:
  • All 5 taps emit the correct GDPR-safe metadata (no content fields).
  • Each tap is fail-open: exceptions are swallowed, never raised to callers.
  • POST /gsam/observations returns 202 for valid sensor payloads.
  • GET  /gsam/health returns 200 with queue counters.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import warden.gsam.ingest as _ingest_mod
from warden.gsam.ingest import (
    tap_agent_span,
    tap_billing_event,
    tap_marketplace_action,
    tap_mcp_call,
    tap_token_cost,
)

# ── helpers ────────────────────────────────────────────────────────────────────

class _CaptureQueue:
    """Records every row passed to gsam_emit."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def __call__(self, row: dict) -> None:
        self.rows.append(row)


@pytest.fixture()
def captured(monkeypatch: pytest.MonkeyPatch) -> _CaptureQueue:
    """Redirect gsam_emit (as seen by ingest.py) to an in-process recorder."""
    cap = _CaptureQueue()
    # Patch the name in ingest.py's module namespace — this is where _emit()
    # looks up gsam_emit at call time (module-global, not closure).
    monkeypatch.setattr(_ingest_mod, "gsam_emit", cap)
    return cap


# ── tap_agent_span ─────────────────────────────────────────────────────────────

def test_tap_agent_span_basic(captured: _CaptureQueue) -> None:
    record = {
        "event":         "agent_end",
        "agent_id":      "ag-001",
        "tenant_id":     "t-1",
        "model":         "claude-haiku-4-5-20251001",
        "input_tokens":  100,
        "output_tokens": 50,
        "cost_usd":      0.0004,
        "latency_ms":    123.4,
        "status":        "ok",
        "tool_name":     "resolve_ticket_kb",
        "detail":        "this is private content that must never flow into GSAM",
    }
    tap_agent_span(record)
    assert len(captured.rows) == 1
    row = captured.rows[0]
    assert row["agent_id"] == "ag-001"
    assert row["model"] == "claude-haiku-4-5-20251001"
    assert row["input_tokens"] == 100
    assert row["output_tokens"] == 50
    assert row["payload_kind"] == "agent_span"
    # GDPR: `detail` must never appear in the observation row
    assert "detail" not in row
    assert "private content" not in str(row)


def test_tap_agent_span_missing_fields(captured: _CaptureQueue) -> None:
    """Partial record (e.g. agent_start span) must not raise."""
    tap_agent_span({"event": "agent_start"})
    assert len(captured.rows) == 1
    assert captured.rows[0]["agent_id"] == ""


def test_tap_agent_span_fail_open() -> None:
    """Exception inside gsam_emit must not propagate."""
    def _boom(row: dict) -> None:
        raise RuntimeError("clickhouse down")

    monkeypatch_target = _ingest_mod
    with patch.object(monkeypatch_target, "gsam_emit", _boom):
        tap_agent_span({"event": "agent_end", "agent_id": "x"})  # must not raise


# ── tap_token_cost ─────────────────────────────────────────────────────────────

def test_tap_token_cost_basic(captured: _CaptureQueue) -> None:
    tap_token_cost("t-2", "ag-002", "screen_sanctions_list", "claude-sonnet-5", 200, 80, 0.0045)
    assert len(captured.rows) == 1
    row = captured.rows[0]
    assert row["tenant_id"] == "t-2"
    assert row["agent_id"] == "ag-002"
    assert row["event"] == "token_cost"
    assert row["payload_kind"] == "screen_sanctions_list"
    assert row["input_tokens"] == 200
    assert row["output_tokens"] == 80
    assert abs(row["execution_cost"] - 0.0045) < 1e-9


def test_tap_token_cost_fail_open() -> None:
    with patch.object(_ingest_mod, "gsam_emit", side_effect=OSError("disk full")):
        tap_token_cost("t", "a", "act", "m", 0, 0, 0.0)  # must not raise


# ── tap_billing_event ──────────────────────────────────────────────────────────

def test_tap_billing_event_basic(captured: _CaptureQueue) -> None:
    entry = {
        "entry_id":      "entry-xyz",
        "event_type":    "STAFF_CALL",
        "tenant_id":     "t-3",
        "agent_id":      "ag-003",
        "model":         "claude-haiku-4-5-20251001",
        "input_tokens":  10,
        "output_tokens": 5,
        "cost_usd":      0.000024,
    }
    tap_billing_event(entry)
    assert len(captured.rows) == 1
    row = captured.rows[0]
    assert row["event"] == "billing_event"
    assert row["payload_kind"] == "STAFF_CALL"
    assert row["trace_id"] == "entry-xyz"
    assert row["tenant_id"] == "t-3"


def test_tap_billing_event_fail_open() -> None:
    with patch.object(_ingest_mod, "gsam_emit", side_effect=ValueError("bad")):
        tap_billing_event({"event_type": "STAFF_CALL"})  # must not raise


# ── tap_marketplace_action ─────────────────────────────────────────────────────

def test_tap_marketplace_action_dispatched(captured: _CaptureQueue) -> None:
    tap_marketplace_action("search", "ag-004", "t-4", dispatched=True)
    assert len(captured.rows) == 1
    row = captured.rows[0]
    assert row["event"] == "marketplace_action"
    assert row["payload_kind"] == "search"
    assert row["agent_id"] == "ag-004"
    assert row["status"] == "dispatched"


def test_tap_marketplace_action_no_handler(captured: _CaptureQueue) -> None:
    tap_marketplace_action("unknown_op", "ag-005", "", dispatched=False)
    assert len(captured.rows) == 1
    assert captured.rows[0]["status"] == "no_handler"


def test_tap_marketplace_action_fail_open() -> None:
    with patch.object(_ingest_mod, "gsam_emit", side_effect=Exception("redis gone")):
        tap_marketplace_action("search", "a", "t", True)  # must not raise


# ── tap_mcp_call ───────────────────────────────────────────────────────────────

def test_tap_mcp_call_basic(captured: _CaptureQueue) -> None:
    tap_mcp_call("screen_sanctions_list", "ag-006", 0.05)
    assert len(captured.rows) == 1
    row = captured.rows[0]
    assert row["event"] == "mcp_call"
    assert row["payload_kind"] == "screen_sanctions_list"
    assert row["agent_id"] == "ag-006"
    assert abs(row["execution_cost"] - 0.05) < 1e-9


def test_tap_mcp_call_fail_open() -> None:
    with patch.object(_ingest_mod, "gsam_emit", side_effect=ConnectionError("timeout")):
        tap_mcp_call("get_ticket", "a", 0.001)  # must not raise


# ── REST API surface ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client() -> TestClient:
    from fastapi import FastAPI

    from warden.gsam.api import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


# Header that satisfies the Pro-tier gate (gsam_enabled=True for Pro+)
_PRO_HEADERS = {"X-Tenant-Tier": "pro"}


def test_gsam_health(client: TestClient) -> None:
    resp = client.get("/gsam/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "queue_depth" in data


def test_gsam_ingest_observation_accepted(client: TestClient, captured: _CaptureQueue) -> None:
    payload = {
        "agent_id":        "sensor-001",
        "tenant_id":       "t-sensor",
        "event":           "sensor_report",
        "payload_kind":    "ebpf_syscall",
        "latency_ms":      1.2,
        "syscalls_count":  5,
        "scan_verdict":    "CLEAN",
    }
    resp = client.post("/gsam/observations", json=payload, headers=_PRO_HEADERS)
    assert resp.status_code == 202
    body = resp.json()
    assert body["accepted"] is True
    assert body["agent_id"] == "sensor-001"


def test_gsam_ingest_rejects_unknown_fields(client: TestClient) -> None:
    """extra='forbid' — unknown fields must be rejected with 422."""
    resp = client.post("/gsam/observations", json={
        "agent_id": "sensor-002",
        "content":  "this should not be accepted",
    }, headers=_PRO_HEADERS)
    assert resp.status_code == 422


def test_gsam_ingest_missing_agent_id(client: TestClient) -> None:
    resp = client.post("/gsam/observations", json={"tenant_id": "t-x"}, headers=_PRO_HEADERS)
    assert resp.status_code == 422


def test_gsam_ingest_gated_without_tier(client: TestClient) -> None:
    """No tier header → starter tier → gsam_enabled=False → 403."""
    payload = {"agent_id": "sensor-003"}
    resp = client.post("/gsam/observations", json=payload)
    assert resp.status_code == 403
