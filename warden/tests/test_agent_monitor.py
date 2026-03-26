"""
warden/tests/test_agent_monitor.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for warden/agent_monitor.py — AgentMonitor class.
Also covers the two new analytics API endpoints (agent-sessions).
"""
from __future__ import annotations

import json

import pytest

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def monitor(monkeypatch, tmp_path):
    """AgentMonitor with in-memory fallback only (no Redis, isolated sessions dir)."""
    monkeypatch.setenv("ANALYTICS_DATA_PATH", str(tmp_path))
    import warden.agent_monitor as am

    monkeypatch.setattr(am, "SESSIONS_PATH", tmp_path / "sessions.json")
    from warden.agent_monitor import AgentMonitor

    m = AgentMonitor()
    m._redis = None  # force in-memory fallback
    return m


@pytest.fixture()
def analytics_client(monkeypatch, tmp_path):
    """
    FastAPI TestClient for analytics/main.py with an isolated data directory.
    Returns (client, tmp_path) so tests can pre-populate sessions.json.
    """
    monkeypatch.setenv("ANALYTICS_DATA_PATH", str(tmp_path))
    import analytics.main as am

    monkeypatch.setattr(am, "SESSIONS_PATH", tmp_path / "sessions.json")
    from fastapi.testclient import TestClient

    return TestClient(am.app), tmp_path


# ── Core record ops ───────────────────────────────────────────────────────────


def test_record_request_creates_session(monitor):
    monitor.record_request("sess1", "req1", True, "low", [], "tenant-a")
    sess = monitor.get_session("sess1")
    assert sess is not None
    assert sess["session_id"] == "sess1"
    assert sess["request_count"] == 1
    assert sess["tenant_id"] == "tenant-a"


def test_record_request_increments_block_count(monitor):
    monitor.record_request("sess2", "req1", True, "low", [], "t")
    monitor.record_request("sess2", "req2", False, "high", ["jailbreak"], "t")
    sess = monitor.get_session("sess2")
    assert sess["block_count"] == 1


def test_record_request_accumulates_risk_score(monitor):
    monitor.record_request("sess3", "req1", False, "high", [], "t")
    monitor.record_request("sess3", "req2", False, "block", [], "t")
    sess = monitor.get_session("sess3")
    assert sess["risk_score"] > 0.0


def test_record_tool_event_adds_tool_names(monitor):
    monitor.record_tool_event("sess4", "read_file", "call", False, None)
    monitor.record_tool_event("sess4", "web_search", "call", False, None)
    sess = monitor.get_session("sess4")
    assert "read_file" in sess["tool_names_seen"]
    assert "web_search" in sess["tool_names_seen"]


def test_record_tool_event_no_duplicate_tool_names(monitor):
    monitor.record_tool_event("sess5", "bash", "call", False, None)
    monitor.record_tool_event("sess5", "bash", "call", False, None)
    sess = monitor.get_session("sess5")
    assert sess["tool_names_seen"].count("bash") == 1


def test_record_tool_event_increments_block_count(monitor):
    monitor.record_tool_event("sess6", "bash", "call", True, "shell_destruction")
    sess = monitor.get_session("sess6")
    assert sess["block_count"] >= 1


# ── TOOL_VELOCITY ─────────────────────────────────────────────────────────────


def test_tool_velocity_not_triggered_at_9_calls(monitor):
    for _ in range(9):
        monitor.record_tool_event("vel1", "read_file", "call", False, None)
    sess = monitor.get_session("vel1")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "TOOL_VELOCITY" not in patterns


def test_tool_velocity_triggered_at_11_calls(monitor):
    for _ in range(11):
        monitor.record_tool_event("vel2", "read_file", "call", False, None)
    sess = monitor.get_session("vel2")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "TOOL_VELOCITY" in patterns


# ── PRIVILEGE_ESCALATION ──────────────────────────────────────────────────────


def test_privilege_escalation_not_triggered_for_pure_reads(monitor):
    monitor.record_tool_event("priv1", "read_file", "call", False, None)   # cat 0
    monitor.record_tool_event("priv1", "query_db", "call", False, None)    # cat 0
    sess = monitor.get_session("priv1")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "PRIVILEGE_ESCALATION" not in patterns


def test_privilege_escalation_triggered_on_read_to_destructive(monitor):
    monitor.record_tool_event("priv2", "read_file", "call", False, None)  # cat 0
    monitor.record_tool_event("priv2", "bash", "call", False, None)        # cat 2
    sess = monitor.get_session("priv2")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "PRIVILEGE_ESCALATION" in patterns


# ── EVASION_ATTEMPT ───────────────────────────────────────────────────────────


def test_evasion_attempt_not_triggered_without_prior_block(monitor):
    monitor.record_tool_event("eva1", "bash", "call", False, None)
    monitor.record_tool_event("eva1", "bash", "call", False, None)
    sess = monitor.get_session("eva1")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "EVASION_ATTEMPT" not in patterns


def test_evasion_attempt_triggered_on_blocked_then_retry(monitor):
    monitor.record_tool_event("eva2", "bash", "call", True, "shell_destruction")  # blocked
    monitor.record_tool_event("eva2", "bash", "call", False, None)                 # retry
    sess = monitor.get_session("eva2")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "EVASION_ATTEMPT" in patterns


# ── EXFIL_CHAIN ───────────────────────────────────────────────────────────────


def test_exfil_chain_not_triggered_for_pure_reads(monitor):
    monitor.record_tool_event("ex1", "read_file", "call", False, None)   # cat 0
    monitor.record_tool_event("ex1", "web_search", "call", False, None)  # cat 0
    sess = monitor.get_session("ex1")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "EXFIL_CHAIN" not in patterns


def test_exfil_chain_triggered_on_read_then_network(monitor):
    monitor.record_tool_event("ex2", "read_file", "call", False, None)    # cat 0
    monitor.record_tool_event("ex2", "http_request", "call", False, None)  # cat 1
    sess = monitor.get_session("ex2")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "EXFIL_CHAIN" in patterns


# ── RAPID_BLOCK ───────────────────────────────────────────────────────────────


def test_rapid_block_not_triggered_at_2_blocks(monitor):
    monitor.record_request("rb1", "r1", False, "high", [], "t")
    monitor.record_request("rb1", "r2", False, "block", [], "t")
    sess = monitor.get_session("rb1")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "RAPID_BLOCK" not in patterns


def test_rapid_block_triggered_at_3_blocks(monitor):
    monitor.record_request("rb2", "r1", False, "high", [], "t")
    monitor.record_request("rb2", "r2", False, "block", [], "t")
    monitor.record_request("rb2", "r3", False, "high", [], "t")
    sess = monitor.get_session("rb2")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "RAPID_BLOCK" in patterns


# ── Session queries ───────────────────────────────────────────────────────────


def test_get_session_returns_none_for_unknown(monitor):
    assert monitor.get_session("no-such-session-xyz") is None


def test_list_sessions_returns_known_sessions(monitor):
    # Trigger RAPID_BLOCK to flush session to sessions.json
    monitor.record_request("ls1", "r1", False, "high", [], "t")
    monitor.record_request("ls1", "r2", False, "block", [], "t")
    monitor.record_request("ls1", "r3", False, "high", [], "t")
    sessions = monitor.list_sessions()
    assert any(s.get("session_id") == "ls1" for s in sessions)


def test_active_only_filters_old_sessions(monitor):
    """Sessions with old last_seen must be excluded when active_only=True."""
    import warden.agent_monitor as am

    old_meta = {
        "session_id":       "stale-session",
        "tenant_id":        "t",
        "first_seen":       "2020-01-01T00:00:00+00:00",
        "last_seen":        "2020-01-01T00:00:00+00:00",
        "request_count":    1,
        "block_count":      0,
        "risk_score":       0.0,
        "tool_names_seen":  [],
        "threats_detected": [],
    }
    am.SESSIONS_PATH.write_text(json.dumps(old_meta) + "\n", encoding="utf-8")
    sessions = monitor.list_sessions(active_only=True)
    assert not any(s.get("session_id") == "stale-session" for s in sessions)


# ── Redis fail-open ───────────────────────────────────────────────────────────


def test_redis_error_falls_back_to_memory(monitor):
    """With _redis = None, all operations should succeed via in-memory store."""
    assert monitor._redis is None  # fixture guarantees this
    monitor.record_request("redis-fb1", "r1", True, "low", [], "t")
    sess = monitor.get_session("redis-fb1")
    assert sess is not None
    assert sess["request_count"] == 1


def test_repeated_redis_failure_does_not_crash(monitor):
    """Multiple consecutive records without Redis should silently use memory."""
    for i in range(5):
        monitor.record_request("redis-fb2", f"r{i}", True, "low", [], "t")
    sess = monitor.get_session("redis-fb2")
    assert sess["request_count"] == 5


# ── sessions.json write / upsert ──────────────────────────────────────────────


def test_sessions_json_written_on_threat(monitor):
    """sessions.json must be created when a threat is first detected."""
    import warden.agent_monitor as am

    assert not am.SESSIONS_PATH.exists(), "file should not exist yet"
    # Trigger RAPID_BLOCK (3 blocked requests >= threshold of 3)
    monitor.record_request("jsn1", "r1", False, "high", [], "t")
    monitor.record_request("jsn1", "r2", False, "block", [], "t")
    monitor.record_request("jsn1", "r3", False, "high", [], "t")
    assert am.SESSIONS_PATH.exists(), "sessions.json should exist after threat detection"


def test_sessions_json_upsert_no_duplicate(monitor):
    """Writing the same session_id twice should update in-place, not append."""
    import warden.agent_monitor as am

    # First flush via RAPID_BLOCK
    for i in range(3):
        monitor.record_request("jsn2", f"r{i}", False, "block", [], "t")
    # Second flush via TOOL_VELOCITY (11 calls)
    for _ in range(11):
        monitor.record_tool_event("jsn2", "read_file", "call", False, None)

    lines = [
        ln.strip()
        for ln in am.SESSIONS_PATH.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    session_ids = [json.loads(ln).get("session_id") for ln in lines]
    assert session_ids.count("jsn2") == 1, "session_id must appear exactly once"


# ── ROGUE_AGENT pattern ───────────────────────────────────────────────────────


def test_rogue_agent_not_triggered_read_only(monitor):
    monitor.record_tool_event("rg1", "read_file", "call", False, None)
    monitor.record_tool_event("rg1", "web_search", "call", False, None)
    sess = monitor.get_session("rg1")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "ROGUE_AGENT" not in patterns


def test_rogue_agent_not_triggered_without_destructive(monitor):
    monitor.record_tool_event("rg2", "read_file", "call", False, None)   # cat 0
    monitor.record_tool_event("rg2", "http_post", "call", False, None)   # cat 1
    sess = monitor.get_session("rg2")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "ROGUE_AGENT" not in patterns


def test_rogue_agent_triggered_on_full_kill_chain(monitor):
    monitor.record_tool_event("rg3", "read_file", "call", False, None)   # cat 0
    monitor.record_tool_event("rg3", "http_post", "call", False, None)   # cat 1
    monitor.record_tool_event("rg3", "bash", "call", False, None)        # cat 2
    sess = monitor.get_session("rg3")
    patterns = [t["pattern"] for t in sess.get("threats_detected", [])]
    assert "ROGUE_AGENT" in patterns


def test_rogue_agent_detail_includes_last_destructive(monitor):
    monitor.record_tool_event("rg4", "web_search", "call", False, None)
    monitor.record_tool_event("rg4", "http_put", "call", False, None)
    monitor.record_tool_event("rg4", "python_repl", "call", False, None)
    sess = monitor.get_session("rg4")
    threat = next(t for t in sess["threats_detected"] if t["pattern"] == "ROGUE_AGENT")
    assert "python_repl" in threat["detail"]


def test_rogue_agent_severity_is_high(monitor):
    monitor.record_tool_event("rg5", "query_db", "call", False, None)
    monitor.record_tool_event("rg5", "write_file", "call", False, None)
    monitor.record_tool_event("rg5", "eval_code", "call", False, None)
    sess = monitor.get_session("rg5")
    threat = next(t for t in sess["threats_detected"] if t["pattern"] == "ROGUE_AGENT")
    assert threat["severity"] == "HIGH"


# ── Attestation chain ─────────────────────────────────────────────────────────


def test_attestation_token_set_on_first_tool_event(monitor):
    monitor.record_tool_event("at1", "read_file", "call", False, None)
    sess = monitor.get_session("at1")
    assert "attestation_token" in sess
    assert len(sess["attestation_token"]) == 32


def test_attestation_token_changes_with_each_event(monitor):
    monitor.record_tool_event("at2", "read_file", "call", False, None)
    token_after_1 = monitor.get_session("at2")["attestation_token"]
    monitor.record_tool_event("at2", "http_post", "call", False, None)
    token_after_2 = monitor.get_session("at2")["attestation_token"]
    assert token_after_1 != token_after_2


def test_attestation_token_is_deterministic(monitor):
    from warden.agent_monitor import _initial_token, _step_token

    session_id = "at3-det"
    monitor.record_tool_event(session_id, "read_file", "call", False, None)
    events = monitor.get_session(session_id)["events"]
    tool_events = [e for e in events if e["event_type"] == "tool"]

    # Replay manually
    token = _initial_token(session_id)
    for e in tool_events:
        token = _step_token(
            token,
            e["tool_name"],
            e["direction"],
            e["blocked"],
            e["ts"],
        )
    assert token == monitor.get_session(session_id)["attestation_token"]


def test_verify_attestation_valid_on_untampered_session(monitor):
    monitor.record_tool_event("at4", "read_file", "call", False, None)
    monitor.record_tool_event("at4", "http_post", "call", True, "ssrf")
    result = monitor.verify_attestation("at4")
    assert result["valid"] is True
    assert result["error"] == ""
    assert result["event_count"] == 2


def test_verify_attestation_session_not_found(monitor):
    result = monitor.verify_attestation("no-such-session-xyz-987")
    assert result["valid"] is False
    assert result["error"] == "session_not_found"


def test_verify_attestation_detects_tamper(monitor):

    session_id = "at5-tamper"
    monitor.record_tool_event(session_id, "read_file", "call", False, None)

    # Tamper: overwrite attestation_token in meta
    with monitor._fallback_lock:
        monitor._fallback[session_id]["meta"]["attestation_token"] = "deadbeefdeadbeef0000000000000000"

    result = monitor.verify_attestation(session_id)
    assert result["valid"] is False
    assert result["stored_token"] == "deadbeefdeadbeef0000000000000000"
    assert result["computed_token"] != "deadbeefdeadbeef0000000000000000"


# ── Kill-Switch ───────────────────────────────────────────────────────────────


def test_revoke_session_returns_revoked_true(monitor):
    result = monitor.revoke_session("ks1", "test_reason")
    assert result["revoked"] is True
    assert result["session_id"] == "ks1"
    assert result["reason"] == "test_reason"
    assert "revoked_at" in result


def test_is_revoked_false_before_revocation(monitor):
    monitor.record_tool_event("ks2", "read_file", "call", False, None)
    assert monitor.is_revoked("ks2") is False


def test_is_revoked_true_after_revocation(monitor):
    monitor.revoke_session("ks3", "suspicious_behaviour")
    assert monitor.is_revoked("ks3") is True


def test_is_revoked_false_for_unknown_session(monitor):
    assert monitor.is_revoked("no-such-session-ks-xyz") is False


def test_is_revoked_false_for_empty_session_id(monitor):
    assert monitor.is_revoked("") is False


def test_revoke_session_marks_meta(monitor):
    monitor.record_tool_event("ks4", "read_file", "call", False, None)
    monitor.revoke_session("ks4", "kill_chain_detected")
    sess = monitor.get_session("ks4")
    assert sess["revoked"] is True
    assert sess["revoke_reason"] == "kill_chain_detected"


def test_revoke_session_default_reason(monitor):
    result = monitor.revoke_session("ks5")
    assert result["reason"] == "admin_kill_switch"


def test_revoke_then_re_revoke_is_idempotent(monitor):
    monitor.revoke_session("ks6", "first")
    monitor.revoke_session("ks6", "second")
    assert monitor.is_revoked("ks6") is True


# ── Analytics endpoints ───────────────────────────────────────────────────────


def test_analytics_empty_sessions_returns_total_zero(analytics_client):
    client, _ = analytics_client
    resp = client.get("/api/v1/agent-sessions")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["sessions"] == []


def test_analytics_get_unknown_session_returns_404(analytics_client):
    client, _ = analytics_client
    resp = client.get("/api/v1/agent-sessions/no-such-session-xyz")
    assert resp.status_code == 404


def test_analytics_list_returns_correct_summaries(analytics_client):
    client, _ = analytics_client
    import analytics.main as am

    meta = {
        "session_id":       "test-sess-001",
        "tenant_id":        "t",
        "first_seen":       "2026-01-01T00:00:00+00:00",
        "last_seen":        "2026-01-01T01:00:00+00:00",
        "request_count":    3,
        "block_count":      1,
        "risk_score":       0.4,
        "tool_names_seen":  ["read_file"],
        "threats_detected": [],
    }
    am.SESSIONS_PATH.write_text(json.dumps(meta) + "\n", encoding="utf-8")

    resp = client.get("/api/v1/agent-sessions")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["sessions"][0]["session_id"] == "test-sess-001"


def test_analytics_get_session_returns_full_record(analytics_client):
    client, _ = analytics_client
    import analytics.main as am

    meta = {
        "session_id":       "test-sess-002",
        "tenant_id":        "t",
        "first_seen":       "2026-01-01T00:00:00+00:00",
        "last_seen":        "2026-01-01T01:00:00+00:00",
        "request_count":    1,
        "block_count":      0,
        "risk_score":       0.0,
        "tool_names_seen":  [],
        "threats_detected": [],
    }
    am.SESSIONS_PATH.write_text(json.dumps(meta) + "\n", encoding="utf-8")

    resp = client.get("/api/v1/agent-sessions/test-sess-002")
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == "test-sess-002"
    assert data["request_count"] == 1
