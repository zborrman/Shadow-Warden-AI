"""
SR-7.2 — coverage for warden/agent_monitor.py Redis paths + fail-open handlers.

The existing test_agent_monitor.py drives the in-memory fallback only. This file
pins the Redis-backed branches, the kill-switch/attestation paths, the fail-open
exception handlers (record_failopen telemetry), two pattern branches, and the
module-level sessions.json helpers.
"""
from __future__ import annotations

import pytest

# ── Fakes ─────────────────────────────────────────────────────────────────────

class _FakeRedis:
    """Minimal in-dict Redis stand-in covering the ops AgentMonitor uses."""

    def __init__(self):
        self.kv: dict = {}
        self.lists: dict = {}

    def ping(self):
        return True

    def get(self, k):
        return self.kv.get(k)

    def set(self, k, v, ex=None):
        self.kv[k] = v

    def delete(self, k):
        self.kv.pop(k, None)
        self.lists.pop(k, None)

    def exists(self, k):
        return 1 if k in self.kv else 0

    def rpush(self, k, v):
        self.lists.setdefault(k, []).append(v)

    def expire(self, k, ttl):
        return True

    def lrange(self, k, a, b):
        return list(self.lists.get(k, []))


class _BoomRedis:
    """Every operation raises — exercises the in-memory fallback + failopen paths."""

    def ping(self):
        return True

    def _boom(self, *a, **k):
        raise RuntimeError("redis down")

    get = set = delete = exists = rpush = expire = lrange = _boom


def _raise(_arg):
    raise RuntimeError("boom")


def _redis_monitor(tmp_path, monkeypatch, client):
    monkeypatch.setenv("ANALYTICS_DATA_PATH", str(tmp_path))
    import warden.agent_monitor as am
    monkeypatch.setattr(am, "SESSIONS_PATH", tmp_path / "sessions.json")
    m = am.AgentMonitor()
    m._redis = client
    return m


@pytest.fixture()
def monitor(monkeypatch, tmp_path):
    """In-memory-only AgentMonitor (mirrors test_agent_monitor.py)."""
    monkeypatch.setenv("ANALYTICS_DATA_PATH", str(tmp_path))
    import warden.agent_monitor as am
    monkeypatch.setattr(am, "SESSIONS_PATH", tmp_path / "sessions.json")
    m = am.AgentMonitor()
    m._redis = None
    return m


# ── Redis success paths ───────────────────────────────────────────────────────

class TestRedisBackedPaths:
    def test_full_cycle_over_redis(self, tmp_path, monkeypatch):
        m = _redis_monitor(tmp_path, monkeypatch, _FakeRedis())
        m.record_request("s-r", "req1", True, "low", [], "tenant-a")
        m.record_tool_event("s-r", "read_file", "call", False)
        m.record_tool_event("s-r", "web_fetch", "result", False)
        sess = m.get_session("s-r")
        assert sess is not None
        assert sess["session_id"] == "s-r"
        assert sess["events"]                       # events came back from redis lists

    def test_verify_attestation_valid_over_redis(self, tmp_path, monkeypatch):
        m = _redis_monitor(tmp_path, monkeypatch, _FakeRedis())
        m.record_request("s-att", "req1", True, "low", [], "t")
        m.record_tool_event("s-att", "read_file", "call", False)
        res = m.verify_attestation("s-att")
        assert res["valid"] is True
        assert res["error"] == ""
        assert res["event_count"] == 1

    def test_revoke_and_is_revoked_over_redis(self, tmp_path, monkeypatch):
        m = _redis_monitor(tmp_path, monkeypatch, _FakeRedis())
        m.record_request("s-rev", "req1", True, "low", [], "t")
        assert m.is_revoked("s-rev") is False
        out = m.revoke_session("s-rev", reason="kill")
        assert out["revoked"] is True
        assert m.is_revoked("s-rev") is True

    def test_verify_attestation_unknown_session(self, tmp_path, monkeypatch):
        m = _redis_monitor(tmp_path, monkeypatch, _FakeRedis())
        res = m.verify_attestation("ghost")
        assert res["valid"] is False and res["error"] == "session_not_found"

    def test_is_revoked_empty_session_is_false(self, tmp_path, monkeypatch):
        m = _redis_monitor(tmp_path, monkeypatch, _FakeRedis())
        assert m.is_revoked("") is False


# ── Redis failure → in-memory fallback + failopen telemetry ───────────────────

class TestRedisFailureFallback:
    def test_record_ops_fall_back_when_redis_raises(self, tmp_path, monkeypatch):
        m = _redis_monitor(tmp_path, monkeypatch, _BoomRedis())
        m.record_request("s-boom", "req1", True, "low", [], "t")
        m.record_tool_event("s-boom", "read_file", "call", False)
        sess = m.get_session("s-boom")
        assert sess is not None and sess["session_id"] == "s-boom"

    def test_is_revoked_failopen_records_telemetry(self, tmp_path, monkeypatch):
        m = _redis_monitor(tmp_path, monkeypatch, _BoomRedis())
        seen = {}
        import warden.agent_monitor as am
        monkeypatch.setattr(
            am, "record_failopen",
            lambda stage, reason, exc: seen.update(stage=stage),
        )
        # exists() raises → kill-switch fails OPEN (returns False) + records failopen.
        assert m.is_revoked("whatever") is False
        assert seen.get("stage") == "agent_monitor"

    def test_revoke_over_boom_redis_still_returns_status(self, tmp_path, monkeypatch):
        m = _redis_monitor(tmp_path, monkeypatch, _BoomRedis())
        out = m.revoke_session("s-boomrev", reason="x")
        assert out["revoked"] is True     # storage error logged, dict still returned


# ── _get_redis real-connection attempt ────────────────────────────────────────

def test_get_redis_bad_url_returns_none(monkeypatch):
    import warden.agent_monitor as am
    monkeypatch.setattr(am.settings, "redis_url", "redis://127.0.0.1:1")
    m = am.AgentMonitor()          # _redis is None → real connect attempt
    # from_url succeeds but ping() fails on the dead port → caught → None.
    assert m._get_redis() is None


# ── Fail-open exception handlers in record_* ──────────────────────────────────

class TestRecordFailOpen:
    def test_record_request_fails_open(self, monitor, monkeypatch):
        import warden.agent_monitor as am
        monkeypatch.setattr(am, "get_policy", _raise)
        assert monitor.record_request("s", "r", True, "low", [], "t") is None

    def test_record_tool_event_fails_open(self, monitor, monkeypatch):
        import warden.agent_monitor as am
        monkeypatch.setattr(am, "get_policy", _raise)
        assert monitor.record_tool_event("s", "read_file", "call", False) is None


# ── Pattern branch coverage ───────────────────────────────────────────────────

class TestPatternBranches:
    def test_unknown_tool_skipped_in_privilege_escalation(self, monitor):
        # An unknown tool has category -1 and must be skipped (continue), not crash.
        monitor.record_tool_event("s-esc", "totally_unknown_tool", "call", False)
        monitor.record_tool_event("s-esc", "read_file", "call", False)
        # A real leap read(0) -> destructive(2) then fires the pattern.
        threat = monitor.record_tool_event("s-esc", "bash", "call", False)
        assert threat is not None
        assert threat.pattern == "PRIVILEGE_ESCALATION"

    def test_injection_chain_detected(self, monitor):
        # A tool result blocked for injection, followed by another tool call.
        monitor.record_tool_event("s-inj", "web_fetch", "result", True, "indirect_injection")
        threat = monitor.record_tool_event("s-inj", "read_file", "call", False)
        assert threat is not None
        assert threat.pattern == "INJECTION_CHAIN"

    def test_worm_propagation_chain_detected(self, monitor):
        # A request flagged with a worm family, then an egress tool call → worm chain.
        monitor.record_request("s-worm", "req1", False, "block", ["ai_worm_replication"], "t")
        threat = monitor.record_tool_event("s-worm", "http_post", "call", False)
        assert threat is not None
        assert threat.pattern == "WORM_PROPAGATION_CHAIN"

    def test_worm_flag_without_propagation_does_not_fire(self, monitor):
        # Worm flag alone (no egress/destructive tool) must NOT emit the chain yet.
        threat = monitor.record_request(
            "s-worm2", "req1", False, "block", ["rag_poisoning"], "t"
        )
        assert threat is None or threat.pattern != "WORM_PROPAGATION_CHAIN"


# ── _tool_category / _is_expired ──────────────────────────────────────────────

class TestPureHelpers:
    def test_tool_category_from_threat_kind_destructive(self):
        import warden.agent_monitor as am
        assert am._tool_category("mystery_tool", "code_injection") == 2

    def test_tool_category_from_threat_kind_network(self):
        import warden.agent_monitor as am
        assert am._tool_category("mystery_tool", "ssrf") == 1

    def test_tool_category_unknown_is_negative_one(self):
        import warden.agent_monitor as am
        assert am._tool_category("mystery_tool", None) == -1

    def test_is_expired_true_for_old_timestamp(self):
        import warden.agent_monitor as am
        assert am._is_expired("2000-01-01T00:00:00+00:00") is True

    def test_is_expired_true_for_garbage(self):
        import warden.agent_monitor as am
        assert am._is_expired("not-a-date") is True

    def test_is_expired_false_for_now(self):
        import warden.agent_monitor as am
        assert am._is_expired(am._now_iso()) is False


# ── Public-method exception handlers ──────────────────────────────────────────

class TestMethodFailOpen:
    def test_get_session_returns_none_on_error(self, monitor, monkeypatch):
        monkeypatch.setattr(monitor, "_r_get_meta", _raise)
        assert monitor.get_session("s") is None

    def test_list_sessions_returns_empty_on_error(self, monitor, monkeypatch):
        import warden.agent_monitor as am
        monkeypatch.setattr(am, "_read_sessions_file", lambda: (_ for _ in ()).throw(OSError("x")))
        assert monitor.list_sessions() == []

    def test_verify_attestation_returns_error_on_exception(self, monitor, monkeypatch):
        monitor.record_request("s-va", "req1", True, "low", [], "t")

        def _boom(_sid):
            raise RuntimeError("events blew up")

        monkeypatch.setattr(monitor, "_r_get_events", _boom)
        res = monitor.verify_attestation("s-va")
        assert res["valid"] is False and res["error"]


# ── Module-level file helpers ──────────────────────────────────────────────────

class TestFileHelpers:
    def test_parse_ts_bad_value_returns_min(self):
        import warden.agent_monitor as am
        assert am._parse_ts("not-a-timestamp") == am.datetime.min.replace(tzinfo=am.UTC)

    def test_parse_ts_valid(self):
        import warden.agent_monitor as am
        assert am._parse_ts("2026-01-01T00:00:00+00:00").year == 2026

    def test_read_sessions_file_skips_blank_lines(self, tmp_path, monkeypatch):
        import warden.agent_monitor as am
        p = tmp_path / "sessions.json"
        p.write_text('{"session_id":"a"}\n\n   \n{"session_id":"b"}\n', encoding="utf-8")
        monkeypatch.setattr(am, "SESSIONS_PATH", p)
        rows = am._read_sessions_file()
        assert [r["session_id"] for r in rows] == ["a", "b"]

    def test_read_sessions_file_missing_returns_empty(self, tmp_path, monkeypatch):
        import warden.agent_monitor as am
        monkeypatch.setattr(am, "SESSIONS_PATH", tmp_path / "nope.json")
        assert am._read_sessions_file() == []

    def test_flush_session_summary_roundtrip(self, tmp_path, monkeypatch):
        import warden.agent_monitor as am
        p = tmp_path / "sessions.json"
        monkeypatch.setattr(am, "SESSIONS_PATH", p)
        am._flush_session_summary("s1", {"session_id": "s1", "request_count": 1})
        am._flush_session_summary("s1", {"session_id": "s1", "request_count": 2})  # upsert
        rows = am._read_sessions_file()
        assert len(rows) == 1 and rows[0]["request_count"] == 2
