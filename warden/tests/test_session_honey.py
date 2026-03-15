"""
warden/tests/test_session_honey.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for:
  - warden.session_guard.SessionGuard  (incremental injection detection)
  - warden.honey.HoneyEngine           (deception technology)
  - warden.telemetry                   (OTel no-op path)
"""
from __future__ import annotations

import json

import pytest

# ── Fixtures ──────────────────────────────────────────────────────────────────

class _FakeRedis:
    """Minimal in-memory Redis stub for unit tests."""

    def __init__(self):
        self._store: dict[str, list[bytes]] = {}
        self._strings: dict[str, bytes] = {}
        self._ttls: dict[str, int] = {}

    # List operations
    def rpush(self, key: str, value: str) -> int:
        lst = self._store.setdefault(key, [])
        lst.append(value.encode() if isinstance(value, str) else value)
        return len(lst)

    def ltrim(self, key: str, start: int, end: int) -> None:
        lst = self._store.get(key, [])
        if end < 0:
            end = len(lst) + end + 1
        self._store[key] = lst[max(0, start):end]

    def expire(self, key: str, ttl: int) -> None:
        self._ttls[key] = ttl

    def lrange(self, key: str, start: int, end: int) -> list[bytes]:
        lst = self._store.get(key, [])
        if end == -1:
            return list(lst)
        return list(lst[start:end + 1])

    def delete(self, key: str) -> None:
        self._store.pop(key, None)
        self._strings.pop(key, None)

    def pipeline(self):
        return _FakePipeline(self)

    # String operations
    def setex(self, key: str, ttl: int, value) -> None:
        self._strings[key] = value.encode() if isinstance(value, str) else value
        self._ttls[key] = ttl

    def get(self, key: str):
        return self._strings.get(key)


class _FakePipeline:
    """Collects pipeline calls and replays them on execute()."""

    def __init__(self, redis: _FakeRedis):
        self._r = redis
        self._ops: list = []

    def rpush(self, key, value):
        self._ops.append(("rpush", key, value))
        return self

    def ltrim(self, key, start, end):
        self._ops.append(("ltrim", key, start, end))
        return self

    def expire(self, key, ttl):
        self._ops.append(("expire", key, ttl))
        return self

    def execute(self):
        for op in self._ops:
            if op[0] == "rpush":
                self._r.rpush(op[1], op[2])
            elif op[0] == "ltrim":
                self._r.ltrim(op[1], op[2], op[3])
            elif op[0] == "expire":
                self._r.expire(op[1], op[2])
        return []


@pytest.fixture
def fake_redis():
    return _FakeRedis()


@pytest.fixture
def session_guard(fake_redis):
    from warden.session_guard import SessionGuard
    return SessionGuard(fake_redis)


@pytest.fixture
def honey_engine(fake_redis):
    from warden.honey import HoneyEngine
    return HoneyEngine(fake_redis)


# ── SessionGuard tests ────────────────────────────────────────────────────────

class TestSessionGuard:

    def test_single_low_risk_no_escalation(self, session_guard):
        """A single low-risk message should never escalate."""
        result = session_guard.record_and_check("sess-1", "low", [], "req-1")
        assert result.escalated is False
        assert result.cumulative_score == 0.0
        assert result.message_count == 1

    def test_single_medium_no_escalation(self, session_guard):
        """One MEDIUM message is below the 3-message limit."""
        result = session_guard.record_and_check("sess-2", "medium", ["PROMPT_INJECTION"], "req-1")
        assert result.escalated is False
        assert result.cumulative_score == 1.0

    def test_three_medium_messages_escalate(self, session_guard):
        """Three MEDIUM messages in a session should trigger escalation."""
        sid = "sess-medium-3"
        for i in range(2):
            r = session_guard.record_and_check(sid, "medium", ["PROMPT_INJECTION"], f"req-{i}")
            assert r.escalated is False
        # Third medium message — should escalate
        result = session_guard.record_and_check(sid, "medium", ["PROMPT_INJECTION"], "req-3")
        assert result.escalated is True
        assert result.pattern  # any escalation reason is acceptable

    def test_cumulative_score_threshold(self, session_guard):
        """One HIGH (score=2.0) and one MEDIUM (score=1.0) = 3.0 >= threshold of 2.5."""
        sid = "sess-score"
        session_guard.record_and_check(sid, "high", ["JAILBREAK_ATTEMPT"], "req-1")
        result = session_guard.record_and_check(sid, "medium", ["PROMPT_INJECTION"], "req-2")
        assert result.escalated is True
        assert result.cumulative_score >= 2.5
        assert "Cumulative" in result.pattern

    def test_two_high_risk_messages_escalate(self, session_guard):
        """Two HIGH/BLOCK messages in a session should escalate."""
        sid = "sess-two-high"
        session_guard.record_and_check(sid, "high", ["JAILBREAK_ATTEMPT"], "req-1")
        result = session_guard.record_and_check(sid, "block", ["HARMFUL_CONTENT"], "req-2")
        assert result.escalated is True
        assert result.cumulative_score >= 4.0   # 2.0 + 3.0 = 5.0

    def test_fail_open_on_redis_error(self):
        """If Redis raises an exception, SessionGuard should fail-open (not escalate)."""
        class BrokenRedis:
            def pipeline(self):
                raise RuntimeError("Redis down")

        from warden.session_guard import SessionGuard
        guard = SessionGuard(BrokenRedis())
        result = guard.record_and_check("sess-broken", "high", [], "req-1")
        assert result.escalated is False
        assert result.cumulative_score == 0.0

    def test_clear_resets_session(self, session_guard, fake_redis):
        """clear() should delete the session key from Redis."""
        sid = "sess-clear"
        session_guard.record_and_check(sid, "medium", [], "req-1")
        key = f"warden:session:{sid}:history"
        assert len(fake_redis.lrange(key, 0, -1)) == 1
        session_guard.clear(sid)
        assert len(fake_redis.lrange(key, 0, -1)) == 0

    def test_disabled_guard_never_escalates(self, fake_redis, monkeypatch):
        """SESSION_GUARD_ENABLED=false should always return escalated=False."""
        monkeypatch.setenv("SESSION_GUARD_ENABLED", "false")
        # Re-import to pick up the env change
        import importlib

        import warden.session_guard as sg_mod
        importlib.reload(sg_mod)
        guard = sg_mod.SessionGuard(fake_redis)
        # Even with HIGH risk level, should not escalate
        result = guard.record_and_check("sess-x", "high", [], "req-1")
        assert result.escalated is False
        # Restore
        importlib.reload(sg_mod)


# ── HoneyEngine tests ─────────────────────────────────────────────────────────

class TestHoneyEngine:

    def test_honey_disabled_by_default(self, honey_engine):
        """HONEY_MODE defaults to false — maybe_honey always returns is_honey=False."""
        result = honey_engine.maybe_honey("req-1", ["PROMPT_INJECTION"], "tenant-a")
        assert result.is_honey is False
        assert result.honey_id == ""
        assert result.response_text == ""

    def test_honey_enabled_probability_1(self, fake_redis, monkeypatch):
        """With HONEY_MODE=true and HONEY_PROBABILITY=1.0, every blocked request gets honey."""
        monkeypatch.setenv("HONEY_MODE", "true")
        monkeypatch.setenv("HONEY_PROBABILITY", "1.0")

        import importlib

        import warden.honey as honey_mod
        importlib.reload(honey_mod)

        engine = honey_mod.HoneyEngine(fake_redis)
        result = engine.maybe_honey("req-honey", ["PROMPT_INJECTION"], "tenant-x")
        assert result.is_honey is True
        assert len(result.honey_id) == 16
        assert len(result.response_text) > 0

        importlib.reload(honey_mod)

    def test_honey_response_matches_flag(self, fake_redis, monkeypatch):
        """Honey response should be selected from the matching flag's response list."""
        monkeypatch.setenv("HONEY_MODE", "true")
        monkeypatch.setenv("HONEY_PROBABILITY", "1.0")

        import importlib

        import warden.honey as honey_mod
        importlib.reload(honey_mod)

        engine = honey_mod.HoneyEngine(fake_redis)
        result = engine.maybe_honey("req-j", ["JAILBREAK_ATTEMPT"], "tenant-y")
        assert result.is_honey is True
        # Response should come from JAILBREAK_ATTEMPT pool
        jailbreak_responses = honey_mod._RESPONSES["JAILBREAK_ATTEMPT"]
        assert result.response_text in jailbreak_responses

        importlib.reload(honey_mod)

    def test_honey_session_stored_in_redis(self, fake_redis, monkeypatch):
        """Honey session metadata should be stored in Redis for follow-up correlation."""
        monkeypatch.setenv("HONEY_MODE", "true")
        monkeypatch.setenv("HONEY_PROBABILITY", "1.0")

        import importlib

        import warden.honey as honey_mod
        importlib.reload(honey_mod)

        engine = honey_mod.HoneyEngine(fake_redis)
        result = engine.maybe_honey("req-store", ["PROMPT_INJECTION"], "tenant-z")
        assert result.is_honey is True

        meta = engine.is_honey_session(result.honey_id)
        assert meta is not None
        assert meta["honey_id"] == result.honey_id
        assert meta["tenant_id"] == "tenant-z"
        assert "PROMPT_INJECTION" in meta["flags"]

        importlib.reload(honey_mod)

    def test_is_honey_session_returns_none_for_unknown(self, honey_engine):
        """is_honey_session should return None for an unknown honey_id."""
        result = honey_engine.is_honey_session("nonexistent-id")
        assert result is None

    def test_honey_fail_open_on_redis_error(self, monkeypatch):
        """HoneyEngine should still return a result even if Redis write fails."""
        monkeypatch.setenv("HONEY_MODE", "true")
        monkeypatch.setenv("HONEY_PROBABILITY", "1.0")

        import importlib

        import warden.honey as honey_mod
        importlib.reload(honey_mod)

        class BrokenRedis:
            def setex(self, *a, **kw):
                raise RuntimeError("Redis down")
            def get(self, key):
                return None

        engine = honey_mod.HoneyEngine(BrokenRedis())
        result = engine.maybe_honey("req-broken", ["PROMPT_INJECTION"], "t")
        # Should still return a honey response even though Redis failed
        assert result.is_honey is True
        assert len(result.response_text) > 0

        importlib.reload(honey_mod)

    def test_log_followup_respects_gdpr(self, honey_engine, caplog):
        """log_followup should log content_hash but never actual content."""
        import logging
        with caplog.at_level(logging.WARNING, logger="warden.honey"):
            honey_engine.log_followup("hid-123", "secret payload text", "req-log")
        # Find the honey_engagement log entry
        honey_logs = [r for r in caplog.records if "honey_engagement" in r.getMessage()]
        assert len(honey_logs) == 1
        payload = json.loads(honey_logs[0].getMessage())
        assert "content_hash" in payload
        assert "secret payload text" not in honey_logs[0].getMessage()
        assert payload["content_len"] == len("secret payload text")


# ── Telemetry no-op path ──────────────────────────────────────────────────────

class TestTelemetryNoOp:

    def test_trace_stage_noop_when_disabled(self):
        """trace_stage should be a zero-overhead no-op when OTEL_ENABLED=false."""
        from warden.telemetry import get_tracer, trace_stage
        assert get_tracer() is None
        executed = []
        with trace_stage("test_stage", {"key": "val"}) as span:
            executed.append(True)
            span.set_attribute("foo", "bar")   # should not raise
            span.set_status("OK")              # should not raise
            span.record_exception(ValueError("x"))  # should not raise
        assert executed == [True]

    def test_init_telemetry_noop_when_disabled(self):
        """init_telemetry should be a no-op when OTEL_ENABLED=false (default)."""
        from warden.telemetry import get_tracer, init_telemetry
        init_telemetry()   # should not raise
        assert get_tracer() is None
