"""
warden/agent_monitor.py
━━━━━━━━━━━━━━━━━━━━━━
Shadow Warden AI — Agentic Session Monitor

Tracks the lifecycle of AI agent sessions across multiple /filter requests and
tool calls.  Groups events by session_id, detects five session-level threat
patterns, and writes session summaries to sessions.json for the analytics API.

Threat patterns detected
────────────────────────
TOOL_VELOCITY        >10 tool calls in 60 s window (DoS / mass exfil)
PRIVILEGE_ESCALATION Tool calls escalating from read → network/write → destructive
EVASION_ATTEMPT      Agent retrying a tool that was previously blocked
EXFIL_CHAIN          Read tool followed by network/write tool (read→exfil)
RAPID_BLOCK          ≥3 blocks within a single session

GDPR notes:
  • No prompt content or tool arguments are stored — only metadata.
  • sessions.json records tool names, directions, timestamps, decisions.

Storage:
  • Redis-backed (sliding TTL = AGENT_SESSION_TTL seconds, default 30 min).
  • Falls back to an in-memory dict if Redis is unavailable (sessions lost
    on restart, but the filter pipeline is never blocked).
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

log = logging.getLogger("warden.agent_monitor")

# ── Config ────────────────────────────────────────────────────────────────────

SESSION_TTL_SECONDS   = int(os.getenv("AGENT_SESSION_TTL",   "1800"))  # 30 min
VELOCITY_WINDOW_SECS  = int(os.getenv("VELOCITY_WINDOW_SECS", "60"))
VELOCITY_THRESHOLD    = int(os.getenv("VELOCITY_THRESHOLD",   "10"))
RAPID_BLOCK_THRESHOLD = int(os.getenv("RAPID_BLOCK_THRESHOLD", "3"))

SESSIONS_PATH = (
    Path(os.getenv("ANALYTICS_DATA_PATH", "/analytics/data")) / "sessions.json"
)

_sessions_lock = threading.Lock()

# ── Pattern constants ─────────────────────────────────────────────────────────

PATTERN_TOOL_VELOCITY        = "TOOL_VELOCITY"
PATTERN_PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
PATTERN_EVASION_ATTEMPT      = "EVASION_ATTEMPT"
PATTERN_EXFIL_CHAIN          = "EXFIL_CHAIN"
PATTERN_RAPID_BLOCK          = "RAPID_BLOCK"

# ── Tool category sets ────────────────────────────────────────────────────────
#
# Categories:
#   0 = read-only   (low privilege)
#   1 = network/write (elevated privilege)
#   2 = destructive  (highest privilege)

_READ_TOOLS: frozenset[str] = frozenset({
    "read_file", "list_files", "get_file", "read_dir", "list_dir",
    "web_search", "web_fetch", "fetch_url", "http_get",
    "query_db", "sql_query", "db_query", "search",
})

_NETWORK_WRITE_TOOLS: frozenset[str] = frozenset({
    "write_file", "create_file", "append_file",
    "http_request", "http_post", "http_put", "http_patch",
    "send_email", "upload_file", "ftp_upload", "api_call",
    "post_request", "put_request",
})

_DESTRUCTIVE_TOOLS: frozenset[str] = frozenset({
    "bash", "shell", "run_command", "run_shell", "execute",
    "python_repl", "eval_code", "exec_code",
    "delete_file", "remove_file", "rm_rf",
    "drop_table", "truncate_table", "format_disk",
})

# ── Risk score deltas per risk level ─────────────────────────────────────────

_RISK_DELTAS: dict[str, float] = {
    "low":    0.0,
    "medium": 0.05,
    "high":   0.2,
    "block":  0.4,
}


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SessionThreat:
    pattern:     str
    severity:    Literal["MEDIUM", "HIGH"]
    detail:      str
    detected_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "pattern":     self.pattern,
            "severity":    self.severity,
            "detail":      self.detail,
            "detected_at": self.detected_at,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tool_category(tool_name: str, threat_kind: str | None = None) -> int:
    """
    Return 0 (read), 1 (network/write), 2 (destructive), or -1 (unknown).
    Falls back to threat_kind when the tool name is not in any known set.
    """
    name = (tool_name or "").lower()
    if name in _DESTRUCTIVE_TOOLS:
        return 2
    if name in _NETWORK_WRITE_TOOLS:
        return 1
    if name in _READ_TOOLS:
        return 0
    # Infer from ToolCallGuard threat kind
    if threat_kind in {"shell_destruction", "code_injection"}:
        return 2
    if threat_kind in {"ssrf", "path_traversal"}:
        return 1
    return -1


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _is_expired(last_seen: str) -> bool:
    try:
        ts = datetime.fromisoformat(last_seen)
        return (datetime.now(UTC) - ts).total_seconds() > SESSION_TTL_SECONDS
    except (ValueError, TypeError):
        return True


# ── AgentMonitor ──────────────────────────────────────────────────────────────

class AgentMonitor:
    """
    Session-level agentic threat monitor.

    Thread-safe.  All public methods are synchronous and fail-open — any
    internal error returns None / empty list rather than propagating.
    Designed to be called from FastAPI BackgroundTasks.
    """

    def __init__(self) -> None:
        self._redis: Any = None          # set lazily by _get_redis()
        self._fallback: dict[str, dict] = {}   # in-memory when Redis absent
        self._fallback_lock = threading.Lock()

    # ── Redis helpers ─────────────────────────────────────────────────────────

    def _get_redis(self) -> Any:
        if self._redis is not None:
            return self._redis
        try:
            import redis as _redis
            url = os.getenv("REDIS_URL", "redis://redis:6379/0")
            if url.startswith("memory://"):
                raise ValueError("in-memory:// scheme — skip Redis")
            client = _redis.from_url(
                url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=1,
            )
            client.ping()
            self._redis = client
        except Exception as exc:
            log.debug("AgentMonitor: Redis unavailable, using in-memory fallback: %s", exc)
            self._redis = None
        return self._redis

    def _r_meta_key(self, session_id: str) -> str:
        return f"warden:session:{session_id}:meta"

    def _r_events_key(self, session_id: str) -> str:
        return f"warden:session:{session_id}:events"

    def _r_get_meta(self, session_id: str) -> dict | None:
        r = self._get_redis()
        if r is not None:
            try:
                raw = r.get(self._r_meta_key(session_id))
                return json.loads(raw) if raw else None
            except Exception:
                pass
        with self._fallback_lock:
            entry = self._fallback.get(session_id)
        if entry is None:
            return None
        meta = entry.get("meta")
        if meta and _is_expired(meta.get("last_seen", "")):
            return None
        return meta

    def _r_set_meta(self, session_id: str, meta: dict) -> None:
        r = self._get_redis()
        if r is not None:
            try:
                r.set(
                    self._r_meta_key(session_id),
                    json.dumps(meta, separators=(",", ":")),
                    ex=SESSION_TTL_SECONDS,
                )
                return
            except Exception:
                pass
        with self._fallback_lock:
            if session_id not in self._fallback:
                self._fallback[session_id] = {"meta": {}, "events": []}
            self._fallback[session_id]["meta"] = meta

    def _r_append_event(self, session_id: str, event: dict) -> None:
        r = self._get_redis()
        line = json.dumps(event, separators=(",", ":"))
        if r is not None:
            try:
                key = self._r_events_key(session_id)
                r.rpush(key, line)
                r.expire(key, SESSION_TTL_SECONDS)
                return
            except Exception:
                pass
        with self._fallback_lock:
            if session_id not in self._fallback:
                self._fallback[session_id] = {"meta": {}, "events": []}
            self._fallback[session_id]["events"].append(event)

    def _r_get_events(self, session_id: str) -> list[dict]:
        r = self._get_redis()
        if r is not None:
            try:
                raw_list = r.lrange(self._r_events_key(session_id), 0, -1)
                events = []
                for raw in raw_list:
                    try:
                        events.append(json.loads(raw))
                    except json.JSONDecodeError:
                        pass
                return events
            except Exception:
                pass
        with self._fallback_lock:
            entry = self._fallback.get(session_id)
        return list(entry["events"]) if entry else []

    def _r_touch_ttl(self, session_id: str) -> None:
        r = self._get_redis()
        if r is not None:
            try:
                r.expire(self._r_meta_key(session_id),   SESSION_TTL_SECONDS)
                r.expire(self._r_events_key(session_id), SESSION_TTL_SECONDS)
            except Exception:
                pass

    # ── Session creation helper ───────────────────────────────────────────────

    def _new_meta(self, session_id: str, tenant_id: str) -> dict:
        now = _now_iso()
        return {
            "session_id":       session_id,
            "tenant_id":        tenant_id,
            "first_seen":       now,
            "last_seen":        now,
            "request_count":    0,
            "block_count":      0,
            "risk_score":       0.0,
            "tool_names_seen":  [],
            "threats_detected": [],
        }

    # ── Public API ────────────────────────────────────────────────────────────

    def record_request(
        self,
        session_id:  str,
        request_id:  str,
        allowed:     bool,
        risk_level:  str,
        flags:       list[str],
        tenant_id:   str = "default",
    ) -> SessionThreat | None:
        """
        Record a /filter request against a session.
        Returns a SessionThreat if a new pattern was detected, else None.
        Fail-open: any internal error returns None.
        """
        try:
            meta = self._r_get_meta(session_id) or self._new_meta(session_id, tenant_id)
            meta["last_seen"]      = _now_iso()
            meta["request_count"]  = int(meta.get("request_count", 0)) + 1
            if not allowed:
                meta["block_count"] = int(meta.get("block_count", 0)) + 1
            delta = _RISK_DELTAS.get(risk_level.lower(), 0.0)
            meta["risk_score"] = min(1.0, round(float(meta.get("risk_score", 0.0)) + delta, 4))

            event = {
                "ts":         _now_iso(),
                "event_type": "request",
                "request_id": request_id,
                "allowed":    allowed,
                "risk_level": risk_level,
                "flags":      flags,
            }
            self._r_set_meta(session_id, meta)
            self._r_append_event(session_id, event)
            self._r_touch_ttl(session_id)

            events = self._r_get_events(session_id)
            threats = self._analyze_patterns(session_id, meta, events)
            return self._handle_new_threats(session_id, meta, threats)

        except Exception as exc:
            log.debug("AgentMonitor.record_request error (ignored): %s", exc)
            return None

    def record_tool_event(
        self,
        session_id:  str,
        tool_name:   str,
        direction:   Literal["call", "result"],
        blocked:     bool,
        threat_kind: str | None = None,
    ) -> SessionThreat | None:
        """
        Record a single tool call or result inspection event.
        Returns a SessionThreat if a new pattern was detected, else None.
        Fail-open.
        """
        try:
            meta = self._r_get_meta(session_id) or self._new_meta(session_id, "default")
            meta["last_seen"] = _now_iso()

            # Track tool names seen (no duplicates)
            seen: list[str] = meta.get("tool_names_seen") or []
            if tool_name not in seen:
                seen = list(seen) + [tool_name]
                meta["tool_names_seen"] = seen

            if blocked:
                meta["block_count"] = int(meta.get("block_count", 0)) + 1
                meta["risk_score"]  = min(
                    1.0,
                    round(float(meta.get("risk_score", 0.0)) + 0.1, 4),
                )

            event = {
                "ts":          _now_iso(),
                "event_type":  "tool",
                "tool_name":   tool_name,
                "direction":   direction,
                "blocked":     blocked,
                "threat_kind": threat_kind,
            }
            self._r_set_meta(session_id, meta)
            self._r_append_event(session_id, event)
            self._r_touch_ttl(session_id)

            events = self._r_get_events(session_id)
            threats = self._analyze_patterns(session_id, meta, events)
            return self._handle_new_threats(session_id, meta, threats)

        except Exception as exc:
            log.debug("AgentMonitor.record_tool_event error (ignored): %s", exc)
            return None

    def get_session(self, session_id: str) -> dict | None:
        """Return full session metadata + events list, or None if not found."""
        try:
            meta = self._r_get_meta(session_id)
            if meta is None:
                return None
            events = self._r_get_events(session_id)
            return {**meta, "events": events}
        except Exception:
            return None

    def list_sessions(self, limit: int = 20, active_only: bool = False) -> list[dict]:
        """
        Return session summaries from sessions.json (no events list).
        Sorted newest-first by last_seen.
        """
        try:
            sessions = _read_sessions_file()
            if active_only:
                sessions = [s for s in sessions if not _is_expired(s.get("last_seen", ""))]
            sessions.sort(key=lambda s: s.get("last_seen", ""), reverse=True)
            return sessions[:limit]
        except Exception:
            return []

    # ── Pattern detection ─────────────────────────────────────────────────────

    def _analyze_patterns(
        self,
        session_id: str,
        meta: dict,
        events: list[dict],
    ) -> list[SessionThreat]:
        """Run all 5 pattern checks; return only those not already recorded."""
        already = {t["pattern"] for t in (meta.get("threats_detected") or [])}
        found: list[SessionThreat] = []
        for check in (
            self._check_rapid_block,
            self._check_tool_velocity,
            self._check_privilege_escalation,
            self._check_evasion_attempt,
            self._check_exfil_chain,
        ):
            try:
                threat = check(meta, events)  # type: ignore[call-arg]
                if threat and threat.pattern not in already:
                    found.append(threat)
                    already.add(threat.pattern)
            except Exception:
                pass
        return found

    def _check_rapid_block(self, meta: dict, _events: list[dict]) -> SessionThreat | None:
        if int(meta.get("block_count", 0)) >= RAPID_BLOCK_THRESHOLD:
            return SessionThreat(
                pattern=PATTERN_RAPID_BLOCK,
                severity="HIGH",
                detail=f"Session has {meta['block_count']} blocked events",
            )
        return None

    def _check_tool_velocity(self, _meta: dict, events: list[dict]) -> SessionThreat | None:
        cutoff = datetime.now(UTC) - timedelta(seconds=VELOCITY_WINDOW_SECS)
        recent = [
            e for e in events
            if e.get("event_type") == "tool"
            and e.get("direction") == "call"
            and _parse_ts(e.get("ts", "")) >= cutoff
        ]
        if len(recent) > VELOCITY_THRESHOLD:
            return SessionThreat(
                pattern=PATTERN_TOOL_VELOCITY,
                severity="HIGH",
                detail=(
                    f"{len(recent)} tool calls in {VELOCITY_WINDOW_SECS}s window "
                    f"(threshold={VELOCITY_THRESHOLD})"
                ),
            )
        return None

    def _check_privilege_escalation(
        self, _meta: dict, events: list[dict]
    ) -> SessionThreat | None:
        tool_calls = [
            e for e in events
            if e.get("event_type") == "tool" and e.get("direction") == "call"
        ]
        max_seen = -1
        for e in tool_calls:
            cat = _tool_category(e.get("tool_name", ""), e.get("threat_kind"))
            if cat < 0:
                continue
            if cat > max_seen + 1 and max_seen >= 0:
                return SessionThreat(
                    pattern=PATTERN_PRIVILEGE_ESCALATION,
                    severity="HIGH",
                    detail=(
                        f"Tool privilege escalated from category {max_seen} "
                        f"to {cat} (tool: {e.get('tool_name')})"
                    ),
                )
            if cat > max_seen:
                max_seen = cat
        return None

    def _check_evasion_attempt(self, _meta: dict, events: list[dict]) -> SessionThreat | None:
        tool_events = [e for e in events if e.get("event_type") == "tool"]
        blocked_names: set[str] = set()
        for e in tool_events:
            if e.get("blocked"):
                blocked_names.add(e.get("tool_name", ""))
        for e in tool_events:
            if (
                not e.get("blocked")
                and e.get("direction") == "call"
                and e.get("tool_name") in blocked_names
            ):
                return SessionThreat(
                    pattern=PATTERN_EVASION_ATTEMPT,
                    severity="HIGH",
                    detail=f"Retry of previously blocked tool: {e.get('tool_name')}",
                )
        return None

    def _check_exfil_chain(self, _meta: dict, events: list[dict]) -> SessionThreat | None:
        tool_calls = [
            e for e in events
            if e.get("event_type") == "tool" and e.get("direction") == "call"
        ]
        saw_read = False
        for e in tool_calls:
            cat = _tool_category(e.get("tool_name", ""), e.get("threat_kind"))
            if cat == 0:
                saw_read = True
            elif cat == 1 and saw_read:
                return SessionThreat(
                    pattern=PATTERN_EXFIL_CHAIN,
                    severity="HIGH",
                    detail=(
                        f"Read tool followed by network/write tool: {e.get('tool_name')}"
                    ),
                )
        return None

    # ── Threat finalization ───────────────────────────────────────────────────

    def _handle_new_threats(
        self,
        session_id: str,
        meta: dict,
        threats: list[SessionThreat],
    ) -> SessionThreat | None:
        if not threats:
            return None

        # Record in metadata
        existing = list(meta.get("threats_detected") or [])
        for t in threats:
            existing.append(t.as_dict())
        meta["threats_detected"] = existing
        self._r_set_meta(session_id, meta)

        # Prometheus counters
        try:
            from warden.metrics import AGENT_ANOMALIES_TOTAL, AGENT_SESSION_BLOCKS
            for t in threats:
                AGENT_ANOMALIES_TOTAL.labels(
                    pattern_type=t.pattern,
                    severity=t.severity,
                ).inc()
            AGENT_SESSION_BLOCKS.labels(
                tenant_id=meta.get("tenant_id", "default"),
            ).inc(len(threats))
        except Exception:
            pass

        # Flush summary to sessions.json
        _flush_session_summary(session_id, meta)

        return threats[0]


# ── sessions.json helpers (module-level for analytics access) ─────────────────

def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=UTC)


def _read_sessions_file() -> list[dict]:
    if not SESSIONS_PATH.exists():
        return []
    sessions: list[dict] = []
    try:
        with SESSIONS_PATH.open("r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    sessions.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
    except OSError as exc:
        log.warning("AgentMonitor: could not read sessions file: %s", exc)
    return sessions


def _flush_session_summary(session_id: str, meta: dict) -> None:
    """Atomic NDJSON upsert — replaces the line for this session_id."""
    try:
        SESSIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _sessions_lock:
            existing = [
                s for s in _read_sessions_file()
                if s.get("session_id") != session_id
            ]
            existing.append(meta)
            lines = [json.dumps(s, separators=(",", ":")) for s in existing]
            content = "\n".join(lines) + "\n"
            tmp = SESSIONS_PATH.with_suffix(".tmp")
            tmp.write_text(content, encoding="utf-8")
            os.replace(tmp, SESSIONS_PATH)
    except Exception as exc:
        log.warning("AgentMonitor: could not flush session summary: %s", exc)
