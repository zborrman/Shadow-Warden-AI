"""
warden/taint_tracker.py
━━━━━━━━━━━━━━━━━━━━━━
Dynamic Taint Tracking — Layer 2 of Zero-Click AI Worm Defense (v2.5)

Problem
───────
A Zero-Click worm exploits the fact that an AI agent reading an external
document (email body, scraped webpage, tool output from a third-party API)
immediately has that content in its context window — and may then call
write/send/exfil tools using that context without any human approval.

The standard Zero-Trust sandbox (agent_sandbox.py) grants permissions
statically based on a manifest.  Static manifests cannot react to *what data*
the agent has in its context at the moment of the call.

Taint Tracking adds a *runtime* data-provenance layer:

  • Any context that arrives from an external / untrusted source is tagged
    TAINTED (TaintLevel.EXTERNAL).
  • When an agent with TAINTED context tries to call a destructive or
    network-egress tool, the sandbox decision is *dynamically overridden* to
    DENY — even if the static manifest would normally allow it.
  • The agent's session is tagged PENDING_HITL (Human-in-the-Loop review)
    and the event is logged to the worm quarantine stream.

Taint levels (ordered)
───────────────────────
  CLEAN    (0) — produced by the trusted system prompt / the model itself
  INTERNAL (1) — tool results from internal / allow-listed services
  EXTERNAL (2) — anything fetched from the network or received via email/webhook
  HOSTILE  (3) — EXTERNAL content that also triggered WormGuard / PhishGuard

Dynamic privilege revocation rules
────────────────────────────────────
  Level ≥ EXTERNAL → revoke destructive tools (bash, exec, delete, …)
  Level ≥ EXTERNAL → revoke network-egress tools (send_email, http_post, …)
                     unless the target host is in the session's ALLOW_HOSTS list.
  Level ≥ HOSTILE  → revoke ALL tool categories; flag for HITL review.

Session storage
────────────────
  Taint state is stored per-session in Redis:
    Key:   warden:taint:{session_id}
    Value: JSON {"level": 2, "sources": ["https://evil.com"], "hostile": false}
    TTL:   AGENT_SESSION_TTL seconds (shared with AgentMonitor)

  Fail-open: if Redis is unavailable the tracker returns CLEAN and logs a
  warning.  The static sandbox still applies — only the *dynamic upgrade* is
  lost.

Environment variables
─────────────────────
  TAINT_TRACKING_ENABLED     "false" to disable (default: true)
  TAINT_ALLOW_HOSTS          Comma-separated list of trusted egress hostnames
                             that EXTERNAL-tainted agents may still POST to.
                             (e.g. "api.internal.corp,logs.internal.corp")
  AGENT_SESSION_TTL          Shared with agent_monitor/agent_sandbox (default 1800)
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from enum import IntEnum

log = logging.getLogger("warden.taint_tracker")

# ── Config ────────────────────────────────────────────────────────────────────

ENABLED: bool      = os.getenv("TAINT_TRACKING_ENABLED", "true").lower() != "false"
_SESSION_TTL: int  = int(os.getenv("AGENT_SESSION_TTL", "1800"))
_ALLOW_HOSTS: frozenset[str] = frozenset(
    h.strip().lower()
    for h in os.getenv("TAINT_ALLOW_HOSTS", "").split(",")
    if h.strip()
)

# ── Taint levels ──────────────────────────────────────────────────────────────

class TaintLevel(IntEnum):
    CLEAN    = 0   # Trusted: system prompt, model's own generation
    INTERNAL = 1   # Semi-trusted: internal tooling, allow-listed services
    EXTERNAL = 2   # Untrusted: email body, scraped web, third-party API
    HOSTILE  = 3   # Confirmed attack: WormGuard/PhishGuard flagged this source


# ── Tool sets subject to dynamic revocation ───────────────────────────────────

_DESTRUCTIVE_TOOLS: frozenset[str] = frozenset({
    "bash", "shell", "run_command", "run_shell", "execute",
    "python_repl", "eval_code", "exec_code", "exec_shell",
    "delete_file", "remove_file", "rm_rf",
    "drop_table", "truncate_table", "format_disk",
    "db_write", "db_delete", "db_exec",
})

_EGRESS_TOOLS: frozenset[str] = frozenset({
    "send_email", "reply_email", "forward_email",
    "http_post", "http_put", "http_patch", "api_call",
    "post_request", "put_request", "upload_file",
    "ftp_upload", "slack_post", "teams_post", "discord_post",
    "create_issue", "post_comment", "webhook_send",
    "send_message", "broadcast",
})


# ── Session taint state ───────────────────────────────────────────────────────

@dataclass
class TaintState:
    """Mutable taint state for one agent session."""
    level:       TaintLevel      = TaintLevel.CLEAN
    sources:     list[str]       = field(default_factory=list)   # URLs / sources
    hostile:     bool            = False
    hitl_pending: bool           = False   # Human-in-the-Loop review requested

    def to_dict(self) -> dict:
        return {
            "level":        int(self.level),
            "sources":      self.sources[:10],   # cap stored entries
            "hostile":      self.hostile,
            "hitl_pending": self.hitl_pending,
        }

    @classmethod
    def from_dict(cls, d: dict) -> TaintState:
        return cls(
            level        = TaintLevel(int(d.get("level", 0))),
            sources      = d.get("sources", []),
            hostile      = bool(d.get("hostile", False)),
            hitl_pending = bool(d.get("hitl_pending", False)),
        )


# ── Revocation result ─────────────────────────────────────────────────────────

@dataclass
class TaintDecision:
    """
    Dynamic override on top of the static SandboxDecision.

    When `revoked=True` the tool call MUST be denied regardless of what the
    static manifest says.  Pass `reason` to the user-facing SandboxDecision.
    """
    revoked:      bool = False
    reason:       str  = ""
    hitl_required: bool = False
    taint_level:  TaintLevel = TaintLevel.CLEAN


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _redis():
    try:
        from warden.cache import _get_client  # noqa: PLC0415
        return _get_client()
    except Exception:
        return None


def _session_key(session_id: str) -> str:
    return f"warden:taint:{session_id}"


def _load_state(session_id: str) -> TaintState:
    """Load taint state from Redis; returns CLEAN on miss or error."""
    r = _redis()
    if r is None:
        return TaintState()
    try:
        raw = r.get(_session_key(session_id))
        if raw:
            return TaintState.from_dict(json.loads(raw))
    except Exception as exc:
        log.debug("TaintTracker: _load_state error: %s", exc)
    return TaintState()


def _save_state(session_id: str, state: TaintState) -> None:
    """Persist taint state to Redis with shared session TTL."""
    r = _redis()
    if r is None:
        return
    try:
        r.setex(
            _session_key(session_id),
            _SESSION_TTL,
            json.dumps(state.to_dict()),
        )
    except Exception as exc:
        log.debug("TaintTracker: _save_state error: %s", exc)


# ── Public API ────────────────────────────────────────────────────────────────

def mark_tainted(
    session_id: str,
    source: str,
    level: TaintLevel = TaintLevel.EXTERNAL,
    *,
    hostile: bool = False,
) -> TaintState:
    """
    Elevate (never lower) the taint level for a session.

    Call this every time the agent ingests external data:
        mark_tainted(session_id, source="https://evil.com/email.html")

    If `hostile=True` (WormGuard / PhishGuard confirmed attack), the session
    is immediately escalated to HOSTILE and HITL review is requested.

    Returns the updated TaintState.
    """
    if not ENABLED:
        return TaintState()

    state = _load_state(session_id)

    if level.value > state.level.value:
        log.info(
            "TaintTracker: session=%s taint escalated %s → %s source=%r",
            session_id, state.level.name, level.name, source[:80],
        )
        state.level = level

    if source and source not in state.sources:
        state.sources.append(source[:200])

    if hostile and not state.hostile:
        state.hostile     = True
        state.hitl_pending = True
        state.level       = TaintLevel.HOSTILE
        log.warning(
            "TaintTracker: session=%s marked HOSTILE — HITL required. source=%r",
            session_id, source[:80],
        )

    _save_state(session_id, state)
    return state


def get_taint(session_id: str) -> TaintState:
    """Return the current taint state for a session (CLEAN if unknown)."""
    if not ENABLED or not session_id:
        return TaintState()
    return _load_state(session_id)


def clear_taint(session_id: str) -> None:
    """
    Reset taint state to CLEAN after a Human-in-the-Loop review approves
    the session.  Only call when a human has explicitly reviewed and approved.
    """
    r = _redis()
    if r is None:
        return
    try:
        r.delete(_session_key(session_id))
        log.info("TaintTracker: session=%s taint cleared (HITL approved)", session_id)
    except Exception as exc:
        log.debug("TaintTracker: clear_taint error: %s", exc)


def check_tool_taint(
    session_id: str,
    tool_name: str,
    target_host: str = "",
) -> TaintDecision:
    """
    Dynamic privilege revocation check.

    Call this AFTER the static SandboxDecision.allow check, BEFORE executing
    the tool.  If this returns revoked=True, deny the call regardless of what
    the static manifest said.

    Parameters
    ----------
    session_id  : str — current agent session identifier
    tool_name   : str — tool being invoked
    target_host : str — destination hostname for egress tools (optional)
                       e.g. "mail.corp.com" for send_email.
                       If in TAINT_ALLOW_HOSTS, egress is permitted.

    Decision table:
    ┌──────────────┬─────────────────────────────────────────────────────┐
    │ Taint Level  │ Revoked tools                                       │
    ├──────────────┼─────────────────────────────────────────────────────┤
    │ CLEAN        │ none                                                │
    │ INTERNAL     │ none                                                │
    │ EXTERNAL     │ _DESTRUCTIVE_TOOLS + _EGRESS_TOOLS (non-allow-host) │
    │ HOSTILE      │ ALL tools — full lockdown + HITL                   │
    └──────────────┴─────────────────────────────────────────────────────┘
    """
    if not ENABLED or not session_id:
        return TaintDecision()

    state = _load_state(session_id)
    tool  = tool_name.lower().strip()

    # CLEAN / INTERNAL — no dynamic revocation
    if state.level < TaintLevel.EXTERNAL:
        return TaintDecision(taint_level=state.level)

    # HOSTILE — total lockdown
    if state.level >= TaintLevel.HOSTILE or state.hostile:
        log.warning(
            "TaintTracker: REVOKE (HOSTILE) session=%s tool=%s — HITL pending",
            session_id, tool,
        )
        return TaintDecision(
            revoked       = True,
            reason        = (
                "taint:hostile — session context contains confirmed worm/phishing payload. "
                "Human-in-the-Loop review required before any tool calls."
            ),
            hitl_required = True,
            taint_level   = state.level,
        )

    # EXTERNAL — revoke destructive tools unconditionally
    if tool in _DESTRUCTIVE_TOOLS:
        log.warning(
            "TaintTracker: REVOKE (destructive+EXTERNAL) session=%s tool=%s sources=%s",
            session_id, tool, state.sources[:2],
        )
        return TaintDecision(
            revoked    = True,
            reason     = (
                f"taint:external — destructive tool '{tool}' denied while session has "
                f"untrusted context from: {', '.join(state.sources[:2])}"
            ),
            taint_level = state.level,
        )

    # EXTERNAL — revoke egress tools unless target host is explicitly allowed
    if tool in _EGRESS_TOOLS:
        host_lc = (target_host or "").lower().strip()
        if host_lc and host_lc in _ALLOW_HOSTS:
            log.info(
                "TaintTracker: ALLOW (trusted egress host) session=%s tool=%s host=%s",
                session_id, tool, host_lc,
            )
            return TaintDecision(taint_level=state.level)

        log.warning(
            "TaintTracker: REVOKE (egress+EXTERNAL) session=%s tool=%s target=%r sources=%s",
            session_id, tool, target_host, state.sources[:2],
        )
        return TaintDecision(
            revoked    = True,
            reason     = (
                f"taint:external — egress tool '{tool}' denied while session has "
                f"untrusted context. "
                + (f"Target host '{host_lc}' not in TAINT_ALLOW_HOSTS." if host_lc else
                   "No target host provided.")
                + f" Sources: {', '.join(state.sources[:2])}"
            ),
            taint_level = state.level,
        )

    return TaintDecision(taint_level=state.level)
