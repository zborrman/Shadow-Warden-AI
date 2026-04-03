"""
warden/agent_sandbox.py
━━━━━━━━━━━━━━━━━━━━━━
Zero-Trust Agent Sandbox — Step 1 of v1.7.

Implements Capability Manifests: every AgentID must have an explicitly registered
manifest that lists EXACTLY which tools it may call and with which parameters.
Any tool not listed, any parameter not listed, and any call over the session quota
is denied — default deny, not default allow.

Integrated with ToolCallGuard: the sandbox check runs FIRST (before regex patterns),
so capability violations are caught before content scanning even starts.

Manifest definition
────────────────────
  A manifest is a JSON object with:
    agent_id              str   — unique identifier (passed via X-Agent-Id header)
    description           str   — human label for audit logs
    capabilities          list  — one entry per allowed tool
      tool_name           str   — exact tool function name
      allowed_params      list  — allowed parameter keys (others → denied)
                                  empty list = all params allowed (use carefully)
      max_calls_per_session int — per-session call quota (0 = unlimited)
      required_approval   bool  — Human-in-the-loop flag (logged, not yet enforced)
    network_egress_allowed bool  — False blocks all network/write category tools
    default_deny          bool  — default True; set False for permissive mode

JSON file format (AGENT_SANDBOX_PATH):
  {
    "manifests": [
      {
        "agent_id": "data-analyst-v1",
        "description": "Read-only SQL analyst — no network egress",
        "capabilities": [
          { "tool_name": "query_db",   "allowed_params": ["query", "database"],
            "max_calls_per_session": 10 },
          { "tool_name": "web_search", "allowed_params": ["query"],
            "max_calls_per_session": 5 }
        ],
        "network_egress_allowed": false
      }
    ]
  }

Decision flow
──────────────
  authorize_tool_call(agent_id, tool_name, params, session_id)
    1. manifest found?            → NO  → DENY  (reason: no_manifest)
    2. tool in capabilities?      → NO  → DENY  (reason: tool_not_allowed)
    3. params ⊆ allowed_params?   → NO  → DENY  (reason: param_not_allowed)
    4. session quota reached?     → YES → DENY  (reason: quota_exceeded)
    5. network egress check?      → FAIL→ DENY  (reason: network_egress_denied)
    6. taint revocation check?    → FAIL→ DENY  (reason: taint:external / taint:hostile)
    7.                                  → ALLOW

Redis storage (call counts)
────────────────────────────
  Key: warden:sandbox:{agent_id}:{session_id}:{tool_name}
  Type: counter (INCR)
  TTL:  AGENT_SESSION_TTL seconds (shared with AgentMonitor)

Environment variables
─────────────────────
  AGENT_SANDBOX_PATH     Path to JSON manifest file (optional — disables manifest
                         checks when unset unless AGENT_SANDBOX_STRICT=true)
  AGENT_SANDBOX_STRICT   "true" → deny all tool calls when no manifest file loaded
                         "false" (default) → skip sandbox check if no manifests loaded
  AGENT_SESSION_TTL      Session TTL seconds (default 1800 — shared with AgentMonitor)
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("warden.agent_sandbox")

# ── Config ────────────────────────────────────────────────────────────────────

_SANDBOX_PATH:   str  = os.getenv("AGENT_SANDBOX_PATH", "")
_STRICT:         bool = os.getenv("AGENT_SANDBOX_STRICT", "false").lower() == "true"
_SESSION_TTL:    int  = int(os.getenv("AGENT_SESSION_TTL", "1800"))

# ── Network/write tool category (mirrors agent_monitor.py) ───────────────────

_NETWORK_WRITE_TOOLS: frozenset[str] = frozenset({
    "write_file", "create_file", "append_file",
    "http_request", "http_post", "http_put", "http_patch",
    "send_email", "upload_file", "ftp_upload", "api_call",
    "post_request", "put_request", "http_delete",
})


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ToolCapability:
    tool_name:             str
    allowed_params:        list[str]   = field(default_factory=list)  # empty = all allowed
    max_calls_per_session: int         = 0     # 0 = unlimited
    required_approval:     bool        = False # Human-in-the-loop flag (logged)


@dataclass
class AgentManifest:
    agent_id:               str
    capabilities:           list[ToolCapability] = field(default_factory=list)
    network_egress_allowed: bool                 = False
    default_deny:           bool                 = True   # always True in practice
    description:            str                  = ""

    def get_capability(self, tool_name: str) -> ToolCapability | None:
        for cap in self.capabilities:
            if cap.tool_name == tool_name:
                return cap
        return None


@dataclass
class SandboxDecision:
    allowed:            bool
    reason:             str  = ""
    requires_approval:  bool = False
    calls_remaining:    int  = -1   # -1 = unlimited; 0+ = remaining quota


# ── Registry ──────────────────────────────────────────────────────────────────

class SandboxRegistry:
    """
    Central manifest registry.

    Thread-safe for reads (manifests are loaded once; updates require reload).
    Uses Redis for per-session call counting.
    """

    def __init__(self) -> None:
        self._manifests: dict[str, AgentManifest] = {}
        self._loaded = False

    # ── Public API ────────────────────────────────────────────────────────────

    def register(self, manifest: AgentManifest) -> None:
        """Register or replace a manifest at runtime."""
        self._manifests[manifest.agent_id] = manifest
        log.info(
            "SandboxRegistry: registered agent_id=%r tools=%d egress=%s",
            manifest.agent_id,
            len(manifest.capabilities),
            manifest.network_egress_allowed,
        )

    def load_from_file(self, path: str | Path | None = None) -> int:
        """
        Load manifests from JSON file.  Returns number of manifests loaded.
        Call once at FastAPI lifespan startup.
        """
        p = Path(path or _SANDBOX_PATH)
        if not p.exists():
            if _STRICT:
                log.warning(
                    "SandboxRegistry: AGENT_SANDBOX_PATH=%s not found — "
                    "strict mode: all tool calls will be denied.", p
                )
            else:
                log.info(
                    "SandboxRegistry: no manifest file (%s) — sandbox checks skipped.", p
                )
            self._loaded = True
            return 0

        try:
            data = json.loads(p.read_text())
            count = 0
            for entry in data.get("manifests", []):
                caps = [
                    ToolCapability(
                        tool_name             = c["tool_name"],
                        allowed_params        = c.get("allowed_params", []),
                        max_calls_per_session = int(c.get("max_calls_per_session", 0)),
                        required_approval     = bool(c.get("required_approval", False)),
                    )
                    for c in entry.get("capabilities", [])
                ]
                self.register(AgentManifest(
                    agent_id               = entry["agent_id"],
                    capabilities           = caps,
                    network_egress_allowed = bool(entry.get("network_egress_allowed", False)),
                    default_deny           = bool(entry.get("default_deny", True)),
                    description            = entry.get("description", ""),
                ))
                count += 1
            log.info("SandboxRegistry: loaded %d manifest(s) from %s", count, p)
            self._loaded = True
            return count
        except Exception as exc:
            log.warning("SandboxRegistry: failed to load manifests: %s", exc)
            self._loaded = True
            return 0

    def authorize_tool_call(
        self,
        agent_id:    str,
        tool_name:   str,
        params:      dict,
        session_id:  str = "",
        target_host: str = "",
    ) -> SandboxDecision:
        """
        The Zero-Trust check.  Returns SandboxDecision with allowed=True/False.

        Called by ToolCallGuard.inspect_call() before any regex scanning.
        Fail-open: if sandbox is not loaded or Redis is down, returns allowed=True
        (unless AGENT_SANDBOX_STRICT=true).
        """
        # ── No manifests loaded → skip or strict deny ─────────────────────
        if not self._manifests:
            if _STRICT:
                return SandboxDecision(
                    allowed=False,
                    reason="no_manifest_file_strict",
                )
            return SandboxDecision(allowed=True, reason="sandbox_not_configured")

        # ── 1. Agent manifest lookup ──────────────────────────────────────
        manifest = self._manifests.get(agent_id)
        if manifest is None:
            log.warning(
                "SandboxRegistry: DENY agent_id=%r — no manifest registered",
                agent_id,
            )
            return SandboxDecision(allowed=False, reason="no_manifest")

        # ── 2. Tool capability lookup ─────────────────────────────────────
        cap = manifest.get_capability(tool_name)
        if cap is None:
            log.warning(
                "SandboxRegistry: DENY agent_id=%r tool=%r — not in capabilities",
                agent_id, tool_name,
            )
            return SandboxDecision(allowed=False, reason="tool_not_allowed")

        # ── 3. Parameter allow-list ───────────────────────────────────────
        if cap.allowed_params:
            denied_params = [p for p in params if p not in cap.allowed_params]
            if denied_params:
                log.warning(
                    "SandboxRegistry: DENY agent_id=%r tool=%r disallowed_params=%r",
                    agent_id, tool_name, denied_params,
                )
                return SandboxDecision(
                    allowed=False,
                    reason=f"param_not_allowed:{','.join(denied_params)}",
                )

        # ── 4. Session call quota ─────────────────────────────────────────
        if cap.max_calls_per_session > 0 and session_id:
            count = self._get_call_count(agent_id, session_id, tool_name)
            if count >= cap.max_calls_per_session:
                log.warning(
                    "SandboxRegistry: DENY agent_id=%r tool=%r "
                    "quota=%d reached (session=%s)",
                    agent_id, tool_name, cap.max_calls_per_session, session_id,
                )
                return SandboxDecision(
                    allowed=False,
                    reason=f"quota_exceeded:{count}/{cap.max_calls_per_session}",
                    calls_remaining=0,
                )
            remaining = cap.max_calls_per_session - count
            # Increment counter (non-blocking — fail-open on Redis error)
            self._incr_call_count(agent_id, session_id, tool_name)
        else:
            remaining = -1

        # ── 5. Network egress check ───────────────────────────────────────
        if not manifest.network_egress_allowed and tool_name in _NETWORK_WRITE_TOOLS:
            log.warning(
                "SandboxRegistry: DENY agent_id=%r tool=%r — network egress disabled",
                agent_id, tool_name,
            )
            return SandboxDecision(
                allowed=False,
                reason="network_egress_denied",
            )

        # ── 6. Dynamic Taint Revocation (WormGuard v2.5) ─────────────────
        # Overrides the static manifest when the session has EXTERNAL or
        # HOSTILE tainted context (e.g. agent read a poisoned email).
        try:
            from warden.taint_tracker import check_tool_taint  # noqa: PLC0415
            _taint = check_tool_taint(session_id, tool_name, target_host)
            if _taint.revoked:
                log.warning(
                    "SandboxRegistry: DENY (taint) agent_id=%r tool=%r — %s",
                    agent_id, tool_name, _taint.reason[:120],
                )
                return SandboxDecision(
                    allowed           = False,
                    reason            = _taint.reason,
                    requires_approval = _taint.hitl_required,
                )
        except Exception as _te:
            log.debug("SandboxRegistry: taint check error (non-fatal): %s", _te)

        # ── ALLOW ─────────────────────────────────────────────────────────
        if cap.required_approval:
            log.warning(
                "SandboxRegistry: ALLOW (requires_approval) agent_id=%r tool=%r",
                agent_id, tool_name,
            )
        return SandboxDecision(
            allowed           = True,
            requires_approval = cap.required_approval,
            calls_remaining   = remaining,
        )

    def get_manifest(self, agent_id: str) -> AgentManifest | None:
        return self._manifests.get(agent_id)

    def list_agents(self) -> list[dict]:
        return [
            {
                "agent_id":               m.agent_id,
                "description":            m.description,
                "tools":                  [c.tool_name for c in m.capabilities],
                "network_egress_allowed": m.network_egress_allowed,
            }
            for m in self._manifests.values()
        ]

    def reload(self) -> int:
        """Force-reload manifests from file."""
        self._manifests.clear()
        self._loaded = False
        return self.load_from_file()

    # ── Redis call counting ───────────────────────────────────────────────────

    @staticmethod
    def _redis():
        try:
            from warden.cache import _get_client  # noqa: PLC0415
            return _get_client()
        except Exception:
            return None

    def _call_key(self, agent_id: str, session_id: str, tool_name: str) -> str:
        return f"warden:sandbox:{agent_id}:{session_id}:{tool_name}"

    def _get_call_count(self, agent_id: str, session_id: str, tool_name: str) -> int:
        r = self._redis()
        if r is None:
            return 0
        try:
            val = r.get(self._call_key(agent_id, session_id, tool_name))
            return int(val) if val else 0
        except Exception:
            return 0

    def _incr_call_count(self, agent_id: str, session_id: str, tool_name: str) -> None:
        r = self._redis()
        if r is None:
            return
        try:
            key = self._call_key(agent_id, session_id, tool_name)
            r.incr(key)
            r.expire(key, _SESSION_TTL)
        except Exception:
            pass


# ── Module-level singleton ────────────────────────────────────────────────────

_registry = SandboxRegistry()


def get_registry() -> SandboxRegistry:
    """Return the shared SandboxRegistry singleton."""
    return _registry
