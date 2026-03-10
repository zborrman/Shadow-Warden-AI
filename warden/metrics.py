"""
warden/metrics.py
─────────────────
Shared Prometheus metric singletons for the Warden gateway.

Import from here — never instantiate metrics in individual modules —
to guarantee a single registration per process and avoid
ValueError("Duplicated timeseries") when modules are reloaded in tests.

All metrics use the ``try/except`` registry guard pattern so the module
is safe to import multiple times (pytest reimports between test files).
"""
from __future__ import annotations

try:
    from prometheus_client import REGISTRY, Counter, Gauge, Histogram  # noqa: F401

    # ── Tool block counter ────────────────────────────────────────────────────
    # Incremented by openai_proxy.py on every ToolCallGuard block (Phase A + B).
    #
    # Labels:
    #   direction  "call" (Phase B — outgoing) | "result" (Phase A — incoming)
    #   tool_name  name of the blocked tool function
    #   threat     first threat kind (e.g. "shell_destruction", "prompt_injection")
    try:
        TOOL_BLOCKS = Counter(
            "warden_tool_blocks_total",
            "Number of tool calls/results blocked by ToolCallGuard",
            ["direction", "tool_name", "threat"],
        )
    except ValueError:
        # Already registered (e.g. test re-import) — retrieve existing
        TOOL_BLOCKS = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined]
            "warden_tool_blocks_total"
        )

    # ── Agent session metrics ─────────────────────────────────────────────────
    # Populated by AgentMonitor in warden/agent_monitor.py.

    try:
        AGENT_SESSIONS_ACTIVE = Gauge(
            "warden_agent_sessions_active",
            "Active agent sessions within the TTL window",
        )
    except ValueError:
        AGENT_SESSIONS_ACTIVE = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined]
            "warden_agent_sessions_active"
        )

    try:
        AGENT_ANOMALIES_TOTAL = Counter(
            "warden_agent_anomalies_total",
            "Session-level anomalies detected by AgentMonitor",
            ["pattern_type", "severity"],
        )
    except ValueError:
        AGENT_ANOMALIES_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined]
            "warden_agent_anomalies_total"
        )

    try:
        AGENT_SESSION_BLOCKS = Counter(
            "warden_agent_session_blocks_total",
            "Blocked events in agent sessions per tenant",
            ["tenant_id"],
        )
    except ValueError:
        AGENT_SESSION_BLOCKS = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined]
            "warden_agent_session_blocks_total"
        )

    # ── EvolutionEngine skip counter ──────────────────────────────────────────
    # Incremented by brain/evolve.py whenever process_blocked() returns early.
    #
    # Label:
    #   reason  "low_risk"    — risk below EVOLUTION_MIN_RISK threshold
    #           "corpus_cap"  — MAX_CORPUS_RULES reached
    #           "duplicate"   — content SHA-256 already processed this session
    #           "rate_limited"— EVOLUTION_RATE_MAX calls/window exceeded
    try:
        EVOLUTION_SKIPPED_TOTAL = Counter(
            "warden_evolution_skipped_total",
            "EvolutionEngine calls skipped before reaching the Claude Opus API",
            ["reason"],
        )
    except ValueError:
        EVOLUTION_SKIPPED_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_evolution_skipped_total"
        )

    # ── Filter-stage latency (optional extension point) ───────────────────────
    # Already covered by prometheus-fastapi-instrumentator for HTTP-level
    # latency.  No extra histogram needed here yet.

    METRICS_ENABLED = True

except ImportError:
    METRICS_ENABLED = False

    class _Noop:  # type: ignore[no-redef]
        """Silent no-op for environments without prometheus_client."""
        def labels(self, **_kw):
            return self
        def inc(self, _amount: float = 1) -> None:
            pass
        def observe(self, _amount: float) -> None:
            pass
        def set(self, _value: float) -> None:
            pass

    TOOL_BLOCKS             = _Noop()  # type: ignore[assignment]
    AGENT_SESSIONS_ACTIVE   = _Noop()  # type: ignore[assignment]
    AGENT_ANOMALIES_TOTAL   = _Noop()  # type: ignore[assignment]
    AGENT_SESSION_BLOCKS    = _Noop()  # type: ignore[assignment]
    EVOLUTION_SKIPPED_TOTAL = _Noop()  # type: ignore[assignment]
