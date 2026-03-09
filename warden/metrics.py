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
    from prometheus_client import Counter, Histogram, REGISTRY  # noqa: F401

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

    TOOL_BLOCKS = _Noop()  # type: ignore[assignment]
