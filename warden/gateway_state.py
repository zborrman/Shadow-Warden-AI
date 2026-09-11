"""
warden/gateway_state.py
───────────────────────
Process-wide mutable state for the ``/filter`` gateway that more than one route
touches:

  • the live-tunable knobs ``POST /api/config`` rebinds while the filter
    pipeline reads them (``fail_strategy``, ``pipeline_timeout_ms``,
    ``uncertainty_lower``)
  • the resilience sliding windows appended by the pipeline and read/pruned by
    ``GET /health`` (``bypass_window`` / ``filter_window``)
  • the multi-tenant SemanticGuard registry (``tenant_guards``) — main.py's
    ``_get_tenant_guard()`` still owns *constructing* a guard (it imports the
    heavy ``BrainSemanticGuard`` class); this module only owns the dict, kept
    untyped (``Any``) so this leaf never imports the ML stack

Historically these were module globals in ``warden/main.py``; extracting the ops
routes out of main.py (P-2) needs a shared, dependency-free leaf that both the
pipeline and ``warden/api/system.py`` can import. Stdlib only — never imports a
warden package, so it can't join an import cycle.

Seeded from the environment at import, exactly as the old main.py constants were.
"""
from __future__ import annotations

import os
from collections import deque
from dataclasses import dataclass, field
from typing import Any


def _env_fail_strategy() -> str:
    # "open"  → pass request through on pipeline timeout (business priority)
    # "closed" → block request on pipeline timeout        (security priority)
    return os.getenv("WARDEN_FAIL_STRATEGY", "open").lower()


def _env_pipeline_timeout_ms() -> int:
    return int(os.getenv("PIPELINE_TIMEOUT_MS", "0"))  # 0 = disabled


def _env_uncertainty_lower() -> float:
    # Requests with ML score in [uncertainty_lower, threshold) are flagged
    # ML_UNCERTAIN and escalated to MEDIUM. 0 disables the band.
    return float(os.getenv("UNCERTAINTY_LOWER_THRESHOLD", "0.55"))


@dataclass
class GatewayState:
    fail_strategy: str = field(default_factory=_env_fail_strategy)
    pipeline_timeout_ms: int = field(default_factory=_env_pipeline_timeout_ms)
    uncertainty_lower: float = field(default_factory=_env_uncertainty_lower)

    # perf_counter() timestamps (seconds); pruned to the last 60 s on every
    # /health read — no background task.
    bypass_window: deque[float] = field(default_factory=deque)   # fail-open bypass events
    filter_window: deque[float] = field(default_factory=deque)   # all /filter requests (denominator)

    # tenant_id -> BrainSemanticGuard (kept as Any — see module docstring)
    tenant_guards: dict[str, Any] = field(default_factory=dict)

    def set_uncertainty_lower(self, value: float) -> float:
        """Clamp to [0.0, 0.99], mirror into the env var, return the applied value.

        ``POST /api/config`` is the only writer. Both effects are **process-local**
        — the value is not shared across uvicorn workers and a container restart
        reloads the deployment ``.env``. This carries over the exact behaviour of
        the old main.py handler; a cross-worker durable config store is out of
        scope for the P-2 extraction.
        """
        self.uncertainty_lower = max(0.0, min(0.99, value))
        os.environ["UNCERTAINTY_LOWER_THRESHOLD"] = str(self.uncertainty_lower)
        return self.uncertainty_lower

    def reset(self) -> None:
        """Re-seed from the environment and clear the windows (test teardown)."""
        self.fail_strategy = _env_fail_strategy()
        self.pipeline_timeout_ms = _env_pipeline_timeout_ms()
        self.uncertainty_lower = _env_uncertainty_lower()
        self.bypass_window.clear()
        self.filter_window.clear()


gateway_state = GatewayState()
