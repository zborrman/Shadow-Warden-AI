"""
warden/runtime.py
──────────────────
Process-wide runtime state container (architecture Phase 1).

Historically, feature modules reached back into ``warden.main`` to grab shared
singletons (``from warden import main; main._brain_guard``). Because ``main``
imports nearly every domain package, those reach-backs created import cycles —
worked around with 100s of lazy ``# noqa: PLC0415`` imports.

This module is the canonical, **dependency-free leaf** that holds those shared
singletons. ``main`` *publishes* into it at startup; domains *read* from it and
never import ``main``. Nothing in this file imports a warden domain package, so
it can never participate in a cycle.

Usage
─────
    # in main.py lifespan, after building the singletons:
    from warden import runtime
    runtime.publish(brain_guard=_brain_guard, evolve=_evolve)

    # in a domain module (no import of warden.main):
    from warden.runtime import runtime
    guard = runtime.brain_guard          # None until main has published
"""
from __future__ import annotations

import threading
from typing import Any

__all__ = ["Runtime", "runtime", "publish"]


class Runtime:
    """Holds shared, process-wide service singletons. Thread-safe assignment.

    Slots are ``None`` until ``main`` publishes them during startup. Readers must
    tolerate ``None`` (e.g. in unit tests that never boot the app) and fall back
    to constructing a local instance.
    """

    __slots__ = ("_lock", "_slots")

    # Known shared singletons. Add a name here when a new one needs sharing.
    _KNOWN = (
        "brain_guard",       # BrainSemanticGuard — default-tenant ML guard
        "evolve",            # EvolutionEngine
        "semantic_engine",   # semantic-layer engine singleton
        "redactor",          # SecretRedactor
        "guard",             # SemanticGuard (rule engine)
        "agent_monitor",     # AgentMonitor
    )

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._slots: dict[str, Any] = dict.fromkeys(self._KNOWN)

    def publish(self, **services: Any) -> None:
        """Set one or more shared singletons. Unknown names are accepted too."""
        with self._lock:
            for name, value in services.items():
                self._slots[name] = value

    def get(self, name: str, default: Any = None) -> Any:
        return self._slots.get(name, default)

    def clear(self) -> None:
        """Reset all slots (test teardown)."""
        with self._lock:
            self._slots = dict.fromkeys(self._slots)

    def __getattr__(self, name: str) -> Any:
        # Attribute access for known/published slots: runtime.brain_guard
        try:
            slots = object.__getattribute__(self, "_slots")
        except AttributeError:  # during __init__
            raise AttributeError(name) from None
        if name in slots:
            return slots[name]
        raise AttributeError(f"Runtime has no service {name!r}")


# Singleton instance — import this, not the class.
runtime = Runtime()


def publish(**services: Any) -> None:
    """Module-level convenience wrapper around ``runtime.publish``."""
    runtime.publish(**services)
