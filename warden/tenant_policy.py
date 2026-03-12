"""
warden/tenant_policy.py
━━━━━━━━━━━━━━━━━━━━━━
Per-tenant behavioral policy for the AgentMonitor.

Loads from TENANT_POLICIES_PATH (JSON file) with hot-reload on SIGHUP.
Falls back to module-level defaults derived from existing env vars so that
existing deployments that have not created a policies file continue to work
exactly as before.

JSON schema
───────────
{
  "default": {
    "velocity_threshold":    10,
    "rapid_block_threshold": 3,
    "session_ttl":           1800,
    "velocity_window":       60
  },
  "tenant-abc": {
    "rapid_block_threshold": 2
  }
}

Each tenant block is merged onto the defaults — only the keys that are present
override the corresponding field.  Unknown keys are silently ignored.

SIGHUP hot-reload
─────────────────
Send ``kill -HUP <pid>`` (or ``docker kill --signal=HUP <container>``) to
reload policies without restarting the gateway:

    kill -HUP $(pgrep -f "uvicorn warden.main")
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import threading
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("warden.tenant_policy")

# ── Defaults — mirror existing env vars so zero-config upgrades are safe ──────

_DEFAULT_VELOCITY_THRESHOLD    = int(os.getenv("VELOCITY_THRESHOLD",    "10"))
_DEFAULT_RAPID_BLOCK_THRESHOLD = int(os.getenv("RAPID_BLOCK_THRESHOLD", "3"))
_DEFAULT_SESSION_TTL           = int(os.getenv("AGENT_SESSION_TTL",     "1800"))
_DEFAULT_VELOCITY_WINDOW       = int(os.getenv("VELOCITY_WINDOW_SECS",  "60"))

TENANT_POLICIES_PATH = Path(
    os.getenv("TENANT_POLICIES_PATH", "/warden/data/tenant_policies.json")
)


# ── TenantPolicy ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TenantPolicy:
    """Behavioral thresholds applied by AgentMonitor for a single tenant."""

    velocity_threshold:    int = field(default_factory=lambda: _DEFAULT_VELOCITY_THRESHOLD)
    rapid_block_threshold: int = field(default_factory=lambda: _DEFAULT_RAPID_BLOCK_THRESHOLD)
    session_ttl:           int = field(default_factory=lambda: _DEFAULT_SESSION_TTL)
    velocity_window:       int = field(default_factory=lambda: _DEFAULT_VELOCITY_WINDOW)


#: Singleton default policy (module-level constants; evaluated once at import time)
DEFAULT_POLICY = TenantPolicy(
    velocity_threshold    = _DEFAULT_VELOCITY_THRESHOLD,
    rapid_block_threshold = _DEFAULT_RAPID_BLOCK_THRESHOLD,
    session_ttl           = _DEFAULT_SESSION_TTL,
    velocity_window       = _DEFAULT_VELOCITY_WINDOW,
)


# ── TenantPolicyStore ─────────────────────────────────────────────────────────

class TenantPolicyStore:
    """
    Thread-safe per-tenant policy registry.

    Loaded lazily from *path* (JSON).  Missing file → all tenants use
    ``DEFAULT_POLICY``.  Unknown tenants fall back to the ``"default"`` entry
    in the file, and then to ``DEFAULT_POLICY`` if no ``"default"`` entry
    exists.

    A SIGHUP signal triggers ``reload()`` for zero-downtime policy updates.
    SIGHUP registration is skipped silently on Windows or in non-main threads.
    """

    def __init__(self, path: Path = TENANT_POLICIES_PATH) -> None:
        self._path  = path
        self._lock  = threading.RLock()
        self._cache: dict[str, TenantPolicy] = {}
        self._load()
        self._register_sighup()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Parse the policies JSON file and populate ``_cache``."""
        if not self._path.exists():
            with self._lock:
                self._cache = {}
            return

        try:
            raw: dict = json.loads(self._path.read_text(encoding="utf-8"))
            cache: dict[str, TenantPolicy] = {}
            for tid, cfg in raw.items():
                if not isinstance(cfg, dict):
                    continue
                cache[tid] = TenantPolicy(
                    velocity_threshold    = int(cfg.get(
                        "velocity_threshold",    _DEFAULT_VELOCITY_THRESHOLD)),
                    rapid_block_threshold = int(cfg.get(
                        "rapid_block_threshold", _DEFAULT_RAPID_BLOCK_THRESHOLD)),
                    session_ttl           = int(cfg.get(
                        "session_ttl",           _DEFAULT_SESSION_TTL)),
                    velocity_window       = int(cfg.get(
                        "velocity_window",       _DEFAULT_VELOCITY_WINDOW)),
                )
            with self._lock:
                self._cache = cache
            log.info(
                "TenantPolicyStore: loaded %d tenant policy(ies) from %s",
                len(cache), self._path,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "TenantPolicyStore: could not load %s — using defaults: %s",
                self._path, exc,
            )

    def reload(self) -> None:
        """Hot-reload policies from disk.  Called by the SIGHUP handler."""
        log.info("TenantPolicyStore: hot-reloading tenant policies…")
        self._load()

    # ── Lookup ────────────────────────────────────────────────────────────────

    def get(self, tenant_id: str) -> TenantPolicy:
        """
        Return the policy for *tenant_id*.

        Precedence:
          1. Exact tenant match in loaded cache.
          2. ``"default"`` entry in loaded cache.
          3. ``DEFAULT_POLICY`` (env-var driven hard defaults).
        """
        with self._lock:
            if tenant_id in self._cache:
                return self._cache[tenant_id]
            if "default" in self._cache:
                return self._cache["default"]
        return DEFAULT_POLICY

    # ── SIGHUP registration ───────────────────────────────────────────────────

    def _register_sighup(self) -> None:
        # SIGHUP is unavailable on Windows; also fails if called from a
        # non-main thread (e.g., pytest fixtures).
        with contextlib.suppress(OSError, ValueError, AttributeError):
            signal.signal(signal.SIGHUP, lambda _sig, _frame: self.reload())  # type: ignore[attr-defined]


# ── Module-level singleton + convenience helpers ──────────────────────────────

_store: TenantPolicyStore | None = None
_store_lock = threading.Lock()


def get_store() -> TenantPolicyStore:
    """Return (lazily creating) the module-level ``TenantPolicyStore``."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = TenantPolicyStore()
    return _store


def get_policy(tenant_id: str) -> TenantPolicy:
    """Return the behavioral policy for *tenant_id* (shorthand for ``get_store().get(tenant_id)``)."""
    return get_store().get(tenant_id)
