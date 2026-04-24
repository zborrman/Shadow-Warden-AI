"""
warden/offline.py
─────────────────
Offline-mode flag.  Set OFFLINE_MODE=true to run the full local filter
pipeline without any external dependencies:

  • Redis      → all cache / rate-limit calls become no-ops (fail-open)
  • MinIO / S3 → evidence bundles are dropped silently
  • Anthropic  → Evolution Engine and SOVA agent are disabled
  • ArXiv      → Intel Bridge is disabled

The 9-layer filter pipeline (topology, obfuscation, secrets, semantic,
brain, causal, phishing, ERS, decision) still runs fully locally —
no network calls, no data leaves the machine.

Typical use: laptop with no internet, air-gapped server, CI smoke tests.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("warden.offline")

_OFFLINE: bool = os.getenv("OFFLINE_MODE", "false").lower() in ("true", "1", "yes")

if _OFFLINE:
    log.warning(
        "OFFLINE_MODE=true — Redis, S3, Anthropic, and ArXiv are disabled. "
        "Local filter pipeline is fully active."
    )


def is_offline() -> bool:
    """Return True when OFFLINE_MODE env var is set."""
    return _OFFLINE


def require_online(feature: str) -> None:
    """Raise RuntimeError with a clear message if offline mode is active."""
    if _OFFLINE:
        raise RuntimeError(
            f"{feature} is not available in offline mode (OFFLINE_MODE=true). "
            "Disable OFFLINE_MODE or connect to the network."
        )
