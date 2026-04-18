"""
warden/shadow_ai/policy.py
────────────────────────────
Per-tenant Shadow AI Governance policy.

Policy document structure (stored in Redis):
    {
        "mode":            "MONITOR" | "BLOCK_DENYLIST" | "ALLOWLIST_ONLY",
        "allowlist":       ["openai", "anthropic"],   # always allowed
        "denylist":        ["huggingface"],            # always flagged/blocked
        "risk_threshold":  "LOW" | "MEDIUM" | "HIGH", # minimum risk to surface
        "notify_slack":    true,
        "updated_at":      "2026-04-17T12:00:00Z",
    }

Modes
─────
  MONITOR         Report all findings; no enforcement action.
  BLOCK_DENYLIST  Report + generate BLOCK events for denylist providers.
  ALLOWLIST_ONLY  Flag anything NOT on the allowlist (strictest).

Storage: Redis key `shadow_ai:policy:{tenant_id}` (no TTL — persists).
Falls back to in-process dict when Redis unavailable.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

log = logging.getLogger("warden.shadow_ai.policy")

_DEFAULT_POLICY: dict = {
    "mode":           "MONITOR",
    "allowlist":      [],
    "denylist":       [],
    "risk_threshold": "LOW",
    "notify_slack":   False,
    "updated_at":     "",
}

_MEMORY_STORE: dict[str, dict] = {}   # fallback when Redis unavailable


def _redis():
    """Return a Redis client or None on failure."""
    try:
        import os  # noqa: PLC0415

        import redis as _redis_lib  # noqa: PLC0415
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _redis_lib.from_url(url, decode_responses=True)
    except Exception:
        return None


def get_policy(tenant_id: str) -> dict:
    """Return the governance policy for *tenant_id* (never raises)."""
    r = _redis()
    if r:
        try:
            raw = r.get(f"shadow_ai:policy:{tenant_id}")
            if raw:
                return json.loads(raw)
        except Exception as exc:
            log.warning("get_policy redis error tenant=%s: %s", tenant_id, exc)

    return _MEMORY_STORE.get(tenant_id, dict(_DEFAULT_POLICY))


def update_policy(tenant_id: str, patch: dict) -> dict:
    """
    Merge *patch* into the tenant's existing policy and persist.

    Validates mode and risk_threshold values.
    Returns the updated policy document.
    """
    valid_modes   = {"MONITOR", "BLOCK_DENYLIST", "ALLOWLIST_ONLY"}
    valid_risks   = {"LOW", "MEDIUM", "HIGH"}

    current = get_policy(tenant_id)
    updated  = {**current, **patch}

    if updated.get("mode") not in valid_modes:
        raise ValueError(f"Invalid mode {updated['mode']!r}. Use: {valid_modes}")
    if updated.get("risk_threshold") not in valid_risks:
        raise ValueError(f"Invalid risk_threshold {updated['risk_threshold']!r}. Use: {valid_risks}")

    # Normalise lists
    updated["allowlist"] = sorted({k.lower() for k in updated.get("allowlist", [])})
    updated["denylist"]  = sorted({k.lower() for k in updated.get("denylist", [])})
    updated["updated_at"] = datetime.now(UTC).isoformat()

    # Persist
    r = _redis()
    if r:
        try:
            r.set(f"shadow_ai:policy:{tenant_id}", json.dumps(updated))
        except Exception as exc:
            log.warning("update_policy redis write error tenant=%s: %s", tenant_id, exc)
    _MEMORY_STORE[tenant_id] = updated

    return updated


def is_allowed(provider_key: str, tenant_id: str) -> bool:
    """
    Return True when this provider is governance-approved for *tenant_id*.

    MONITOR mode:       all allowed
    BLOCK_DENYLIST:     allowed unless on denylist
    ALLOWLIST_ONLY:     only allowed if on allowlist
    """
    pol = get_policy(tenant_id)
    k   = provider_key.lower()
    mode = pol.get("mode", "MONITOR")

    if mode == "MONITOR":
        return True
    if mode == "BLOCK_DENYLIST":
        return k not in pol.get("denylist", [])
    if mode == "ALLOWLIST_ONLY":
        return k in pol.get("allowlist", [])
    return True


def get_verdict(provider_key: str, tenant_id: str) -> str:
    """Return 'APPROVED' | 'FLAGGED' | 'BLOCKED' for a provider under current policy."""
    pol  = get_policy(tenant_id)
    k    = provider_key.lower()
    mode = pol.get("mode", "MONITOR")

    if k in pol.get("allowlist", []):
        return "APPROVED"
    if k in pol.get("denylist", []):
        return "BLOCKED" if mode != "MONITOR" else "FLAGGED"
    if mode == "ALLOWLIST_ONLY":
        return "FLAGGED"
    return "FLAGGED"
