"""
warden/sovereign/policy.py
────────────────────────────
Per-tenant Sovereign AI Cloud routing policy.

Policy document (stored in Redis `sovereign:policy:{tenant_id}`):
{
    "tenant_id":            "acme-corp",
    "home_jurisdiction":    "EU",
    "allowed_jurisdictions": ["EU", "UK"],
    "blocked_jurisdictions": ["CN", "RU"],
    "data_class_overrides": {
        "PHI":        ["US"],          # PHI may only go to US (HIPAA)
        "CLASSIFIED": []               # classified data never routed externally
    },
    "require_attestation":  true,      # generate attestation for every routed call
    "fallback_mode":        "BLOCK",   # "BLOCK" | "DIRECT" when no tunnel available
    "preferred_tunnel_id":  "t-abc123", # optional fixed tunnel preference
    "updated_at":           "2026-07-01T09:00:00Z"
}

Fallback modes:
  BLOCK   — reject the request when no compliant tunnel is available (default, safest)
  DIRECT  — allow the call to proceed without a tunnel (logs a compliance warning)
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

log = logging.getLogger("warden.sovereign.policy")

_DEFAULT: dict = {
    "home_jurisdiction":     "EU",
    "allowed_jurisdictions": ["EU"],
    "blocked_jurisdictions": [],
    "data_class_overrides":  {},
    "require_attestation":   True,
    "fallback_mode":         "BLOCK",
    "preferred_tunnel_id":   None,
    "updated_at":            "",
}

_MEMORY_STORE: dict[str, dict] = {}


def _redis():
    try:
        import os  # noqa: PLC0415

        import redis as _r  # noqa: PLC0415
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


def get_policy(tenant_id: str) -> dict:
    r = _redis()
    if r:
        try:
            raw = r.get(f"sovereign:policy:{tenant_id}")
            if raw:
                return json.loads(raw)
        except Exception as exc:
            log.debug("get_policy redis error: %s", exc)
    return {**_DEFAULT, "tenant_id": tenant_id}


def update_policy(tenant_id: str, patch: dict) -> dict:
    """Merge *patch* into existing policy and persist. Returns updated doc."""
    valid_fallbacks = {"BLOCK", "DIRECT"}
    current = get_policy(tenant_id)
    updated = {**current, **patch, "tenant_id": tenant_id}

    if updated.get("fallback_mode") not in valid_fallbacks:
        raise ValueError(f"Invalid fallback_mode. Use: {valid_fallbacks}")

    from warden.sovereign.jurisdictions import JURISDICTIONS
    for jcode in updated.get("allowed_jurisdictions", []):
        if jcode not in JURISDICTIONS:
            raise ValueError(f"Unknown jurisdiction: {jcode!r}")

    updated["allowed_jurisdictions"] = sorted(set(updated.get("allowed_jurisdictions", [])))
    updated["blocked_jurisdictions"] = sorted(set(updated.get("blocked_jurisdictions", [])))
    updated["updated_at"] = datetime.now(UTC).isoformat()

    _MEMORY_STORE[tenant_id] = updated
    r = _redis()
    if r:
        try:
            r.set(f"sovereign:policy:{tenant_id}", json.dumps(updated))
        except Exception as exc:
            log.debug("update_policy redis write error: %s", exc)
    return updated


def is_jurisdiction_allowed(jurisdiction: str, tenant_id: str) -> bool:
    """Return True when *jurisdiction* is permitted for this tenant's data."""
    pol = get_policy(tenant_id)
    if jurisdiction in pol.get("blocked_jurisdictions", []):
        return False
    allowed = pol.get("allowed_jurisdictions", [])
    if not allowed:
        return True
    return jurisdiction in allowed


def allowed_jurisdictions_for(
    data_class: str,
    tenant_id:  str,
) -> list[str]:
    """
    Return the list of allowed jurisdictions for a given data classification,
    respecting per-class overrides in the tenant's policy.
    """
    pol       = get_policy(tenant_id)
    overrides = pol.get("data_class_overrides", {})
    if data_class in overrides:
        return overrides[data_class]
    return pol.get("allowed_jurisdictions", [])
