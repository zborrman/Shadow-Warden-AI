"""
warden/api/retention.py  (CP-26)
─────────────────────────────────
Data retention policy enforcement — per-tenant, per-data-class configurable
retention windows with background enforcement.

Policy model
────────────
  Each tenant may define retention windows (in days) per data_class:
    PII        default 30 days
    PHI        default 30 days
    FINANCIAL  default 90 days
    SECRETS    default 7  days
    GENERAL    default 180 days

  Policies are stored in Redis hash `retention:policy:{tenant_id}`.
  Falls back to in-process dict when Redis unavailable.

  The ARQ cron `sova_retention_enforce` runs daily 03:30 UTC and
  calls `enforce_retention(tenant_id)` for all tenants with policies.

Endpoints
─────────
  GET  /retention/policy                  → current policy (all data_classes)
  PUT  /retention/policy                  → update one or more data_class windows
  DELETE /retention/policy/{data_class}   → reset to default
  POST /retention/enforce                 → trigger enforcement now (admin)
  GET  /retention/stats                   → last enforcement stats
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query

from warden.config import settings

log = logging.getLogger("warden.api.retention")

router = APIRouter(prefix="/retention", tags=["retention"])

# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULT_RETENTION_DAYS: dict[str, int] = {
    "PII":       settings.retention_pii_days,
    "PHI":       settings.retention_phi_days,
    "FINANCIAL": settings.retention_financial_days,
    "SECRETS":   settings.retention_secrets_days,
    "GENERAL":   settings.retention_general_days,
}

_ALL_CLASSES = set(DEFAULT_RETENTION_DAYS.keys())

_MEMORY_POLICIES: dict[str, dict[str, int]] = {}
_MEMORY_STATS:    dict[str, dict]            = {}


# ── Redis helpers ──────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = settings.redis_url
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


def _load_policy(tenant_id: str) -> dict[str, int]:
    r = _redis()
    if r:
        try:
            raw = r.hgetall(f"retention:policy:{tenant_id}")
            if raw:
                return {k: int(v) for k, v in raw.items()}
        except Exception as exc:
            log.debug("retention _load_policy redis: %s", exc)
    return dict(_MEMORY_POLICIES.get(tenant_id, {}))


def _save_policy(tenant_id: str, policy: dict[str, int]) -> None:
    _MEMORY_POLICIES[tenant_id] = dict(policy)
    r = _redis()
    if r:
        try:
            key = f"retention:policy:{tenant_id}"
            r.delete(key)
            if policy:
                r.hset(key, mapping={k: str(v) for k, v in policy.items()})
        except Exception as exc:
            log.debug("retention _save_policy redis: %s", exc)


def _save_stats(tenant_id: str, stats: dict) -> None:
    _MEMORY_STATS[tenant_id] = stats
    r = _redis()
    if r:
        try:
            r.setex(f"retention:stats:{tenant_id}", 86_400, json.dumps(stats))
        except Exception as exc:
            log.debug("retention _save_stats redis: %s", exc)


def _load_stats(tenant_id: str) -> dict | None:
    r = _redis()
    if r:
        try:
            raw = r.get(f"retention:stats:{tenant_id}")
            if raw:
                return json.loads(raw)
        except Exception as exc:
            log.debug("retention _load_stats redis: %s", exc)
    return _MEMORY_STATS.get(tenant_id)


# ── Effective policy (merge defaults with tenant overrides) ───────────────────

def get_effective_policy(tenant_id: str) -> dict[str, int]:
    overrides = _load_policy(tenant_id)
    return {cls: overrides.get(cls, DEFAULT_RETENTION_DAYS[cls]) for cls in _ALL_CLASSES}


# ── Enforcement ───────────────────────────────────────────────────────────────

def _classify_entry(entry: dict) -> str:
    """Map log entry flags/fields to a data class for retention purposes."""
    flags    = entry.get("flags", [])
    secrets  = entry.get("secrets_found", [])
    entities = entry.get("entities_detected", [])

    flags_str = " ".join(str(f) for f in flags + secrets + entities).upper()

    if any(kw in flags_str for kw in ("PHI", "HEALTH", "MEDICAL", "HIPAA")):
        return "PHI"
    if any(kw in flags_str for kw in ("PII", "EMAIL", "SSN", "IBAN", "PASSPORT", "PHONE")):
        return "PII"
    if any(kw in flags_str for kw in ("SECRET", "API_KEY", "PASSWORD", "TOKEN", "CREDENTIAL")):
        return "SECRETS"
    if any(kw in flags_str for kw in ("FINANCIAL", "CREDIT_CARD", "BANK", "TAX")):
        return "FINANCIAL"
    return "GENERAL"


def enforce_retention(tenant_id: str = "default") -> dict:
    """
    Purge log entries that exceed the tenant's per-data-class retention window.
    Rewrites logs.json atomically. Returns enforcement stats.
    """
    from warden.analytics.logger import LOGS_PATH, _lock

    policy  = get_effective_policy(tenant_id)
    now     = datetime.now(UTC)
    removed = 0
    kept    = []
    breakdown: dict[str, int] = dict.fromkeys(_ALL_CLASSES, 0)

    if not LOGS_PATH.exists():
        stats = {"tenant_id": tenant_id, "removed": 0, "ts": now.isoformat(), "breakdown": breakdown}
        _save_stats(tenant_id, stats)
        return stats

    import json as _json

    with LOGS_PATH.open("r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = _json.loads(raw)
            except _json.JSONDecodeError:
                kept.append(raw)
                continue

            ts_str = entry.get("ts") or entry.get("timestamp") or ""
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                kept.append(raw)
                continue

            cls       = _classify_entry(entry)
            max_days  = policy.get(cls, DEFAULT_RETENTION_DAYS.get(cls, 180))
            cutoff    = now - timedelta(days=max_days)

            if ts < cutoff:
                removed += 1
                breakdown[cls] = breakdown.get(cls, 0) + 1
            else:
                kept.append(raw)

    if removed:
        import os as _os
        tmp = LOGS_PATH.with_suffix(".tmp")
        with _lock:
            tmp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            _os.replace(tmp, LOGS_PATH)
        log.info("retention: tenant=%s removed=%d entries", tenant_id, removed)

    stats = {
        "tenant_id":    tenant_id,
        "removed":      removed,
        "entries_kept": len(kept),
        "ts":           now.isoformat(),
        "policy":       policy,
        "breakdown":    breakdown,
    }
    _save_stats(tenant_id, stats)
    return stats


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/policy", summary="Get retention policy for tenant (CP-26)")
async def get_policy(
    tenant_id: Annotated[str, Query()] = "default",
) -> dict:
    policy   = get_effective_policy(tenant_id)
    overrides = _load_policy(tenant_id)
    return {
        "tenant_id":  tenant_id,
        "policy":     policy,
        "overrides":  overrides,
        "defaults":   DEFAULT_RETENTION_DAYS,
        "generated_at": datetime.now(UTC).isoformat(),
    }


@router.put("/policy", summary="Update retention windows per data_class (CP-26)")
async def update_policy(
    body:      dict,
    tenant_id: Annotated[str, Query()] = "default",
) -> dict:
    current = _load_policy(tenant_id)
    updated: dict[str, int] = {}
    for cls, days in body.items():
        cls = cls.upper()
        if cls not in _ALL_CLASSES:
            raise HTTPException(400, f"Unknown data_class: {cls!r}. Valid: {sorted(_ALL_CLASSES)}")
        if not isinstance(days, int) or days < 1 or days > 3650:
            raise HTTPException(400, f"Retention days must be an integer 1–3650 (got {days!r})")
        updated[cls] = days

    merged = {**current, **updated}
    _save_policy(tenant_id, merged)
    log.info("retention policy updated tenant=%s changes=%s", tenant_id, updated)
    return {
        "tenant_id":    tenant_id,
        "policy":       get_effective_policy(tenant_id),
        "updated_keys": list(updated.keys()),
    }


@router.delete("/policy/{data_class}", summary="Reset a data_class to default retention (CP-26)")
async def reset_policy(
    data_class: str,
    tenant_id:  Annotated[str, Query()] = "default",
) -> dict:
    cls = data_class.upper()
    if cls not in _ALL_CLASSES:
        raise HTTPException(404, f"Unknown data_class: {cls!r}")
    current = _load_policy(tenant_id)
    current.pop(cls, None)
    _save_policy(tenant_id, current)
    return {
        "tenant_id":    tenant_id,
        "data_class":   cls,
        "reset_to_days": DEFAULT_RETENTION_DAYS[cls],
        "policy":       get_effective_policy(tenant_id),
    }


@router.post("/enforce", summary="Trigger retention enforcement now (CP-26)")
async def trigger_enforce(
    tenant_id: Annotated[str, Query()] = "default",
) -> dict:
    stats = enforce_retention(tenant_id)
    return stats


@router.get("/stats", summary="Last enforcement run statistics (CP-26)")
async def get_stats(
    tenant_id: Annotated[str, Query()] = "default",
) -> dict:
    stats = _load_stats(tenant_id)
    if not stats:
        return {
            "tenant_id": tenant_id,
            "message":   "No enforcement run recorded yet. POST /retention/enforce to trigger.",
        }
    return stats
