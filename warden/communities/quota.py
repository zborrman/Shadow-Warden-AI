"""
warden/communities/quota.py
────────────────────────────
Storage, bandwidth, and entity-size quota enforcement for Communities.

Architecture
────────────
  Redis counters per community_id:
    warden:quota:{community_id}:storage_bytes      — total bytes stored
    warden:quota:{community_id}:bw_bytes:{YYYY-MM}  — monthly bandwidth

  SQLite fallback when Redis unavailable (dev/test).

Quota check flow
────────────────
  1. check_entity_size(tier, payload_bytes)       → HTTP 413 if > max_entity_bytes
  2. check_storage_quota(community_id, tier, bytes) → HTTP 402 if storage exhausted
  3. check_bandwidth_quota(community_id, tier, bytes) → HTTP 402 if bw exhausted

  On upload:   record_upload(community_id, bytes)
  On download: record_download(community_id, bytes)
  On delete:   release_storage(community_id, bytes)

Overage (Business / MCP)
─────────────────────────
  When overage_enabled=True, hard quota is not enforced — instead a flag
  overage_active is set in Redis and the billing webhook fires.
  The caller receives HTTP 202 with {"overage": true} in the response body.
  The Stripe/Paddle overage billing is handled by warden/billing/overage.py.

Referral bonus
──────────────
  apply_referral_bonus(community_id, referrer_id) adds referral_bonus_bytes
  to the community's storage quota. Stored as a separate key so it's auditable.

Guest tunnel "tax"
──────────────────
  Guests writing into a Business/MCP tunnel are counted against the HOST
  community's bandwidth. The host's bandwidth counter accumulates guest
  uploads — an incentive for guests to upgrade to Individual.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from datetime import UTC, datetime
from typing import Optional

log = logging.getLogger("warden.communities.quota")

_QUOTA_DB_PATH = os.getenv("QUOTA_DB_PATH", "/tmp/warden_quota.db")
_db_lock = threading.RLock()


# ── SQLite fallback store ─────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_QUOTA_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS quota_counters (
            community_id    TEXT NOT NULL,
            metric          TEXT NOT NULL,
            value_bytes     INTEGER NOT NULL DEFAULT 0,
            updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            PRIMARY KEY (community_id, metric)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS quota_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            community_id    TEXT NOT NULL,
            event_type      TEXT NOT NULL,
            bytes           INTEGER NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """)
    conn.commit()
    return conn


def _bw_metric() -> str:
    """Monthly bandwidth metric key: bw:{YYYY-MM}"""
    return f"bw:{datetime.now(UTC).strftime('%Y-%m')}"


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _redis_incr(key: str, delta: int, ttl_s: Optional[int] = None) -> int:
    """Increment Redis counter, return new value. Falls back to 0 on error."""
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            val = r.incrby(key, delta)
            if ttl_s and r.ttl(key) < 0:
                r.expire(key, ttl_s)
            return int(val)
    except Exception as exc:
        log.debug("quota: Redis incr error: %s", exc)
    return 0


def _redis_get(key: str) -> int:
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            val = r.get(key)
            return int(val) if val else 0
    except Exception:
        pass
    return 0


def _redis_set(key: str, value: int, ttl_s: Optional[int] = None) -> None:
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            if ttl_s:
                r.setex(key, ttl_s, value)
            else:
                r.set(key, value)
    except Exception:
        pass


# ── Counter keys ──────────────────────────────────────────────────────────────

def _storage_key(community_id: str) -> str:
    return f"warden:quota:{community_id}:storage_bytes"


def _bw_key(community_id: str) -> str:
    return f"warden:quota:{community_id}:{_bw_metric()}"


def _bonus_key(community_id: str) -> str:
    return f"warden:quota:{community_id}:bonus_bytes"


# ── Fallback SQLite counter ───────────────────────────────────────────────────

def _sqlite_get(community_id: str, metric: str) -> int:
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT value_bytes FROM quota_counters WHERE community_id=? AND metric=?",
            (community_id, metric)
        ).fetchone()
        return row["value_bytes"] if row else 0


def _sqlite_incr(community_id: str, metric: str, delta: int) -> int:
    with _db_lock:
        conn = _get_conn()
        conn.execute("""
            INSERT INTO quota_counters (community_id, metric, value_bytes)
            VALUES (?, ?, ?)
            ON CONFLICT(community_id, metric)
            DO UPDATE SET value_bytes = value_bytes + excluded.value_bytes,
                          updated_at  = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        """, (community_id, metric, delta))
        conn.commit()
        row = conn.execute(
            "SELECT value_bytes FROM quota_counters WHERE community_id=? AND metric=?",
            (community_id, metric)
        ).fetchone()
        return row["value_bytes"] if row else delta


def _get_counter(community_id: str, metric: str) -> int:
    """Get counter from Redis, fallback to SQLite."""
    key = f"warden:quota:{community_id}:{metric}"
    redis_val = _redis_get(key)
    if redis_val > 0:
        return redis_val
    return _sqlite_get(community_id, metric)


def _incr_counter(community_id: str, metric: str, delta: int, ttl_s: Optional[int] = None) -> int:
    """Increment counter in Redis + SQLite."""
    key = f"warden:quota:{community_id}:{metric}"
    redis_val = _redis_incr(key, delta, ttl_s)
    sqlite_val = _sqlite_incr(community_id, metric, delta)
    return redis_val if redis_val > 0 else sqlite_val


# ── Public API ────────────────────────────────────────────────────────────────

class QuotaExceeded(Exception):
    """Raised when a hard quota is hit (no overage for this tier)."""
    def __init__(self, metric: str, used: int, limit: int, upgrade_tier: str):
        self.metric       = metric
        self.used         = used
        self.limit        = limit
        self.upgrade_tier = upgrade_tier
        super().__init__(
            f"Quota exceeded: {metric} used={_fmt(used)} limit={_fmt(limit)}. "
            f"Upgrade to {upgrade_tier.upper()} tier or purchase an overage pack."
        )


class OverageRequired(Exception):
    """Raised when overage billing must be triggered (soft quota exceeded)."""
    def __init__(self, metric: str, used: int, limit: int):
        self.metric = metric
        self.used   = used
        self.limit  = limit
        super().__init__(
            f"Overage: {metric} used={_fmt(used)} limit={_fmt(limit)}. "
            "Billing overage charges apply."
        )


def _fmt(b: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024 or unit == "TB":
            return f"{b:.1f} {unit}"
        b /= 1024
    return str(b)


def check_entity_size(tier: str, payload_bytes: int) -> None:
    """
    Assert that a single entity does not exceed the tier's max_entity_bytes.

    Raises ValueError (HTTP 413) if too large.
    """
    from warden.billing.feature_gate import TIER_LIMITS, _normalize_tier
    limits = TIER_LIMITS[_normalize_tier(tier)]
    max_bytes = limits["max_entity_bytes"]
    if payload_bytes > max_bytes:
        raise ValueError(
            f"Entity size {_fmt(payload_bytes)} exceeds {tier.upper()} tier limit "
            f"of {_fmt(max_bytes)}. Use a smaller file or upgrade your plan."
        )


def check_storage_quota(community_id: str, tier: str, incoming_bytes: int) -> bool:
    """
    Check if adding *incoming_bytes* would exceed storage quota.

    Returns True  — within quota (proceed).
    Returns True  — overage enabled, overage will be billed (proceed).
    Raises QuotaExceeded — hard limit, no overage.

    Does NOT record the usage — call record_upload() after successful storage.
    """
    from warden.billing.feature_gate import TIER_LIMITS, _normalize_tier
    limits    = TIER_LIMITS[_normalize_tier(tier)]
    quota     = limits["storage_bytes"]
    bonus     = _get_counter(community_id, "bonus_bytes")
    effective = quota + bonus
    used      = get_storage_used(community_id)

    if used + incoming_bytes <= effective:
        return True

    if limits.get("overage_enabled"):
        raise OverageRequired("storage", used + incoming_bytes, effective)

    # Hard limit — suggest upgrade
    next_tier = "business" if tier == "individual" else "mcp"
    raise QuotaExceeded("storage", used + incoming_bytes, effective, next_tier)


def check_bandwidth_quota(community_id: str, tier: str, outgoing_bytes: int) -> bool:
    """
    Check if sending *outgoing_bytes* would exceed monthly bandwidth quota.

    Same semantics as check_storage_quota.
    """
    from warden.billing.feature_gate import TIER_LIMITS, _normalize_tier
    limits    = TIER_LIMITS[_normalize_tier(tier)]
    quota     = limits["bandwidth_bytes_per_month"]
    used      = get_bandwidth_used(community_id)

    if used + outgoing_bytes <= quota:
        return True

    if limits.get("overage_enabled"):
        raise OverageRequired("bandwidth", used + outgoing_bytes, quota)

    next_tier = "business" if tier == "individual" else "mcp"
    raise QuotaExceeded("bandwidth", used + outgoing_bytes, quota, next_tier)


def record_upload(community_id: str, bytes_stored: int) -> dict:
    """
    Record a successful entity upload.

    Increments storage counter (persistent) and monthly bandwidth counter
    (30-day TTL for automatic monthly reset).

    Returns current usage dict.
    """
    # Storage: persistent
    _incr_counter(community_id, "storage_bytes", bytes_stored)
    # Bandwidth: monthly window (~31 days TTL)
    _incr_counter(community_id, _bw_metric(), bytes_stored, ttl_s=31 * 86400)

    log.debug("quota: upload community=%s bytes=%d", community_id[:8], bytes_stored)
    return get_usage(community_id)


def record_download(community_id: str, bytes_sent: int) -> None:
    """Record bandwidth consumption for a download (read)."""
    _incr_counter(community_id, _bw_metric(), bytes_sent, ttl_s=31 * 86400)
    log.debug("quota: download community=%s bytes=%d", community_id[:8], bytes_sent)


def release_storage(community_id: str, bytes_freed: int) -> None:
    """
    Decrement storage counter when an entity is deleted or crypto-shredded.

    Uses negative delta — floor at 0 to avoid negative counters.
    """
    current = get_storage_used(community_id)
    delta   = min(bytes_freed, current)   # don't go negative
    if delta > 0:
        _incr_counter(community_id, "storage_bytes", -delta)
    log.debug("quota: release community=%s bytes=%d", community_id[:8], delta)


def apply_referral_bonus(community_id: str, referrer_id: str) -> int:
    """
    Add referral_bonus_bytes to the community's effective storage quota.

    Called when a referred user signs up and activates their account.
    Returns the new total bonus bytes.
    """
    from warden.billing.feature_gate import TIER_LIMITS
    bonus_bytes = TIER_LIMITS["individual"]["referral_bonus_bytes"]
    if not bonus_bytes:
        return 0
    total = _incr_counter(community_id, "bonus_bytes", bonus_bytes)
    log.info(
        "quota: referral bonus +%s community=%s referrer=%s total_bonus=%s",
        _fmt(bonus_bytes), community_id[:8], referrer_id[:8] if len(referrer_id) > 8 else referrer_id,
        _fmt(total),
    )
    return total


def get_storage_used(community_id: str) -> int:
    """Return total bytes currently stored for a community."""
    return _get_counter(community_id, "storage_bytes")


def get_bandwidth_used(community_id: str) -> int:
    """Return bytes transferred this calendar month."""
    return _get_counter(community_id, _bw_metric())


def get_usage(community_id: str) -> dict:
    """Return full usage summary for a community."""
    storage  = get_storage_used(community_id)
    bandwidth = get_bandwidth_used(community_id)
    bonus    = _get_counter(community_id, "bonus_bytes")
    return {
        "community_id":     community_id,
        "storage_bytes":    storage,
        "storage_human":    _fmt(storage),
        "bandwidth_bytes":  bandwidth,
        "bandwidth_human":  _fmt(bandwidth),
        "bonus_bytes":      bonus,
        "bonus_human":      _fmt(bonus),
        "period":           datetime.now(UTC).strftime("%Y-%m"),
    }
