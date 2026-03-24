"""
warden/global_blocklist.py
━━━━━━━━━━━━━━━━━━━━━━━━━
Cross-region shared IP/hash blocklist — Step 3 of v1.3 Global Threat Intelligence.

All Warden nodes share a single Redis ZSET.  When an IP is blocked on the USA
node (auto-block after 20 attacks), EU and Dubai see it within milliseconds —
before the attacker's next request arrives.

Data model
──────────
  Key     : warden:global:blocked:{tenant_id}
  Type    : Sorted Set
  Member  : IP address (or SHA-256 content hash for hash-bans)
  Score   : Unix expiry timestamp (float); 0.0 = permanent

  Why a sorted set?
    Redis sets have no per-member TTL.  A sorted set with score = expiry lets
    us check expiry in O(log N) via ZSCORE, and sweep expired entries in one
    ZREMRANGEBYSCORE call — no cron job required.

Event stream (for local SQLite sync)
──────────────────────────────────────
  Key     : warden:blocklist:events
  Entries :
    action       "block" | "unblock"
    ip           IP address or content hash
    tenant_id    tenant label
    reason       human-readable reason string
    blocked_by   "auto" | "manual" | "global_sync"
    expires_at   ISO 8601 or "" (permanent)
    source_region publishing node label
    published_at ISO 8601 timestamp

Lookup path in the filter pipeline
────────────────────────────────────
  1. GlobalBlocklist.is_blocked()   — Redis ZSCORE   (< 1ms, first check)
  2. ThreatStore.is_blocked()       — SQLite          (local fallback / offline)

Failure modes
─────────────
  • Global Redis unavailable  → is_blocked() returns False (fail-open); local
                                 SQLite blocklist still enforced
  • Stream consumer lag       → local SQLite may lag by seconds; Redis ZSET
                                 check is always current
  • Expired entries           → swept automatically by sweep_expired() which
                                 is called by is_blocked() every 60 s

Environment variables
─────────────────────
  GLOBAL_BLOCKLIST_ENABLED  "false" to disable (default: true)
  GLOBAL_BLOCKLIST_KEY      ZSET key prefix (default: warden:global:blocked)
  BLOCKLIST_EVENT_STREAM    Stream key (default: warden:blocklist:events)
  BLOCKLIST_STREAM_MAX      Max stream length (default: 10000)
  WARDEN_REGION             This node's region label (shared)
"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

log = logging.getLogger("warden.global_blocklist")

# ── Config ────────────────────────────────────────────────────────────────────

ENABLED: bool     = os.getenv("GLOBAL_BLOCKLIST_ENABLED", "true").lower() != "false"
KEY_PREFIX: str   = os.getenv("GLOBAL_BLOCKLIST_KEY", "warden:global:blocked")
EVT_STREAM: str   = os.getenv("BLOCKLIST_EVENT_STREAM", "warden:blocklist:events")
STREAM_MAX: int   = int(os.getenv("BLOCKLIST_STREAM_MAX", "10000"))
REGION: str       = os.getenv("WARDEN_REGION", "default")

_SWEEP_INTERVAL = 60   # seconds between expired-entry sweeps
_BATCH          = 50
_BLOCK_MS       = 5_000
_GROUP_PREFIX   = "warden:bl"


# ── Redis ─────────────────────────────────────────────────────────────────────

_client = None
_rlock  = threading.Lock()


def _get_redis():
    global _client
    if _client is not None:
        return _client
    with _rlock:
        if _client is not None:
            return _client
        url = os.getenv("GLOBAL_REDIS_URL") or os.getenv("REDIS_URL", "redis://redis:6379/0")
        try:
            import redis as _redis  # noqa: PLC0415
            c = _redis.from_url(url, decode_responses=True,
                                socket_connect_timeout=3, socket_timeout=1)
            c.ping()
            _client = c
        except Exception as exc:
            log.warning("GlobalBlocklist: Redis unavailable: %s", exc)
            _client = None
    return _client


# ── Key helpers ───────────────────────────────────────────────────────────────

def _zset_key(tenant_id: str) -> str:
    return f"{KEY_PREFIX}:{tenant_id}"


# ── Core operations ───────────────────────────────────────────────────────────

_last_sweep: float = 0.0


def is_blocked(ip: str, tenant_id: str = "default") -> bool:
    """
    Return True if *ip* is in the global blocklist for *tenant_id*.

    Also checks the 'default' tenant blocklist so a global ban (tenant='default')
    covers all tenants on this node.

    Periodically sweeps expired entries (every 60 s) to keep the ZSET compact.
    Fail-open: returns False when Redis is unavailable.
    """
    if not ENABLED or not ip:
        return False
    r = _get_redis()
    if r is None:
        return False

    _maybe_sweep(r, tenant_id)

    now = time.time()
    for key in _lookup_keys(tenant_id):
        try:
            score = r.zscore(key, ip)
            if score is None:
                continue
            if score == 0.0 or score > now:   # 0 = permanent; >now = not yet expired
                return True
        except Exception as exc:
            log.debug("GlobalBlocklist.is_blocked error: %s", exc)
    return False


def block_ip(
    ip: str,
    tenant_id: str = "default",
    reason: str = "",
    expires_s: int = 0,
    blocked_by: str = "manual",
) -> bool:
    """
    Add *ip* to the global blocklist.

    Args:
        ip:         IP address or content hash to block.
        tenant_id:  Tenant scope ('default' = all tenants on this node).
        reason:     Human-readable reason (logged + streamed).
        expires_s:  TTL in seconds; 0 = permanent.
        blocked_by: 'manual' | 'auto' | 'global_sync'.

    Returns True if the entry was written to Redis.
    """
    if not ENABLED or not ip:
        return False
    r = _get_redis()
    if r is None:
        return False

    score = 0.0 if expires_s == 0 else time.time() + expires_s
    expires_at = "" if expires_s == 0 else datetime.fromtimestamp(score, UTC).isoformat()

    try:
        r.zadd(_zset_key(tenant_id), {ip: score})
        log.info(
            "GlobalBlocklist: blocked ip=%s tenant=%s reason=%r expires_s=%d region=%s",
            ip, tenant_id, reason, expires_s, REGION,
        )
        try:
            from warden.metrics import SYNC_BLOCKS_PROPAGATED_TOTAL  # noqa: PLC0415
            SYNC_BLOCKS_PROPAGATED_TOTAL.labels(blocked_by=blocked_by).inc()
        except Exception:
            pass
    except Exception as exc:
        log.warning("GlobalBlocklist.block_ip ZADD failed: %s", exc)
        return False

    _publish_event(r, "block", ip, tenant_id, reason, blocked_by, expires_at)
    return True


def unblock_ip(ip: str, tenant_id: str = "default") -> bool:
    """
    Remove *ip* from the global blocklist.

    Returns True if the entry existed and was removed.
    """
    if not ENABLED or not ip:
        return False
    r = _get_redis()
    if r is None:
        return False

    try:
        removed = r.zrem(_zset_key(tenant_id), ip)
        if removed:
            log.info("GlobalBlocklist: unblocked ip=%s tenant=%s", ip, tenant_id)
            _publish_event(r, "unblock", ip, tenant_id, "", "manual", "")
        return bool(removed)
    except Exception as exc:
        log.warning("GlobalBlocklist.unblock_ip failed: %s", exc)
        return False


def get_blocked(tenant_id: str = "default") -> list[dict]:
    """
    Return all currently blocked entries for *tenant_id*.

    Expired entries are filtered out (but not swept — call sweep_expired() for that).
    """
    if not ENABLED:
        return []
    r = _get_redis()
    if r is None:
        return []

    now = time.time()
    try:
        members = r.zrange(_zset_key(tenant_id), 0, -1, withscores=True)
        result = []
        for ip, score in members:
            if score != 0.0 and score <= now:
                continue  # expired — skip
            result.append({
                "ip":         ip,
                "tenant_id":  tenant_id,
                "permanent":  score == 0.0,
                "expires_at": "" if score == 0.0
                              else datetime.fromtimestamp(score, UTC).isoformat(),
            })
        return result
    except Exception as exc:
        log.debug("GlobalBlocklist.get_blocked error: %s", exc)
        return []


def sweep_expired(tenant_id: str = "default") -> int:
    """Remove expired entries from the ZSET. Returns count removed."""
    r = _get_redis()
    if r is None:
        return 0
    try:
        # Score range (0, now] = entries with non-zero score that have expired.
        # Permanent entries (score=0) are excluded because 0 < epsilon < now.
        n = r.zremrangebyscore(_zset_key(tenant_id), 0.001, time.time())
        if n:
            log.debug("GlobalBlocklist: swept %d expired entries (tenant=%s)", n, tenant_id)
        return int(n)
    except Exception as exc:
        log.debug("GlobalBlocklist sweep error: %s", exc)
        return 0


# ── Internal helpers ──────────────────────────────────────────────────────────

def _lookup_keys(tenant_id: str) -> list[str]:
    """Return ZSET keys to check — tenant-specific + global 'default' fallback."""
    keys = [_zset_key(tenant_id)]
    if tenant_id != "default":
        keys.append(_zset_key("default"))
    return keys


def _maybe_sweep(r, tenant_id: str) -> None:
    global _last_sweep
    now = time.time()
    if now - _last_sweep < _SWEEP_INTERVAL:
        return
    _last_sweep = now
    try:
        r.zremrangebyscore(_zset_key(tenant_id), 0.001, now)
        if tenant_id != "default":
            r.zremrangebyscore(_zset_key("default"), 0.001, now)
    except Exception:
        pass


def _publish_event(
    r,
    action: str,
    ip: str,
    tenant_id: str,
    reason: str,
    blocked_by: str,
    expires_at: str,
) -> None:
    try:
        r.xadd(
            EVT_STREAM,
            {
                "action":        action,
                "ip":            ip,
                "tenant_id":     tenant_id,
                "reason":        reason,
                "blocked_by":    blocked_by,
                "expires_at":    expires_at,
                "source_region": REGION,
                "published_at":  datetime.now(UTC).isoformat(),
            },
            maxlen=STREAM_MAX,
            approximate=True,
        )
    except Exception as exc:
        log.debug("GlobalBlocklist: event publish failed: %s", exc)


# ── Stream consumer — sync to local ThreatStore ───────────────────────────────

def _ensure_group(r) -> bool:
    group = f"{_GROUP_PREFIX}:{REGION}"
    try:
        r.xgroup_create(EVT_STREAM, group, id="0", mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            log.warning("GlobalBlocklist: xgroup_create error: %s", exc)
            return False
    return True


def _apply_event(fields: dict, threat_store) -> None:
    """Apply a block/unblock event from another region to local ThreatStore."""
    if fields.get("source_region") == REGION:
        return   # own event — skip

    action    = fields.get("action", "")
    ip        = fields.get("ip", "")
    tenant_id = fields.get("tenant_id", "default")
    reason    = fields.get("reason", "global_sync")

    if not ip:
        return

    if threat_store is None:
        return

    try:
        if action == "block":
            expires_at_str = fields.get("expires_at", "")
            expires_at = None
            if expires_at_str:
                from datetime import datetime as _dt  # noqa: PLC0415
                expires_at = _dt.fromisoformat(expires_at_str)
            threat_store.block_ip(
                ip         = ip,
                tenant_id  = tenant_id,
                reason     = f"[global_sync:{fields.get('source_region','?')}] {reason}",
                blocked_by = "global_sync",
                expires_at = expires_at,
            )
            log.info(
                "GlobalBlocklist: synced block ip=%s from region=%s",
                ip, fields.get("source_region", "?"),
            )
            try:
                from warden.metrics import SYNC_BLOCKS_APPLIED_TOTAL  # noqa: PLC0415
                SYNC_BLOCKS_APPLIED_TOTAL.labels(
                    source_region=fields.get("source_region", "unknown")
                ).inc()
            except Exception:
                pass
        elif action == "unblock":
            threat_store.unblock_ip(ip, tenant_id)
            log.info(
                "GlobalBlocklist: synced unblock ip=%s from region=%s",
                ip, fields.get("source_region", "?"),
            )
    except Exception as exc:
        log.warning("GlobalBlocklist: local sync failed ip=%s: %s", ip, exc)


def _poll_events(r, threat_store) -> int:
    group = f"{_GROUP_PREFIX}:{REGION}"
    try:
        results = r.xreadgroup(
            groupname    = group,
            consumername = f"{REGION}-bl-worker",
            streams      = {EVT_STREAM: ">"},
            count        = _BATCH,
            block        = _BLOCK_MS,
        )
    except Exception as exc:
        log.warning("GlobalBlocklist: xreadgroup error: %s", exc)
        return 0

    if not results:
        return 0

    processed = 0
    for _stream, messages in results:
        for msg_id, fields in messages:
            try:
                _apply_event(fields, threat_store)
                r.xack(EVT_STREAM, group, msg_id)
                processed += 1
            except Exception as exc:
                log.warning("GlobalBlocklist: message error msg_id=%s: %s", msg_id, exc)
    return processed


# ── Background watcher ────────────────────────────────────────────────────────

class GlobalBlocklistWatcher:
    """
    Daemon thread that consumes the blocklist event stream and applies
    block/unblock events from remote regions to the local ThreatStore.

    Usage (warden/main.py lifespan)::

        _bl_watcher = GlobalBlocklistWatcher(threat_store=_threat_store)
        _bl_watcher.start()
        ...
        _bl_watcher.stop()
    """

    def __init__(self, threat_store=None) -> None:
        self._threat_store = threat_store
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if not ENABLED:
            log.info("GlobalBlocklist disabled (GLOBAL_BLOCKLIST_ENABLED=false)")
            return
        r = _get_redis()
        if r is None:
            log.warning("GlobalBlocklist: Redis unavailable — watcher not started")
            return
        if not _ensure_group(r):
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="global-blocklist-watcher",
            daemon=True,
        )
        self._thread.start()
        log.info("GlobalBlocklistWatcher started: region=%s stream=%s", REGION, EVT_STREAM)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        backoff = 1
        while not self._stop.is_set():
            r = _get_redis()
            if r is None:
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 1
            try:
                _poll_events(r, self._threat_store)
            except Exception as exc:
                log.warning("GlobalBlocklistWatcher loop error: %s", exc)
                self._stop.wait(2)
