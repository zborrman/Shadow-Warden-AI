"""
warden/threat_sync.py
━━━━━━━━━━━━━━━━━━━━
Global Threat Intelligence Sharing via Redis Streams.

When EvolutionEngine generates a new rule on any Warden node, ThreatSyncClient
publishes it to a shared Redis Stream.  All other regional nodes consume the
stream and apply the rule locally — no code deploy, no restart required.

Architecture
────────────
  Stream  : warden:threats:global
  Groups  : one consumer group per region  (warden:sync:usa / eu / dubai)
  Strategy: each node skips messages it published (source_region filter)
  Dedup   : source_hash checked against local seen-set + dynamic_rules

Why Redis Streams over Pub/Sub
───────────────────────────────
  Pub/Sub drops messages for offline consumers.  Streams persist the log —
  a node that restarts (or is offline for maintenance) replays missed events
  from its last acknowledged message ID, guaranteeing eventual consistency.

Failure modes
─────────────
  • Global Redis unavailable  → publish silently no-ops (local rule still saved)
  • Consumer lag              → replayed on reconnect via consumer group ID
  • Duplicate delivery        → deduplicated via _seen_hashes set

Message payload (one Redis Stream entry)
─────────────────────────────────────────
  source_region   "usa" | "eu" | "dubai"   (publishing node)
  rule_id         UUID of the RuleRecord
  source_hash     SHA-256 of original blocked content (dedup key)
  attack_type     e.g. "prompt_injection"
  severity        "medium" | "high" | "block"
  rule_type       "semantic_example" | "regex_pattern"
  rule_value      the pattern / example text
  rule_desc       one-line description
  evasion_json    JSON array of evasion variant strings
  published_at    ISO 8601 timestamp

Environment variables
─────────────────────
  WARDEN_REGION             This node's region label (default: "default")
                            Set to "usa", "eu", or "dubai" per deployment
  GLOBAL_REDIS_URL          URL of the shared Redis cluster
                            (default: falls back to REDIS_URL)
  THREAT_SYNC_ENABLED       "false" to disable entirely (default: true)
  THREAT_SYNC_STREAM        Stream name (default: warden:threats:global)
  THREAT_SYNC_MAX_LEN       Max stream length — older entries trimmed (default: 10000)
  THREAT_SYNC_BATCH         Messages to read per poll cycle (default: 50)
  THREAT_SYNC_BLOCK_MS      XREADGROUP block timeout in ms (default: 5000)
  THREAT_SYNC_SEEN_CAP      In-process dedup set size cap (default: 50000)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from warden.brain.evolve import RuleRecord

log = logging.getLogger("warden.threat_sync")

# ── Config ────────────────────────────────────────────────────────────────────

REGION: str      = os.getenv("WARDEN_REGION", "default")
ENABLED: bool    = os.getenv("THREAT_SYNC_ENABLED", "true").lower() != "false"
STREAM: str      = os.getenv("THREAT_SYNC_STREAM", "warden:threats:global")
MAX_LEN: int     = int(os.getenv("THREAT_SYNC_MAX_LEN",  "10000"))
BATCH: int       = int(os.getenv("THREAT_SYNC_BATCH",    "50"))
BLOCK_MS: int    = int(os.getenv("THREAT_SYNC_BLOCK_MS", "5000"))
SEEN_CAP: int    = int(os.getenv("THREAT_SYNC_SEEN_CAP", "50000"))

_GROUP_PREFIX = "warden:sync"
_CONSUMER_NAME = f"{REGION}-worker"

# ── Redis connection ──────────────────────────────────────────────────────────

_client = None
_lock   = threading.Lock()


def _get_client():
    """Lazy-init Redis client from GLOBAL_REDIS_URL → REDIS_URL fallback."""
    global _client
    if _client is not None:
        return _client
    with _lock:
        if _client is not None:
            return _client
        url = os.getenv("GLOBAL_REDIS_URL") or os.getenv("REDIS_URL", "redis://redis:6379/0")
        try:
            import redis as _redis
            c = _redis.from_url(
                url,
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=2,
            )
            c.ping()
            _client = c
            log.info("ThreatSync connected to global Redis: region=%s stream=%s", REGION, STREAM)
        except Exception as exc:
            log.warning("ThreatSync: global Redis unavailable — cross-region sync disabled: %s", exc)
            _client = None
    return _client


# ── In-process dedup ──────────────────────────────────────────────────────────

_seen_hashes: set[str] = set()


def _is_seen(source_hash: str) -> bool:
    if source_hash in _seen_hashes:
        return True
    if len(_seen_hashes) >= SEEN_CAP:
        _seen_hashes.clear()   # evict all — simpler than LRU for this use case
    _seen_hashes.add(source_hash)
    return False


# ── Producer ──────────────────────────────────────────────────────────────────

def publish_rule(rule: "RuleRecord") -> bool:
    """
    Publish a newly generated rule to the global threat stream.

    Called by EvolutionEngine after writing the rule to dynamic_rules.json.
    Fail-silent: returns False (instead of raising) when Redis is unavailable.

    Returns True if the message was published successfully.
    """
    if not ENABLED:
        return False
    r = _get_client()
    if r is None:
        return False

    try:
        entry = {
            "source_region": REGION,
            "rule_id":       rule.id,
            "source_hash":   rule.source_hash,
            "attack_type":   rule.attack_type,
            "severity":      rule.severity,
            "rule_type":     rule.new_rule.rule_type,
            "rule_value":    rule.new_rule.value,
            "rule_desc":     rule.new_rule.description,
            "evasion_json":  json.dumps(rule.evasion_variants, ensure_ascii=False),
            "published_at":  datetime.now(UTC).isoformat(),
        }
        r.xadd(STREAM, entry, maxlen=MAX_LEN, approximate=True)
        log.info(
            "ThreatSync published: rule_id=%s attack_type=%s region=%s",
            rule.id, rule.attack_type, REGION,
        )
        try:
            from warden.metrics import SYNC_RULES_PUBLISHED_TOTAL  # noqa: PLC0415
            SYNC_RULES_PUBLISHED_TOTAL.inc()
        except Exception:
            pass
        return True
    except Exception as exc:
        log.warning("ThreatSync publish failed: %s", exc)
        return False


# ── Consumer group setup ──────────────────────────────────────────────────────

def _ensure_group(r) -> bool:
    """Create consumer group if it does not exist. Returns True on success."""
    group = f"{_GROUP_PREFIX}:{REGION}"
    try:
        r.xgroup_create(STREAM, group, id="0", mkstream=True)
        log.info("ThreatSync: created consumer group %s", group)
    except Exception as exc:
        # BUSYGROUP = already exists; that is fine
        if "BUSYGROUP" not in str(exc):
            log.warning("ThreatSync: xgroup_create error: %s", exc)
            return False
    return True


# ── Consumer ──────────────────────────────────────────────────────────────────

def _apply_rule(entry: dict, semantic_guard) -> None:
    """
    Apply a received rule to the local node.

    Steps:
      1. Skip rules published by this region (source_region filter).
      2. Skip duplicate source_hashes (in-process dedup).
      3. If rule_type == semantic_example: hot-reload corpus via add_examples().
      4. Append to dynamic_rules.json (atomic write via EvolutionEngine helper).
      5. Log the ingestion.
    """
    source_region = entry.get("source_region", "")
    if source_region == REGION:
        return   # own message — skip

    source_hash = entry.get("source_hash", "")
    if source_hash and _is_seen(source_hash):
        log.debug("ThreatSync: duplicate rule skipped source_hash=%s", source_hash[:16])
        return

    rule_type  = entry.get("rule_type", "")
    rule_value = entry.get("rule_value", "")
    rule_id    = entry.get("rule_id", "?")
    attack_type = entry.get("attack_type", "unknown")

    # Hot-reload corpus for semantic examples
    if rule_type == "semantic_example" and rule_value and semantic_guard is not None:
        try:
            semantic_guard.add_examples([rule_value])
            log.info(
                "ThreatSync applied semantic rule: rule_id=%s from=%s attack=%s",
                rule_id, source_region, attack_type,
            )
            try:
                from warden.metrics import SYNC_RULES_APPLIED_TOTAL  # noqa: PLC0415
                SYNC_RULES_APPLIED_TOTAL.labels(source_region=source_region).inc()
            except Exception:
                pass
        except Exception as exc:
            log.warning("ThreatSync: add_examples failed: %s", exc)

    # Persist to dynamic_rules.json
    try:
        from warden.brain.evolve import NewRule, RuleRecord, DYNAMIC_RULES_PATH  # noqa: PLC0415
        evasion = json.loads(entry.get("evasion_json", "[]"))
        rec = RuleRecord(
            id               = rule_id,
            created_at       = entry.get("published_at", datetime.now(UTC).isoformat()),
            source_hash      = source_hash,
            attack_type      = attack_type,
            explanation      = f"[Synced from {source_region}] " + entry.get("rule_desc", ""),
            evasion_variants = evasion,
            new_rule         = NewRule(
                rule_type   = rule_type,
                value       = rule_value,
                description = entry.get("rule_desc", ""),
            ),
            severity         = entry.get("severity", "high"),
        )
        _persist_synced_rule(rec, DYNAMIC_RULES_PATH)
    except Exception as exc:
        log.warning("ThreatSync: rule persistence failed: %s", exc)


def _persist_synced_rule(rule: "RuleRecord", rules_path) -> None:
    """Atomic append of a synced rule to dynamic_rules.json."""
    import tempfile  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415
    p = Path(rules_path)
    if p.exists():
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError:
            data = {"schema_version": "1.0", "rules": []}
    else:
        data = {"schema_version": "1.0", "rules": []}

    # Dedup: skip if rule_id already present
    existing_ids = {r.get("id") for r in data.get("rules", [])}
    if rule.id in existing_ids:
        return

    data["last_updated"] = datetime.now(UTC).isoformat()
    data["rules"].append(json.loads(rule.model_dump_json()))

    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, p)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _poll_once(r, semantic_guard) -> int:
    """Read one batch from the stream and apply rules. Returns number processed."""
    group    = f"{_GROUP_PREFIX}:{REGION}"
    try:
        results = r.xreadgroup(
            groupname  = group,
            consumername = _CONSUMER_NAME,
            streams    = {STREAM: ">"},
            count      = BATCH,
            block      = BLOCK_MS,
        )
    except Exception as exc:
        log.warning("ThreatSync: xreadgroup error: %s", exc)
        return 0

    if not results:
        return 0

    processed = 0
    for _stream_name, messages in results:
        for msg_id, fields in messages:
            try:
                _apply_rule(fields, semantic_guard)
                r.xack(STREAM, group, msg_id)
                processed += 1
            except Exception as exc:
                log.warning("ThreatSync: message processing error msg_id=%s: %s", msg_id, exc)

    return processed


# ── Background consumer loop ──────────────────────────────────────────────────

class ThreatSyncClient:
    """
    Manages the background consumer thread for inbound cross-region rules.

    Usage (warden/main.py lifespan)::

        _sync = ThreatSyncClient(semantic_guard=_brain_guard)
        _sync.start()
        ...
        _sync.stop()
    """

    def __init__(self, semantic_guard=None) -> None:
        self._semantic_guard = semantic_guard
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if not ENABLED:
            log.info("ThreatSync disabled (THREAT_SYNC_ENABLED=false)")
            return
        r = _get_client()
        if r is None:
            log.warning("ThreatSync: cannot start — global Redis unavailable")
            return
        if not _ensure_group(r):
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="threat-sync-consumer",
            daemon=True,
        )
        self._thread.start()
        log.info("ThreatSync consumer started: region=%s group=%s:%s",
                 REGION, _GROUP_PREFIX, REGION)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        backoff = 1
        while not self._stop_event.is_set():
            r = _get_client()
            if r is None:
                log.warning("ThreatSync: Redis lost — retrying in %ds", backoff)
                self._stop_event.wait(backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 1
            try:
                _poll_once(r, self._semantic_guard)
            except Exception as exc:
                log.warning("ThreatSync loop error: %s", exc)
                self._stop_event.wait(2)

    # ── Convenience: publish after evolution ──────────────────────────────────

    @staticmethod
    def publish(rule: "RuleRecord") -> bool:
        """Static shortcut — call from EvolutionEngine without holding a reference."""
        return publish_rule(rule)
