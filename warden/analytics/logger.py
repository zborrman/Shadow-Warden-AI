"""
warden/analytics/logger.py
━━━━━━━━━━━━━━━━━━━━━━━━━
Append-only JSON event logger for the /filter pipeline.

Every filter decision is written to data/logs.json as a newline-delimited
JSON record (NDJSON).  The dashboard reads this file directly — no database
required for the analytics layer.

GDPR notes:
  • Content is NEVER written to the log — only metadata (length, flags, timing).
  • PII types (email, ssn, iban) are recorded as strings, not values.
  • Log entries have a configurable TTL; the purge() method removes old records.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from warden.storage import s3 as _s3_storage

log = logging.getLogger("warden.analytics.logger")

LOGS_PATH = Path(os.getenv("LOGS_PATH", "/warden/data/logs.json"))
LOG_RETENTION_DAYS = int(os.getenv("GDPR_LOG_RETENTION_DAYS", "30"))

_lock = threading.Lock()   # one write at a time; I/O is fast for NDJSON


# ── Cost-to-Attack model ──────────────────────────────────────────────────────
#
# We approximate "how much does it cost an attacker to send this payload?"
# using the input-token pricing of a cheap frontier model as a proxy —
# default $0.15 / 1 million tokens (GPT-4o-mini / Haiku tier).
#
# Token count: len(text) / 4  (rule-of-thumb, ±10% for English/code).
# attack_cost_usd = payload_tokens × COST_PER_TOKEN_USD

_COST_PER_TOKEN_USD: float = float(
    os.getenv("COST_PER_TOKEN_USD", str(0.15 / 1_000_000))
)


def estimate_tokens(text: str) -> int:
    """Rough token count: len(text) // 4, minimum 1."""
    return max(1, len(text) // 4)


def token_cost_usd(tokens: int) -> float:
    """Convert token count to USD using the configured cost-per-token rate."""
    return round(tokens * _COST_PER_TOKEN_USD, 8)


# ── Public schema (what gets written per request) ─────────────────────────────

def build_entry(
    *,
    request_id:        str,
    allowed:           bool,
    risk_level:        str,
    flags:             list[str],
    secrets_found:     list[str],
    payload_len:       int,
    payload_tokens:    int,
    attack_cost_usd:   float,
    elapsed_ms:        float,
    strict:            bool,
    session_id:        str | None        = None,
    # ── Yellow zone (masking) ────────────────────────────────────────────────
    entities_detected: list[str]         = (),   # type: ignore[assignment]  # entity TYPES found (not values!)
    entity_count:      int               = 0,    # total entity occurrences
    masked:            bool              = False, # True when masking was actually applied
) -> dict:
    entry = {
        "ts":              datetime.now(UTC).isoformat(),
        "request_id":      request_id,
        "allowed":         allowed,
        "risk_level":      risk_level,
        "flags":           flags,
        "secrets_found":   secrets_found,
        "payload_len":     payload_len,
        "payload_tokens":  payload_tokens,
        "attack_cost_usd": attack_cost_usd,
        "elapsed_ms":      elapsed_ms,
        "strict":          strict,
    }
    if session_id is not None:
        entry["session_id"] = session_id
    if entity_count or entities_detected:
        entry["entities_detected"] = list(entities_detected)
        entry["entity_count"]      = entity_count
        entry["masked"]            = masked
    return entry


# ── Writer ────────────────────────────────────────────────────────────────────

# Insertion-ordered dedup set (bounded, O(1) lookup + O(1) oldest-eviction).
# A plain `set` that gets `.clear()`-ed at the cap would open a window right
# after each wipe where every request_id — including ones seen seconds ago —
# is treated as new again, defeating idempotency at exactly the traffic
# volume where duplicate submits are most likely. Evicting the single oldest
# entry keeps the recent window intact instead.
_SEEN_REQUEST_IDS: OrderedDict[str, None] = OrderedDict()
_SEEN_REQUEST_IDS_CAP = 50_000        # ~4 MB RAM; covers ~14h at 1 req/s


def append(entry: dict) -> None:
    """
    Append one JSON line to LOGS_PATH.
    Thread-safe; creates the file and parent directories on first write.
    Idempotent: duplicate request_ids within the same process lifetime are dropped.
    """
    LOGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    with _lock:
        rid = entry.get("request_id")
        if rid:
            if rid in _SEEN_REQUEST_IDS:
                return
            _SEEN_REQUEST_IDS[rid] = None
            if len(_SEEN_REQUEST_IDS) > _SEEN_REQUEST_IDS_CAP:
                _SEEN_REQUEST_IDS.popitem(last=False)
        with LOGS_PATH.open("a", encoding="utf-8") as f:
            f.write(line)
    # Ship to S3-compatible object storage in background (fail-open, GDPR-safe)
    _s3_storage.ship_log_entry(entry)
    # Mirror into the filter_events hypertable so reporting can query SQL instead
    # of re-parsing this file (D-3). Off by default, never raises, and strictly
    # after the authoritative write above — the NDJSON line is what the system
    # depends on.
    _mirror_to_sql(entry)


def _mirror_to_sql(entry: dict) -> None:
    """Best-effort SQL mirror. Imported lazily: this module is a leaf used by
    tests and workers that have no SQLAlchemy/Postgres at all."""
    try:
        from warden.analytics.events_store import mirror

        mirror(entry)
    except Exception as exc:
        log.debug("filter_events mirror skipped: %s", exc)


def _purge_mirror_before(before: datetime) -> int:
    """Erase mirrored rows in the same operation as the NDJSON purge.

    GDPR erasure is only complete if it reaches every copy; a mirror that
    outlived a subject-erasure request would be a violation, not an
    optimisation. Failures here are logged, never raised — the authoritative
    NDJSON purge must still complete.
    """
    try:
        from warden.analytics.events_store import purge_before as _pb

        return _pb(before)
    except Exception as exc:
        try:
            from warden.observability import Reason, record_failopen

            record_failopen("filter_events_purge", Reason.BACKEND_ERROR, exc)
        except Exception:
            pass
        log.warning("filter_events mirror purge skipped: %s", exc)
        return 0


# ── Reader (used by the dashboard) ───────────────────────────────────────────

def load_entries(days: float | None = None) -> list[dict]:
    """
    Read all log entries, optionally filtering to the last *days* days.
    Returns an empty list if the file does not exist yet.
    """
    if not LOGS_PATH.exists():
        return []

    cutoff = None
    if days is not None:
        cutoff = datetime.now(UTC) - timedelta(days=days)

    entries: list[dict] = []
    with LOGS_PATH.open("r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if cutoff is not None:
                ts = datetime.fromisoformat(entry.get("ts", "1970-01-01T00:00:00+00:00"))
                if ts < cutoff:
                    continue
            entries.append(entry)

    return entries


# ── GDPR data-subject helpers ────────────────────────────────────────────────

def read_by_request_id(request_id: str) -> dict | None:
    """
    Return the single log entry matching *request_id*, or ``None``.

    Used by the GDPR /gdpr/export endpoint so a data subject can retrieve
    the metadata recorded about a specific request.
    """
    for entry in load_entries():
        if entry.get("request_id") == request_id:
            return entry
    return None


def purge_before(before: datetime) -> int:
    """
    Remove all log entries whose timestamp is strictly before *before*.
    Returns the number of entries removed.

    Used by the GDPR /gdpr/purge endpoint for on-demand erasure requests.
    """
    # The mirror is purged unconditionally — including when the NDJSON file is
    # already gone. An erasure request must clear every copy, and "the journal
    # file does not exist" says nothing about what Postgres still holds.
    _purge_mirror_before(before)

    if not LOGS_PATH.exists():
        return 0

    kept, removed = [], 0
    with LOGS_PATH.open("r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            ts = datetime.fromisoformat(entry.get("ts", "1970-01-01T00:00:00+00:00"))
            if ts >= before:
                kept.append(raw)
            else:
                removed += 1

    if removed:
        tmp = LOGS_PATH.with_suffix(".tmp")
        with _lock:
            tmp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            os.replace(tmp, LOGS_PATH)
        log.info("GDPR purge_before: removed %d entries before %s.", removed, before.isoformat())

    return removed


# ── GDPR purge (call periodically, e.g. daily cron / startup) ────────────────

def purge_old_entries() -> int:
    """
    Remove entries older than LOG_RETENTION_DAYS.
    Rewrites the file atomically.  Returns the number of entries removed.

    LOG_RETENTION_DAYS is the *single* retention authority: the filter_events
    migration installs no Timescale retention policy precisely so an env var and
    a hardcoded SQL interval cannot drift apart. This call is therefore what
    ages the mirror out too.
    """
    cutoff = datetime.now(UTC) - timedelta(days=LOG_RETENTION_DAYS)
    _purge_mirror_before(cutoff)

    if not LOGS_PATH.exists():
        return 0

    kept, removed = [], 0

    with LOGS_PATH.open("r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            ts = datetime.fromisoformat(entry.get("ts", "1970-01-01T00:00:00+00:00"))
            if ts >= cutoff:
                kept.append(raw)
            else:
                removed += 1

    tmp = LOGS_PATH.with_suffix(".tmp")
    with _lock:
        tmp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        os.replace(tmp, LOGS_PATH)

    if removed:
        log.info("GDPR purge: removed %d entries older than %d days.", removed, LOG_RETENTION_DAYS)
    return removed
