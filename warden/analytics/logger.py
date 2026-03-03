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
from datetime import UTC, datetime, timedelta
from pathlib import Path

log = logging.getLogger("warden.analytics.logger")

LOGS_PATH = Path(os.getenv("LOGS_PATH", "/warden/data/logs.json"))
LOG_RETENTION_DAYS = int(os.getenv("GDPR_LOG_RETENTION_DAYS", "30"))

_lock = threading.Lock()   # one write at a time; I/O is fast for NDJSON


# ── Public schema (what gets written per request) ─────────────────────────────

def build_entry(
    *,
    request_id:   str,
    allowed:      bool,
    risk_level:   str,
    flags:        list[str],
    secrets_found: list[str],
    content_len:  int,
    elapsed_ms:   float,
    strict:       bool,
) -> dict:
    return {
        "ts":           datetime.now(UTC).isoformat(),
        "request_id":   request_id,
        "allowed":      allowed,
        "risk_level":   risk_level,
        "flags":        flags,
        "secrets_found": secrets_found,
        "content_len":  content_len,
        "elapsed_ms":   elapsed_ms,
        "strict":       strict,
    }


# ── Writer ────────────────────────────────────────────────────────────────────

def append(entry: dict) -> None:
    """
    Append one JSON line to LOGS_PATH.
    Thread-safe; creates the file and parent directories on first write.
    """
    LOGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    with _lock, LOGS_PATH.open("a", encoding="utf-8") as f:
        f.write(line)


# ── Reader (used by the dashboard) ───────────────────────────────────────────

def load_entries(days: int | None = None) -> list[dict]:
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
    """
    if not LOGS_PATH.exists():
        return 0

    cutoff   = datetime.now(UTC) - timedelta(days=LOG_RETENTION_DAYS)
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
