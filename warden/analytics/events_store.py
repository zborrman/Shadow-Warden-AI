"""
warden/analytics/events_store.py — SQL read path for the /filter journal (D-3).

`data/logs.json` stays the authority. Every `/filter` decision is appended there
first, the S3 evidence ship reads it, and GDPR erasure owns it. What this module
adds is a *queryable* copy in the `warden_core.filter_events` hypertable, so the
25 modules that today re-parse the entire NDJSON file — several of them with no
time window at all — can ask Postgres a bounded question instead.

Posture
───────
* **Mirror, never source.** `mirror()` is best-effort: a write that raises is
  swallowed and counted, because the authoritative append already succeeded and
  must never be undone by a reporting copy.
* **Opt-in.** Gated on `settings.filter_events_mirror` (default off), so merging
  this changes nothing until an operator flips it — the same posture as
  `ledger/dual_write.py`.
* **Readers degrade, they do not fail.** Every read helper returns ``None`` when
  the mirror cannot serve the question, and each caller falls back to the
  existing `load_entries()` scan. A caller therefore works identically whether
  the mirror is on, off, or mid-backfill.

GDPR
────
The mirror carries the same metadata-only fields `build_entry()` produces —
never content, never decoded text, never secret values. It is also **inside the
erasure path**: `logger.purge_before()` and `logger.purge_old_entries()` call
`purge_before()` here in the same operation, so a subject-erasure request cannot
leave rows behind in Postgres. Retention lives in `GDPR_LOG_RETENTION_DAYS`
alone; the migration deliberately installs no Timescale retention policy, so the
env var stays the single authority.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

log = logging.getLogger("warden.analytics.events_store")


# Swallowed mirror-write failures this process (health signal, no hard dep).
_mirror_failures = 0


def mirror_failure_count() -> int:
    return _mirror_failures


def enabled() -> bool:
    """True when live appends should also be mirrored into Postgres."""
    try:
        from warden.config import settings

        if not getattr(settings, "filter_events_mirror", False):
            return False
        from warden.db.connection import DATABASE_URL

        return bool(DATABASE_URL)
    except Exception:
        return False


def available() -> bool:
    """True when the mirror can serve reads.

    Deliberately independent of :func:`enabled` — an operator may stop mirroring
    while still querying the history already collected.
    """
    try:
        from warden.db.connection import DATABASE_URL

        return bool(DATABASE_URL)
    except Exception:
        return False


def _engine() -> Any:
    from warden.db.connection import get_engine

    return get_engine()


# ── Writer ────────────────────────────────────────────────────────────────────

_INSERT = """
    INSERT INTO warden_core.filter_events (
        ts, request_id, tenant_id, allowed, risk_level, flags, secrets_found,
        payload_len, payload_tokens, attack_cost_usd, elapsed_ms, strict,
        session_id, entities_detected, entity_count, masked
    ) VALUES (
        :ts, :request_id, :tenant_id, :allowed, :risk_level, :flags, :secrets_found,
        :payload_len, :payload_tokens, :attack_cost_usd, :elapsed_ms, :strict,
        :session_id, :entities_detected, :entity_count, :masked
    )
    ON CONFLICT (request_id, ts) DO NOTHING
"""


def _params(entry: dict) -> dict[str, Any]:
    """Project a logger entry onto the table's columns.

    Only the known metadata fields are carried across — an unexpected key in the
    entry is dropped rather than stored, so the mirror cannot silently start
    holding something the GDPR review never approved.
    """
    return {
        "ts": entry.get("ts"),
        "request_id": entry.get("request_id") or "",
        "tenant_id": entry.get("tenant_id") or "default",
        "allowed": bool(entry.get("allowed", True)),
        "risk_level": entry.get("risk_level") or "LOW",
        "flags": list(entry.get("flags") or []),
        "secrets_found": list(entry.get("secrets_found") or []),
        "payload_len": int(entry.get("payload_len") or 0),
        "payload_tokens": int(entry.get("payload_tokens") or 0),
        "attack_cost_usd": float(entry.get("attack_cost_usd") or 0.0),
        "elapsed_ms": entry.get("elapsed_ms"),
        "strict": bool(entry.get("strict", False)),
        "session_id": entry.get("session_id"),
        "entities_detected": list(entry.get("entities_detected") or []),
        "entity_count": int(entry.get("entity_count") or 0),
        "masked": bool(entry.get("masked", False)),
    }


def mirror(entry: dict) -> bool:
    """Best-effort copy of one journal entry into Postgres. Never raises.

    Returns True when a write was attempted and succeeded. A ``False`` means the
    mirror is off or the write failed — in both cases the NDJSON journal already
    holds the entry, which is what the system is allowed to depend on.
    """
    if not enabled():
        return False
    global _mirror_failures
    try:
        from sqlalchemy import text

        with _engine().begin() as conn:
            conn.execute(text(_INSERT), _params(entry))
        return True
    except Exception as exc:
        _mirror_failures += 1
        try:
            from warden.observability import Reason, record_failopen

            record_failopen("filter_events_mirror", Reason.BACKEND_ERROR, exc)
        except Exception:
            pass
        log.warning("filter_events mirror failed (entry kept in NDJSON): %s", exc)
        return False



# ── Read statements ──────────────────────────────────────────────────────────
# Written out in full per variant. Assembling a WHERE clause from fragments is
# what the SQL-injection SAST rule flags, and it is a fair objection even when
# every fragment is a constant: safety should be visible without tracing where
# the pieces came from.

_SUMMARY_COLUMNS = """
    SELECT
        COUNT(*)                                     AS total,
        COUNT(*) FILTER (WHERE allowed)              AS allowed,
        COUNT(*) FILTER (WHERE NOT allowed)          AS blocked,
        COUNT(*) FILTER (WHERE risk_level = 'HIGH')  AS high,
        COUNT(*) FILTER (WHERE risk_level = 'BLOCK') AS block,
        COUNT(*) FILTER (WHERE masked)               AS masked,
        COALESCE(SUM(attack_cost_usd), 0)            AS attack_cost_usd,
        AVG(elapsed_ms)                              AS avg_elapsed_ms
    FROM warden_core.filter_events
"""
_SUMMARY_ALL = _SUMMARY_COLUMNS + " WHERE ts >= :since"
_SUMMARY_BY_TENANT = _SUMMARY_COLUMNS + " WHERE ts >= :since AND tenant_id = :tid"

_HOURLY_COLUMNS = """
    SELECT bucket, tenant_id, total, allowed, blocked, high, block,
           masked, attack_cost_usd, avg_elapsed_ms, max_elapsed_ms
    FROM warden_core.filter_events_hourly
"""
_HOURLY_ALL = _HOURLY_COLUMNS + " WHERE bucket >= :since ORDER BY bucket"
_HOURLY_BY_TENANT = (
    _HOURLY_COLUMNS + " WHERE bucket >= :since AND tenant_id = :tid ORDER BY bucket"
)

# ── GDPR erasure ──────────────────────────────────────────────────────────────

def purge_before(before: datetime) -> int:
    """Delete mirrored rows older than *before*. Returns rows removed (0 on any
    failure — the caller's NDJSON purge is the authoritative one and must not be
    aborted by this).

    Called from `logger.purge_before()` / `purge_old_entries()` so subject
    erasure and retention cover the mirror in the same operation.
    """
    if not available():
        return 0
    try:
        from sqlalchemy import text

        with _engine().begin() as conn:
            res = conn.execute(
                text("DELETE FROM warden_core.filter_events WHERE ts < :before"), {"before": before}
            )
            removed = int(res.rowcount or 0)
        if removed:
            log.info("filter_events mirror: purged %d rows before %s", removed, before)
        return removed
    except Exception as exc:
        # A purge that silently fails to erase the mirror is a *compliance*
        # event, not a degraded report: rows the subject asked to have deleted
        # would survive in Postgres. Counted so it becomes a Prometheus series
        # and an alert rather than one warning line in a log nobody greps.
        try:
            from warden.observability import Reason, record_failopen

            record_failopen("filter_events_purge", Reason.BACKEND_ERROR, exc)
        except Exception:
            pass
        log.warning("filter_events mirror purge failed: %s", exc)
        return 0


# ── Readers (None ⇒ caller falls back to load_entries()) ──────────────────────

def summary(since: datetime, *, tenant_id: str | None = None) -> dict[str, Any] | None:
    """Aggregate counters over [since, now). ``None`` when unavailable."""
    if not available():
        return None
    try:
        from sqlalchemy import text

        # Two whole literal statements rather than one assembled from a
        # fragment: nothing here is user input, but SQL that is *built* cannot
        # be read as safe at a glance, and the SAST gate is right to say so.
        sql = _SUMMARY_BY_TENANT if tenant_id else _SUMMARY_ALL
        params: dict[str, Any] = {"since": since}
        if tenant_id:
            params["tid"] = tenant_id
        with _engine().connect() as conn:
            row = conn.execute(text(sql), params).fetchone()
        if row is None:
            return None
        d = dict(row._mapping)
        d["attack_cost_usd"] = float(d["attack_cost_usd"] or 0)
        d["avg_elapsed_ms"] = float(d["avg_elapsed_ms"]) if d["avg_elapsed_ms"] is not None else None
        return d
    except Exception as exc:
        log.debug("filter_events summary unavailable: %s", exc)
        return None


def hourly_series(since: datetime, *, tenant_id: str | None = None) -> list[dict[str, Any]] | None:
    """Hourly buckets from the continuous aggregate — the dashboard read path."""
    if not available():
        return None
    try:
        from sqlalchemy import text

        sql = _HOURLY_BY_TENANT if tenant_id else _HOURLY_ALL
        params: dict[str, Any] = {"since": since}
        if tenant_id:
            params["tid"] = tenant_id
        with _engine().connect() as conn:
            return [dict(r._mapping) for r in conn.execute(text(sql), params)]
    except Exception as exc:
        log.debug("filter_events hourly_series unavailable: %s", exc)
        return None


def blocked_flag_counts(since: datetime) -> dict[str, int] | None:
    """Flag → occurrences among **non-allowed** decisions in the window.

    The threat-category breakdown reporting needs; doing it in SQL turns a
    full-window scan plus a Python Counter into one grouped query.
    """
    if not available():
        return None
    try:
        from sqlalchemy import text

        sql = """
            SELECT flag, COUNT(*) AS n
            FROM warden_core.filter_events, UNNEST(flags) AS flag
            WHERE ts >= :since AND NOT allowed
            GROUP BY flag
        """
        with _engine().connect() as conn:
            return {r[0]: int(r[1]) for r in conn.execute(text(sql), {"since": since})}
    except Exception as exc:
        log.debug("filter_events blocked_flag_counts unavailable: %s", exc)
        return None


def top_flags(since: datetime, *, limit: int = 10) -> list[tuple[str, int]] | None:
    """Most frequent detection flags in the window."""
    if not available():
        return None
    try:
        from sqlalchemy import text

        sql = """
            SELECT flag, COUNT(*) AS n
            FROM warden_core.filter_events, UNNEST(flags) AS flag
            WHERE ts >= :since
            GROUP BY flag ORDER BY n DESC LIMIT :lim
        """
        with _engine().connect() as conn:
            return [(r[0], int(r[1])) for r in conn.execute(text(sql), {"since": since, "lim": limit})]
    except Exception as exc:
        log.debug("filter_events top_flags unavailable: %s", exc)
        return None
