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
import time
from datetime import datetime, timedelta
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


# ── Coverage ──────────────────────────────────────────────────────────────────
#
# The mirror starts collecting when an operator flips FILTER_EVENTS_MIRROR on;
# nothing backfills what came before. Without a floor, a reader asking for the
# last 30 days would get only the rows since the flip and present them as the
# whole window — a smaller number than the truth, with nothing to indicate it.
# That is worse than the NDJSON scan it replaces, because the scan is at least
# correct.
#
# So every reader refuses a window the mirror cannot cover and returns None,
# which sends the caller back to the journal. `available()` cannot answer this:
# it only reports that Postgres is configured.

_COVERAGE_TTL_S = 60.0
_coverage: tuple[float, datetime | None] | None = None   # (fetched_at, earliest ts)


def coverage_start() -> datetime | None:
    """Earliest mirrored event, or None when the mirror holds nothing.

    One indexed MIN(ts) lookup, memoised for a minute — it only moves when the
    oldest row is purged or the mirror is first populated.
    """
    global _coverage
    now = time.monotonic()
    if _coverage is not None and now - _coverage[0] < _COVERAGE_TTL_S:
        return _coverage[1]
    if not available():
        return None
    try:
        from sqlalchemy import text

        with _engine().connect() as conn:
            earliest = conn.execute(
                text("SELECT MIN(ts) FROM warden_core.filter_events")
            ).scalar()
        _coverage = (now, earliest)
        return earliest
    except Exception as exc:
        log.debug("filter_events coverage unavailable: %s", exc)
        return None


def covers(since: datetime) -> bool:
    """True when the mirror holds the whole window starting at *since*."""
    earliest = coverage_start()
    return earliest is not None and earliest <= since


def reset_coverage_cache() -> None:
    """Drop the memoised coverage floor — after a backfill or a purge."""
    global _coverage
    _coverage = None


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

    `risk_level` is upper-cased on the way in. The journal writes it lower-case
    (`block`, `high`, `low`) while every SQL comparison built on this table used
    the upper-case literals, so the severity counters matched nothing and
    reported 0 — see revision `0014`. Readers use `upper(risk_level)` regardless,
    so rows written by an older build still count; this keeps new ones canonical.
    """
    return {
        "ts": entry.get("ts"),
        "request_id": entry.get("request_id") or "",
        "tenant_id": entry.get("tenant_id") or "default",
        "allowed": bool(entry.get("allowed", True)),
        "risk_level": (entry.get("risk_level") or "LOW").upper(),
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



def backfill_from_journal(days: float | None = None, *, batch: int = 500) -> dict[str, int]:
    """Copy existing journal entries into the mirror.

    Without this the mirror only ever holds what arrived after an operator
    flipped it on, so `covers()` stays false for any useful window and every
    reader keeps scanning — the feature would be permanently inert.

    Reads the NDJSON journal, which is the authority, and inserts with the same
    `ON CONFLICT DO NOTHING` the live path uses, so it is safe to run while
    mirroring is active and safe to re-run. Deliberately synchronous and
    batched: this is an operator action, not a request path.

    Finishes by materialising `filter_events_hourly` over the range it just
    wrote — see :func:`refresh_hourly_aggregate` for why that is not optional.

    Returns counts; never raises, because a failed backfill must leave the
    journal and the existing mirror exactly as they were.
    """
    out = {"read": 0, "written": 0, "failed": 0, "aggregate_refreshed": 0}
    if not available():
        return out
    try:
        from sqlalchemy import text

        from warden.analytics.logger import load_entries

        entries = load_entries(days=days)
        out["read"] = len(entries)
        for i in range(0, len(entries), batch):
            chunk = entries[i:i + batch]
            try:
                with _engine().begin() as conn:
                    conn.execute(text(_INSERT), [_params(e) for e in chunk])
                out["written"] += len(chunk)
            except Exception as exc:
                out["failed"] += len(chunk)
                log.warning("filter_events backfill: batch failed: %s", exc)
    except Exception as exc:
        log.warning("filter_events backfill aborted: %s", exc)
        return out

    reset_coverage_cache()
    if out["written"]:
        out["aggregate_refreshed"] = 1 if refresh_hourly_aggregate() else 0
    log.info("filter_events backfill %s", out)
    return out


def refresh_hourly_aggregate() -> bool:
    """Materialise `filter_events_hourly` over its whole range. Never raises.

    Timescale refreshes a continuous aggregate through a policy, and revision
    `0013` gives this one `start_offset => 3 hours`. That is right for the live
    path and useless for a backfill: rows written with older timestamps sit
    outside every window the policy will ever refresh, so they are never
    materialised. Measured on the first production backfill (2026-08-08) —
    3 311 rows landed in the hypertable and `filter_events_hourly` stayed at
    **zero buckets**, so `hourly_series()`, the dashboard read path, returned
    an empty list for everything older than three hours while `summary()` and
    `top_flags()` (which read the hypertable directly) were correct. A backfill
    that leaves the aggregate empty is half a backfill.

    `refresh_continuous_aggregate` cannot run inside a transaction block, hence
    the explicit AUTOCOMMIT connection rather than `engine.begin()`.
    """
    if not available():
        return False
    try:
        from sqlalchemy import text

        with _engine().connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(
                text("CALL refresh_continuous_aggregate('warden_core.filter_events_hourly', NULL, NULL)")
            )
        log.info("filter_events_hourly refreshed over full range")
        return True
    except Exception as exc:
        # Not counted as a mirror failure: the rows are in the hypertable and
        # every reader except hourly_series() is already correct. Loud, because
        # the fix is one operator call and the symptom otherwise looks like
        # "the dashboard has no history".
        log.warning(
            "filter_events_hourly refresh failed (%s) — rows are mirrored but the "
            "hourly aggregate is stale; run CALL refresh_continuous_aggregate("
            "'warden_core.filter_events_hourly', NULL, NULL)",
            exc,
        )
        return False


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
            reset_coverage_cache()   # the floor just moved forward
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
    if not covers(since):
        return None
    try:
        from sqlalchemy import text

        # Each statement is written out where it is executed. Not style: the
        # SAST gate's `avoid-sqlalchemy-text` rule only clears `text()` when it
        # can see the literal at the call site, and a rule that has to trace a
        # value back through a module constant cannot vouch for it. Nothing
        # here is user input either way — every value is bound.
        with _engine().connect() as conn:
            if tenant_id:
                row = conn.execute(
                    text("""
                        SELECT
                            COUNT(*)                                     AS total,
                            COUNT(*) FILTER (WHERE allowed)              AS allowed,
                            COUNT(*) FILTER (WHERE NOT allowed)          AS blocked,
                            COUNT(*) FILTER (WHERE upper(risk_level) = 'HIGH')  AS high,
                            COUNT(*) FILTER (WHERE upper(risk_level) = 'BLOCK') AS block,
                            COUNT(*) FILTER (WHERE masked)               AS masked,
                            COALESCE(SUM(attack_cost_usd), 0)            AS attack_cost_usd,
                            AVG(elapsed_ms)                              AS avg_elapsed_ms
                        FROM warden_core.filter_events
                        WHERE ts >= :since AND tenant_id = :tid
                    """),
                    {"since": since, "tid": tenant_id},
                ).fetchone()
            else:
                row = conn.execute(
                    text("""
                        SELECT
                            COUNT(*)                                     AS total,
                            COUNT(*) FILTER (WHERE allowed)              AS allowed,
                            COUNT(*) FILTER (WHERE NOT allowed)          AS blocked,
                            COUNT(*) FILTER (WHERE upper(risk_level) = 'HIGH')  AS high,
                            COUNT(*) FILTER (WHERE upper(risk_level) = 'BLOCK') AS block,
                            COUNT(*) FILTER (WHERE masked)               AS masked,
                            COALESCE(SUM(attack_cost_usd), 0)            AS attack_cost_usd,
                            AVG(elapsed_ms)                              AS avg_elapsed_ms
                        FROM warden_core.filter_events
                        WHERE ts >= :since
                    """),
                    {"since": since},
                ).fetchone()
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
    if not covers(since):
        return None
    try:
        from sqlalchemy import text

        with _engine().connect() as conn:
            if tenant_id:
                rows = conn.execute(
                    text("""
                        SELECT bucket, tenant_id, total, allowed, blocked, high, block,
                               masked, attack_cost_usd, avg_elapsed_ms, max_elapsed_ms
                        FROM warden_core.filter_events_hourly
                        WHERE bucket >= :since AND tenant_id = :tid
                        ORDER BY bucket
                    """),
                    {"since": since, "tid": tenant_id},
                )
            else:
                rows = conn.execute(
                    text("""
                        SELECT bucket, tenant_id, total, allowed, blocked, high, block,
                               masked, attack_cost_usd, avg_elapsed_ms, max_elapsed_ms
                        FROM warden_core.filter_events_hourly
                        WHERE bucket >= :since
                        ORDER BY bucket
                    """),
                    {"since": since},
                )
            return [dict(r._mapping) for r in rows]
    except Exception as exc:
        log.debug("filter_events hourly_series unavailable: %s", exc)
        return None


def blocked_flag_counts(since: datetime) -> dict[str, int] | None:
    """Flag → occurrences among **non-allowed** decisions in the window.

    The threat-category breakdown reporting needs; doing it in SQL turns a
    full-window scan plus a Python Counter into one grouped query.
    """
    if not covers(since):
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
    if not covers(since):
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


def compliance_metrics(since: datetime) -> dict[str, Any] | None:
    """Every journal-derived figure `compliance/dashboard.py` needs, in one trip.

    `ComplianceDashboard.get_metrics()` pulled the whole window into memory and
    made eight passes over it in Python — a Counter over `flags`, another over
    `secrets_found`, four sums and two filtered counts. All eight are one
    grouped query each here.

    Note `high_blocks` counts HIGH **and** BLOCK together, which is what the
    ROI arithmetic downstream means by "an averted incident" — not the
    `summary()` split, where they are separate columns.

    Returns ``None`` when the mirror cannot cover the window, and the caller
    falls back to its `load_entries()` scan.
    """
    if not covers(since):
        return None
    try:
        from sqlalchemy import text

        with _engine().connect() as conn:
            row = conn.execute(
                text("""
                    SELECT
                        COUNT(*)                                            AS total,
                        COUNT(*) FILTER (WHERE NOT allowed)                  AS blocked,
                        COUNT(*) FILTER (
                            WHERE upper(risk_level) IN ('HIGH', 'BLOCK'))    AS high_blocks,
                        COUNT(*) FILTER (WHERE 'shadow_ban' = ANY(flags))    AS shadow_ban,
                        COALESCE(SUM(attack_cost_usd), 0)                    AS attack_cost_usd,
                        COALESCE(SUM(payload_tokens), 0)                     AS payload_tokens,
                        COALESCE(SUM(COALESCE(array_length(secrets_found, 1), 0)), 0)
                                                                             AS secrets_total
                    FROM warden_core.filter_events
                    WHERE ts >= :since
                """),
                {"since": since},
            ).fetchone()
            if row is None:
                return None

            flag_rows = conn.execute(
                text("""
                    SELECT flag, COUNT(*) AS n
                    FROM warden_core.filter_events, UNNEST(flags) AS flag
                    WHERE ts >= :since
                    GROUP BY flag ORDER BY n DESC LIMIT 10
                """),
                {"since": since},
            ).fetchall()

            secret_rows = conn.execute(
                text("""
                    SELECT s, COUNT(*) AS n
                    FROM warden_core.filter_events, UNNEST(secrets_found) AS s
                    WHERE ts >= :since
                    GROUP BY s ORDER BY n DESC
                """),
                {"since": since},
            ).fetchall()

        d = dict(row._mapping)
        return {
            "total": int(d["total"] or 0),
            "blocked": int(d["blocked"] or 0),
            "high_blocks": int(d["high_blocks"] or 0),
            "shadow_ban": int(d["shadow_ban"] or 0),
            "attack_cost_usd": float(d["attack_cost_usd"] or 0.0),
            "payload_tokens": int(d["payload_tokens"] or 0),
            "secrets_total": int(d["secrets_total"] or 0),
            "flag_counts": {r[0]: int(r[1]) for r in flag_rows},
            "secret_counts": {r[0]: int(r[1]) for r in secret_rows},
        }
    except Exception as exc:
        log.debug("filter_events compliance_metrics unavailable: %s", exc)
        return None


def community_stats(
    retention_floor: datetime,
    *,
    now: datetime,
    trend_days: int = 7,
    flag_days: int = 30,
    recent_limit: int = 10,
) -> dict[str, Any] | None:
    """Everything `api/public_stats.py`'s public dashboard needs, in one round trip.

    That endpoint is unauthenticated and previously called `load_entries()` with
    no window at all — a full-journal scan on every hit from the open internet.
    ``retention_floor`` should be ``now - GDPR_LOG_RETENTION_DAYS``: the oldest
    timestamp the journal can ever hold post-purge, which is what "all-time"
    means in practice for a store with a retention policy. ``covers()`` refuses
    the call otherwise, exactly like every other reader here.

    ``recent`` preserves the source's existing order — oldest-within-the-window
    first, not most-recent-first. That ordering predates this migration and is
    reproduced deliberately rather than "fixed" as a side effect of moving the
    query to SQL.
    """
    if not covers(retention_floor):
        return None
    try:
        from sqlalchemy import text

        trend_floor = now - timedelta(days=trend_days)
        flag_floor = now - timedelta(days=flag_days)

        with _engine().connect() as conn:
            totals = conn.execute(
                text("""
                    SELECT
                        COUNT(DISTINCT tenant_id)
                            FILTER (WHERE tenant_id NOT IN ('', 'default'))    AS members,
                        COUNT(*)                                                AS total,
                        COUNT(*) FILTER (WHERE NOT allowed)                     AS blocked
                    FROM warden_core.filter_events
                """)
            ).fetchone()

            trend_rows = conn.execute(
                text("""
                    SELECT
                        to_char(ts, 'YYYY-MM-DD')                                       AS day,
                        COUNT(*) FILTER (
                            WHERE NOT allowed OR upper(risk_level) = 'BLOCK')           AS block,
                        COUNT(*) FILTER (
                            WHERE allowed AND upper(risk_level) <> 'BLOCK'
                              AND upper(risk_level) IN ('HIGH', 'CRITICAL'))            AS high,
                        COUNT(*) FILTER (
                            WHERE allowed AND upper(risk_level) <> 'BLOCK'
                              AND upper(risk_level) NOT IN ('HIGH', 'CRITICAL'))        AS allow
                    FROM warden_core.filter_events
                    WHERE ts >= :trend_floor
                    GROUP BY day
                """),
                {"trend_floor": trend_floor},
            ).fetchall()

            flag_rows = conn.execute(
                text("""
                    SELECT flag, COUNT(*) AS n
                    FROM warden_core.filter_events, UNNEST(flags) AS flag
                    WHERE ts >= :flag_floor
                    GROUP BY flag ORDER BY n DESC LIMIT 5
                """),
                {"flag_floor": flag_floor},
            ).fetchall()

            recent_rows = conn.execute(
                text("""
                    SELECT ts, allowed, risk_level, flags
                    FROM warden_core.filter_events
                    WHERE ts >= :trend_floor
                    ORDER BY ts ASC
                    LIMIT :lim
                """),
                {"trend_floor": trend_floor, "lim": recent_limit},
            ).fetchall()
    except Exception as exc:
        log.debug("filter_events community_stats unavailable: %s", exc)
        return None

    total = int(totals[1] or 0)
    blocked = int(totals[2] or 0)

    trend = {r[0]: {"block": int(r[1]), "high": int(r[2]), "allow": int(r[3])} for r in trend_rows}
    for i in range(trend_days):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        trend.setdefault(day, {"block": 0, "high": 0, "allow": 0})

    recent = []
    for ts, allowed, risk_level, flags in recent_rows:
        rl = (risk_level or "UNKNOWN").upper()
        verdict = "BLOCK" if not allowed else ("HIGH" if rl in ("HIGH", "CRITICAL") else "ALLOW")
        recent.append({
            "verdict": verdict, "risk_level": rl,
            "date": ts.strftime("%Y-%m-%d"), "flags": list(flags or [])[:2],
        })

    return {
        "members": int(totals[0] or 0),
        "total_events": total,
        "blocked_total": blocked,
        "block_rate_pct": round(blocked / total * 100, 1) if total else 0.0,
        "trend_7d": [{"date": d, **v} for d, v in sorted(trend.items())],
        "top_threats": [{"type": f, "count": int(n)} for f, n in flag_rows if n > 0],
        "recent": recent,
    }
