"""
warden/tests/test_filter_events_store.py — D-3 SQL read path for the /filter journal.

The properties that matter here are the safety ones, and they hold with no
Postgres present:

  * the mirror is **opt-in** and **fail-open** — it can never break `append()`,
    which owns the authoritative NDJSON write;
  * readers **degrade to None** rather than raising, so every caller keeps its
    existing `load_entries()` path;
  * GDPR erasure reaches the mirror. `purge_before()` is the subject-erasure
    endpoint's implementation; a mirrored copy that outlived it would be a
    violation, not a stale cache. That is asserted, including the case where the
    NDJSON file is already gone.
  * the mirror carries **metadata only** — no column may accept payload text.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from warden.analytics import events_store

# ── Opt-in + fail-open writer ─────────────────────────────────────────────────

def test_mirror_is_off_by_default(monkeypatch):
    """Merging D-3 must change nothing until an operator opts in."""
    monkeypatch.setattr("warden.config.settings.filter_events_mirror", False, raising=False)
    assert events_store.enabled() is False
    assert events_store.mirror({"request_id": "r1", "ts": "2026-01-01T00:00:00+00:00"}) is False


def test_mirror_requires_a_database(monkeypatch):
    monkeypatch.setattr("warden.config.settings.filter_events_mirror", True, raising=False)
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "", raising=False)
    assert events_store.enabled() is False


def test_mirror_swallows_backend_failure(monkeypatch):
    """A mirror write that raises must not propagate: the NDJSON line is already
    written and is what the system depends on."""
    monkeypatch.setattr("warden.config.settings.filter_events_mirror", True, raising=False)
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)

    def _boom():
        raise RuntimeError("postgres is down")

    monkeypatch.setattr(events_store, "_engine", _boom)

    before = events_store.mirror_failure_count()
    assert events_store.mirror({"request_id": "r", "ts": "2026-01-01T00:00:00+00:00"}) is False
    assert events_store.mirror_failure_count() == before + 1


def test_append_still_works_when_mirror_explodes(monkeypatch, tmp_path):
    """End-to-end: the journal append is unaffected by a broken mirror."""
    from warden.analytics import logger

    logs = tmp_path / "logs.json"
    monkeypatch.setattr(logger, "LOGS_PATH", logs, raising=False)
    monkeypatch.setattr(logger, "_SEEN_REQUEST_IDS", type(logger._SEEN_REQUEST_IDS)())

    def _explode(_entry):
        raise RuntimeError("mirror is on fire")

    monkeypatch.setattr(events_store, "mirror", _explode)

    entry = logger.build_entry(
        request_id="req-1", allowed=False, risk_level="BLOCK", flags=["jailbreak"],
        secrets_found=[], payload_len=10, payload_tokens=3, attack_cost_usd=0.01,
        elapsed_ms=1.5, strict=False,
    )
    logger.append(entry)

    written = [json.loads(ln) for ln in logs.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(written) == 1 and written[0]["request_id"] == "req-1"


# ── Readers degrade, never raise ──────────────────────────────────────────────

@pytest.mark.parametrize(
    "call",
    [
        lambda since: events_store.summary(since),
        lambda since: events_store.hourly_series(since),
        lambda since: events_store.top_flags(since),
        lambda since: events_store.blocked_flag_counts(since),
    ],
)
def test_readers_return_none_without_postgres(monkeypatch, call):
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "", raising=False)
    assert call(datetime.now(UTC) - timedelta(days=1)) is None


def test_financial_reader_uses_the_authoritative_journal(monkeypatch, tmp_path):
    """Financial figures never come from the mirror.

    The mirror is fail-open — a write that raises is counted and dropped — so a
    dollar-impact number taken from it could under-report with no signal. These
    counters read the NDJSON journal, which is the only complete record.
    """
    from warden.financial.metrics_reader import MetricsReader

    logs = tmp_path / "logs.json"
    now = datetime.now(UTC)
    rows = [
        {"ts": now.isoformat(), "request_id": "a", "allowed": False,
         "risk_level": "BLOCK", "flags": ["jailbreak"], "masked": True},
        {"ts": now.isoformat(), "request_id": "b", "allowed": True,
         "risk_level": "LOW", "flags": [], "masked": False},
    ]
    logs.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "", raising=False)

    reader = MetricsReader(logs_path=str(logs), lookback_days=30)
    assert reader.monthly_requests() == 2          # 2 entries, 30/30 scaling
    assert reader.pii_redactions_count() == 1


# ── GDPR ──────────────────────────────────────────────────────────────────────

def test_purge_before_also_erases_the_mirror(monkeypatch, tmp_path):
    """Subject erasure must reach every copy, not just the NDJSON file."""
    from warden.analytics import logger

    logs = tmp_path / "logs.json"
    old = datetime.now(UTC) - timedelta(days=90)
    logs.write_text(json.dumps({"ts": old.isoformat(), "request_id": "old"}) + "\n",
                    encoding="utf-8")
    monkeypatch.setattr(logger, "LOGS_PATH", logs, raising=False)

    seen: list[datetime] = []
    monkeypatch.setattr(events_store, "purge_before", lambda before: seen.append(before) or 1)

    cutoff = datetime.now(UTC) - timedelta(days=30)
    logger.purge_before(cutoff)
    assert seen == [cutoff], "purge_before() did not erase the SQL mirror"


def test_mirror_is_purged_even_when_the_journal_file_is_missing(monkeypatch, tmp_path):
    """"No NDJSON file" says nothing about what Postgres still holds — the early
    return must not skip the mirror."""
    from warden.analytics import logger

    monkeypatch.setattr(logger, "LOGS_PATH", tmp_path / "does-not-exist.json", raising=False)

    seen: list[datetime] = []
    monkeypatch.setattr(events_store, "purge_before", lambda before: seen.append(before) or 0)

    cutoff = datetime.now(UTC) - timedelta(days=30)
    assert logger.purge_before(cutoff) == 0
    assert seen == [cutoff], "mirror was not purged when logs.json was absent"


def test_retention_purge_covers_the_mirror(monkeypatch, tmp_path):
    from warden.analytics import logger

    monkeypatch.setattr(logger, "LOGS_PATH", tmp_path / "absent.json", raising=False)
    seen: list[datetime] = []
    monkeypatch.setattr(events_store, "purge_before", lambda before: seen.append(before) or 0)

    logger.purge_old_entries()
    assert len(seen) == 1, "purge_old_entries() did not age out the SQL mirror"


def test_mirror_carries_metadata_only(monkeypatch):
    """GDPR: content is NEVER stored. An entry carrying payload text must not
    produce a parameter holding it — unknown keys are dropped by projection."""
    params = events_store._params({
        "ts": "2026-01-01T00:00:00+00:00",
        "request_id": "r",
        "allowed": True,
        "risk_level": "LOW",
        "content": "my secret prompt",       # must never survive
        "payload": "sk-live-abcdef",         # must never survive
        "decoded_text": "decoded payload",   # must never survive
    })
    joined = " ".join(str(v) for v in params.values())
    for forbidden in ("my secret prompt", "sk-live-abcdef", "decoded payload"):
        assert forbidden not in joined
    assert set(params) <= {
        "ts", "request_id", "tenant_id", "allowed", "risk_level", "flags",
        "secrets_found", "payload_len", "payload_tokens", "attack_cost_usd",
        "elapsed_ms", "strict", "session_id", "entities_detected",
        "entity_count", "masked",
    }


def test_migration_defines_no_content_column():
    """The table must never gain a column that could carry payload text."""
    rev = (
        Path(__file__).resolve().parent.parent
        / "db" / "migrations" / "versions" / "0013_filter_events.py"
    ).read_text(encoding="utf-8")
    # Take the whole CREATE TABLE, not up to the first ")" — that stops inside
    # `NUMERIC(14,6)` and leaves most of the column list unchecked, so the guard
    # was not guarding. Cut at the statement's closing `"""` instead.
    after = rev.split("CREATE TABLE IF NOT EXISTS warden_core.filter_events")[1]
    body = after.split('"""')[0]
    assert "masked" in body, "the column list was truncated — this guard is not reading the table"
    for forbidden in ("content", "payload_text", "prompt", "raw", "decoded", "body"):
        assert forbidden not in body.lower(), (
            f"filter_events gained a `{forbidden}` column — the journal is "
            "metadata-only (GDPR)."
        )


# ── Coverage floor ────────────────────────────────────────────────────────────

def test_readers_refuse_a_window_the_mirror_cannot_cover(monkeypatch):
    """The failure this prevents is silent under-reporting.

    Nothing backfills the mirror when an operator flips it on, so a reader asking
    for 30 days would otherwise get only the rows since the flip and present them
    as the whole window — a smaller number than the truth with nothing to say so.
    Worse than the NDJSON scan it replaces, because the scan is correct.
    """
    from datetime import UTC, datetime, timedelta

    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)
    now = datetime.now(UTC)
    events_store.reset_coverage_cache()
    # The mirror holds only the last hour.
    monkeypatch.setattr(events_store, "coverage_start", lambda: now - timedelta(hours=1))

    assert events_store.covers(now - timedelta(minutes=30)) is True
    assert events_store.covers(now - timedelta(days=30)) is False
    assert events_store.summary(now - timedelta(days=30)) is None
    assert events_store.hourly_series(now - timedelta(days=30)) is None
    assert events_store.top_flags(now - timedelta(days=30)) is None
    assert events_store.blocked_flag_counts(now - timedelta(days=30)) is None


def test_an_empty_mirror_covers_nothing(monkeypatch):
    from datetime import UTC, datetime, timedelta

    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)
    events_store.reset_coverage_cache()
    monkeypatch.setattr(events_store, "coverage_start", lambda: None)
    assert events_store.covers(datetime.now(UTC) - timedelta(minutes=1)) is False


def test_backfill_is_a_noop_without_postgres(monkeypatch):
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "", raising=False)
    assert events_store.backfill_from_journal() == {
        "read": 0, "written": 0, "failed": 0, "aggregate_refreshed": 0,
    }


def test_backfill_never_raises_when_the_backend_fails(monkeypatch, tmp_path):
    """A failed backfill must leave the journal and the existing mirror alone."""
    from warden.analytics import logger

    logs = tmp_path / "logs.json"
    entry = {"ts": "2026-01-01T00:00:00+00:00", "request_id": "a"}
    logs.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    monkeypatch.setattr(logger, "LOGS_PATH", logs, raising=False)
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)

    def _boom():
        raise RuntimeError("postgres is down")

    monkeypatch.setattr(events_store, "_engine", _boom)
    out = events_store.backfill_from_journal()
    assert out["failed"] >= 1 and out["written"] == 0


# ── continuous-aggregate refresh after a backfill ─────────────────────────────
#
# The refresh policy on `filter_events_hourly` has start_offset => 3 hours, so
# backfilled rows with older timestamps are never materialised by it. Measured
# in production: 3 311 rows mirrored, the aggregate stayed at zero buckets, and
# hourly_series() — the dashboard path — returned nothing beyond three hours.

def test_backfill_refreshes_the_hourly_aggregate(monkeypatch, tmp_path):
    from warden.analytics import logger

    logs = tmp_path / "logs.json"
    logs.write_text(
        json.dumps({"ts": "2026-01-01T00:00:00+00:00", "request_id": "a"}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(logger, "LOGS_PATH", logs, raising=False)
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)

    written: list[object] = []

    class _Conn:
        def execute(self, *a, **k):
            written.append(a)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Engine:
        def begin(self):
            return _Conn()

    monkeypatch.setattr(events_store, "_engine", lambda: _Engine())
    refreshed: list[bool] = []
    monkeypatch.setattr(
        events_store, "refresh_hourly_aggregate", lambda: refreshed.append(True) or True
    )

    out = events_store.backfill_from_journal()
    assert out["written"] == 1
    assert out["aggregate_refreshed"] == 1, "a backfill that skips the refresh is half a backfill"
    assert refreshed == [True]


def test_backfill_does_not_refresh_when_nothing_was_written(monkeypatch):
    """No rows, no refresh — the aggregate cannot have gone stale."""
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)
    monkeypatch.setattr(events_store, "_engine", lambda: (_ for _ in ()).throw(RuntimeError("down")))
    called: list[int] = []
    monkeypatch.setattr(events_store, "refresh_hourly_aggregate", lambda: called.append(1) or True)

    assert events_store.backfill_from_journal()["aggregate_refreshed"] == 0
    assert called == []


def test_refresh_runs_outside_a_transaction(monkeypatch):
    """CALL refresh_continuous_aggregate() is rejected inside a transaction block."""
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)
    opts: list[dict] = []
    stmts: list[str] = []

    class _Conn:
        def execute(self, stmt, *a, **k):
            stmts.append(str(stmt))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Raw:
        def execution_options(self, **kw):
            opts.append(kw)
            return _Conn()

    monkeypatch.setattr(events_store, "_engine", lambda: type("E", (), {"connect": lambda s: _Raw()})())

    assert events_store.refresh_hourly_aggregate() is True
    assert opts == [{"isolation_level": "AUTOCOMMIT"}]
    assert "refresh_continuous_aggregate" in stmts[0]


def test_refresh_failure_never_raises(monkeypatch):
    """The rows are already mirrored; a stale aggregate must not undo that."""
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)
    monkeypatch.setattr(events_store, "_engine", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert events_store.refresh_hourly_aggregate() is False


def test_refresh_is_a_noop_without_postgres(monkeypatch):
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "", raising=False)
    assert events_store.refresh_hourly_aggregate() is False


# ── community_stats (public_stats.py's single query) ──────────────────────────

def test_community_stats_refuses_a_window_the_mirror_cannot_cover(monkeypatch):
    from datetime import UTC, datetime, timedelta

    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)
    events_store.reset_coverage_cache()
    now = datetime.now(UTC)
    monkeypatch.setattr(events_store, "coverage_start", lambda: now - timedelta(hours=1))
    assert events_store.community_stats(now - timedelta(days=7), now=now) is None


def test_community_stats_excludes_the_default_tenant_sentinel(monkeypatch):
    """`_params()` substitutes tenant_id="default" for any falsy value, so a
    naive `COUNT(DISTINCT tenant_id) WHERE tenant_id <> ''` would count entries
    that arrived with no tenant at all as a real, distinct member. That inflated
    `members` by exactly one in an early version of this query, caught by
    comparing against the NDJSON-scan reference implementation."""
    from datetime import UTC, datetime, timedelta

    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)
    events_store.reset_coverage_cache()
    now = datetime.now(UTC)
    monkeypatch.setattr(events_store, "coverage_start", lambda: now - timedelta(days=30))

    class _Row(tuple):
        pass

    class _FakeResult:
        def __init__(self, rows):
            self._rows = rows

        def fetchone(self):
            return self._rows[0] if self._rows else None

        def fetchall(self):
            return self._rows

    calls: list[str] = []

    class _FakeConn:
        def execute(self, stmt, params=None):
            sql = str(stmt)
            calls.append(sql)
            if "COUNT(DISTINCT tenant_id)" in sql:
                assert "'default'" in sql, (
                    "the members query no longer excludes the 'default' sentinel "
                    "that _params() substitutes for a missing tenant_id"
                )
                return _FakeResult([(0, 0, 0)])
            if "to_char(ts" in sql:
                return _FakeResult([])
            if "UNNEST(flags)" in sql:
                return _FakeResult([])
            return _FakeResult([])

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeEngine:
        def connect(self):
            return _FakeConn()

    monkeypatch.setattr(events_store, "_engine", lambda: _FakeEngine())
    result = events_store.community_stats(now - timedelta(days=7), now=now)
    assert result is not None
    assert any("COUNT(DISTINCT tenant_id)" in c for c in calls)
