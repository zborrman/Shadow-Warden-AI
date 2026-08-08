"""
warden/tests/test_journal_bound.py — the NDJSON journal's bound is a cron job (D-3 / 1d).

Phase 1d of the data-layer plan was written as "rotate `logs.json`", on the
audit's finding that the file "has no rotation — only GDPR `purge_before()`" and
that read cost therefore "grows linearly and forever".

Measured before implementing anything, that premise is false.
`purge_old_entries()` *is* the rotation: it trims to `GDPR_LOG_RETENTION_DAYS`,
it runs daily as the registered `cron:run_gdpr_retention` job, and production
shows it working — the oldest entry on 2026-08-08 was 29 days old against a
30-day window, in a 1.09 MB file. Adding a second rotation mechanism on top of a
working one is what this whole track has spent its time removing.

What is real is that the bound is a *scheduled job*, and a scheduled job that
stops has no symptom. These tests pin the two things that make that visible.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from warden.analytics import logger


@pytest.fixture
def journal(tmp_path, monkeypatch):
    path = tmp_path / "logs.json"
    monkeypatch.setattr(logger, "LOGS_PATH", path, raising=False)
    return path


def _write(path, *ages_in_days: float) -> None:
    now = datetime.now(UTC)
    path.write_text(
        "".join(
            json.dumps({"ts": (now - timedelta(days=d)).isoformat(), "request_id": f"r{i}"}) + "\n"
            for i, d in enumerate(ages_in_days)
        ),
        encoding="utf-8",
    )


def test_stats_report_a_trimmed_journal_as_bounded(journal, monkeypatch):
    monkeypatch.setattr(logger, "LOG_RETENTION_DAYS", 30, raising=False)
    _write(journal, 29, 10, 0.5)
    stats = logger.journal_stats()
    assert stats["entries"] == 3
    assert stats["bounded"] is True
    assert 28.9 < stats["oldest_age_days"] < 29.1


def test_stats_report_an_untrimmed_journal_as_unbounded(journal, monkeypatch):
    """The signal that retention has stopped running, whatever the logs claim."""
    monkeypatch.setattr(logger, "LOG_RETENTION_DAYS", 30, raising=False)
    _write(journal, 45, 1)
    stats = logger.journal_stats()
    assert stats["bounded"] is False, (
        "an entry 45 days into a 30-day window means the retention cron has not run"
    )
    assert stats["retention_days"] == 30


def test_one_day_of_slack_for_the_cron_schedule(journal, monkeypatch):
    """Retention runs once a day, so exactly-at-the-window is not yet a fault."""
    monkeypatch.setattr(logger, "LOG_RETENTION_DAYS", 30, raising=False)
    _write(journal, 30.5)
    assert logger.journal_stats()["bounded"] is True
    _write(journal, 31.5)
    assert logger.journal_stats()["bounded"] is False


def test_stats_do_not_hold_the_journal_in_memory(journal, monkeypatch):
    """An operator probe must not cost more than the scan it is watching."""
    monkeypatch.setattr(logger, "LOG_RETENTION_DAYS", 30, raising=False)
    _write(journal, *[float(i) / 100 for i in range(500)])
    stats = logger.journal_stats()
    assert stats["entries"] == 500
    assert not any(isinstance(v, (list, dict)) for v in stats.values()), (
        "journal_stats returned entry data — it must return counters only"
    )


def test_missing_journal_is_bounded_not_broken(journal):
    stats = logger.journal_stats()
    assert stats["exists"] is False and stats["bounded"] is True and stats["entries"] == 0


def test_retention_failure_is_counted_not_swallowed(monkeypatch):
    """A purge that raises used to return 0 — identical to a quiet day.

    Retention is what bounds the journal *and* what erases expired personal
    data, so a silent failure is a compliance event. It must reach the
    fail-open counter, which is what an alert can key on.
    """
    import asyncio

    from warden.api import gdpr

    def _boom():
        raise RuntimeError("disk full")

    monkeypatch.setattr(logger, "purge_old_entries", _boom, raising=False)

    seen: list[tuple] = []
    import warden.observability as obs

    monkeypatch.setattr(obs, "record_failopen", lambda *a, **k: seen.append(a), raising=False)

    assert asyncio.run(gdpr.run_retention_purge()) == 0
    assert seen and seen[0][0] == "gdpr_retention_purge", (
        "a failed retention run left no counter behind"
    )


def test_retention_cron_is_registered():
    """The bound only exists because this job is scheduled — pin that.

    `run_gdpr_retention`'s own docstring claimed a 02:00 UTC schedule; on this
    codebase that happens to be true, but the same claim was false for the
    Alembic step in entrypoint.sh for four months (see warden/db/migrate.py).
    A docstring is not a schedule.
    """
    # Read the source rather than importing it: `warden/workers/settings.py`
    # imports `arq`, which is a container runtime dependency and absent from the
    # test environment. The question here is whether the job is registered, and
    # the file answers that without a worker.
    src = (
        Path(__file__).resolve().parent.parent / "workers" / "settings.py"
    ).read_text(encoding="utf-8")
    cron_block = src.split("cron_jobs", 1)[1]
    assert "cron(run_gdpr_retention" in cron_block, (
        "the GDPR retention cron is not registered — logs.json has no bound at all"
    )
