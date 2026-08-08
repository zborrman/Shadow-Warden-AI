"""
warden/db/migrate.py — run the Alembic tree against the app Postgres (D-1).

Why this module exists
──────────────────────
`warden/db/migrations/` has held a real revision chain (0001 → 0010 → 0011)
since the uptime-monitoring and pgvector features shipped — and **nothing ever
ran it to completion**.

The original audit said `alembic upgrade head` appeared nowhere in CI,
`entrypoint.sh`, the Dockerfile or the deploy workflow. That was wrong in one
place, and the correction is worth keeping: `entrypoint.sh` *did* invoke it,
on every boot, since `b3d02377` (2026-04-06) — with a path that could never
resolve (`cd /warden` + `-c warden/alembic.ini`, while the ini is at
`/warden/alembic.ini`), behind `|| echo "WARNING: migrations failed (continuing
anyway)"`. So the tree was invoked on ~every boot for four months, failed every
time with `No 'script_location' key found in configuration`, and the `|| echo`
reduced each failure to one ignorable log line. Removed in the same change that
verified D-1 in production; the lifespan call below is the only invocation.

Postgres schema in production came from two other places instead:

  * `data/init.sql`  — applied once by the Postgres entrypoint on *first*
    container init only (so it never picks up later changes), and
  * `connection.py::create_schema()` — a hand-maintained idempotent DDL list
    called from the FastAPI lifespan.

Neither contains the tables that exist only in the migration tree, so three
objects were never created in any deployment:

  * `warden_core.monitors`       (0010) — `warden/api/monitor.py` is **mounted**
    at `/monitors` and queries it, so every endpoint there fails.
  * `warden_core.probe_results`  (0010) — the uptime hypertable + its continuous
    aggregate, retention and compression policies.
  * `marketplace_embeddings`     (0011) — pgvector semantic listing search, which
    fails *open*, so it degraded silently rather than erroring.

Same failure shape as the Track P finding that PQC never worked in a deployed
image: a shipped, mounted, documented feature that cannot function because a
step everyone assumed ran, did not.

Safety properties
─────────────────
  * **Idempotent against the live DB.** Every statement in all three revisions is
    `CREATE … IF NOT EXISTS` / `if_not_exists => TRUE`, verified before this
    landed. The existing production tables are adopted, not recreated — Alembic
    stamps `alembic_version` and moves on.
  * **Single-migrator.** A Postgres advisory lock serialises concurrent workers
    and containers; losers wait up to `timeout_s`, then skip rather than block
    boot forever. Exactly one process runs the upgrade.
  * **No-op without Postgres.** Empty `DATABASE_URL` returns `skipped` — the
    SQLite-only / air-gapped deployment is unchanged.
  * **Fail-soft, and now without a second path.** `create_schema()` was the
    fallback when this landed; it was deleted in `8220f6c6` once production
    reached `0013` cleanly. A failure here is logged loudly and the gateway
    continues — the filter pipeline has no Postgres dependency, so refusing to
    boot would trade a reporting outage for a security one. The features that
    need these tables now fail on their own, which is the only signal and the
    correct one.
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("warden.db.migrate")

# Stable per-application advisory-lock key. Any int64 works as long as nothing
# else in this database picks the same one; this is the only advisory lock the
# app takes.
_LOCK_KEY = 0x5741_5244_4E01  # "WARDEN" + slot 1, comfortably inside int64

_HERE = Path(__file__).resolve().parent
_MIGRATIONS_DIR = _HERE / "migrations"
_ALEMBIC_INI = _HERE.parent / "alembic.ini"   # warden/alembic.ini


def _alembic_config(sync_url: str) -> Any:
    """Build an Alembic Config with absolute paths.

    `warden/alembic.ini` sets `script_location = warden/db/migrations`, which
    only resolves when the process cwd happens to be the repo root. The
    container's workdir is not guaranteed to be, so both the ini path and the
    script location are resolved from `__file__` instead of the cwd.
    """
    from alembic.config import Config
    cfg = Config(str(_ALEMBIC_INI) if _ALEMBIC_INI.exists() else None)
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", sync_url)
    return cfg


def upgrade_to_head(*, timeout_s: float = 60.0) -> dict[str, Any]:
    """Run `alembic upgrade head` once, under an advisory lock.

    Returns a status dict — never raises for an ordinary "cannot migrate here"
    condition (no Postgres, lock held elsewhere). A genuine migration failure
    *does* propagate, so the caller can fall back and log it.

    status:
      ``skipped_no_database``  — DATABASE_URL empty (SQLite-only deployment)
      ``skipped_locked``       — another process holds the lock; it is migrating
      ``ok``                   — upgrade ran to head in this process
    """
    from warden.db.connection import DATABASE_URL, _sync_url
    if not DATABASE_URL:
        return {"status": "skipped_no_database"}

    from sqlalchemy import text

    from warden.db.connection import get_engine
    engine = get_engine()
    started = time.monotonic()

    # Hold the lock on its own connection for the whole upgrade: Alembic opens a
    # separate connection of its own, and a session-scoped advisory lock only
    # lives as long as the session that took it.
    with engine.connect() as lock_conn:
        acquired = False
        while True:
            acquired = bool(
                lock_conn.execute(
                    text("SELECT pg_try_advisory_lock(:k)"), {"k": _LOCK_KEY}
                ).scalar()
            )
            if acquired or (time.monotonic() - started) >= timeout_s:
                break
            time.sleep(0.5)

        if not acquired:
            log.warning(
                "alembic: another process holds the migration lock after %.0fs — "
                "skipping upgrade in this worker (it is being applied elsewhere)",
                timeout_s,
            )
            return {"status": "skipped_locked"}

        sync_url = _sync_url(DATABASE_URL)
        # migrations/env.py reads os.environ["DATABASE_URL"] itself and *raises*
        # when it is unset — it never consults the Config we build. The app
        # resolves its URL through settings, which today happens to read the same
        # env var, but relying on that coupling means a deployment that supplies
        # the DSN any other way would fail the upgrade and silently fall back to
        # create_schema() forever. Pin the variable for the duration instead.
        prev_env = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = sync_url
        try:
            from alembic import command
            cfg = _alembic_config(sync_url)
            command.upgrade(cfg, "head")
            log.info("alembic: schema at head (%.1fs)", time.monotonic() - started)
            return {"status": "ok", "elapsed_s": round(time.monotonic() - started, 2)}
        finally:
            if prev_env is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = prev_env
            # Best-effort unlock; the lock is session-scoped, so closing the
            # connection would release it anyway.
            try:
                lock_conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _LOCK_KEY})
            except Exception as exc:
                log.debug("alembic: advisory unlock failed (harmless): %s", exc)


def current_revision() -> str | None:
    """The revision stamped in `alembic_version`, or None (no Postgres / never
    stamped). Read-only — used by health reporting."""
    from warden.db.connection import DATABASE_URL
    if not DATABASE_URL:
        return None
    try:
        from sqlalchemy import text

        from warden.db.connection import get_engine
        with get_engine().connect() as conn:
            return conn.execute(
                text("SELECT version_num FROM alembic_version LIMIT 1")
            ).scalar()
    except Exception as exc:
        log.debug("alembic: current_revision unavailable: %s", exc)
        return None
