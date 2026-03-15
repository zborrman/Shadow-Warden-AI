"""
warden/db/connection.py
━━━━━━━━━━━━━━━━━━━━━━
Database connection factory.  Supports PostgreSQL (asyncpg + psycopg2) and
SQLite (via stdlib sqlite3).  The active backend is selected by DATABASE_URL.

  DATABASE_URL=postgresql+asyncpg://warden_user:secret@postgres:5432/warden
      → async SQLAlchemy engine (FastAPI / async code)

  DATABASE_URL=postgresql://warden_user:secret@postgres:5432/warden
      → sync SQLAlchemy engine (scripts, migrations)

  DATABASE_URL=   (empty)
      → SQLite fallback (local dev, air-gapped)

Usage::

    # Async (FastAPI)
    from warden.db.connection import get_async_engine, is_postgres

    async with get_async_engine().begin() as conn:
        await conn.execute(text("SELECT 1"))

    # Sync (scripts / migrations)
    from warden.db.connection import get_engine
    with get_engine().begin() as conn:
        conn.execute(text("SELECT 1"))
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Any

log = logging.getLogger("warden.db.connection")

DATABASE_URL: str = os.getenv("DATABASE_URL", "")

# Async URL uses asyncpg; sync URL uses psycopg2.
# We derive the sync URL automatically from the async one.
_ASYNC_DRIVERS = ("postgresql+asyncpg://", "postgresql+asyncpg+")
_SYNC_DRIVERS  = ("postgresql://", "postgresql+psycopg2://", "postgres://")


def is_postgres() -> bool:
    """True when DATABASE_URL points to a PostgreSQL instance."""
    return any(DATABASE_URL.startswith(p) for p in (*_ASYNC_DRIVERS, *_SYNC_DRIVERS))


def _sync_url(url: str) -> str:
    """Convert an asyncpg URL to a psycopg2 URL for sync operations."""
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


def _async_url(url: str) -> str:
    """Ensure the URL uses the asyncpg driver."""
    if url.startswith("postgresql://") or url.startswith("postgres://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1).replace(
            "postgres://", "postgresql+asyncpg://", 1
        )
    return url


@lru_cache(maxsize=1)
def get_engine() -> Any:
    """
    Return a synchronous SQLAlchemy Engine (psycopg2).
    Used for migrations, scripts, and any non-async context.
    Raises RuntimeError when DATABASE_URL is empty.
    """
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. "
            "Set DATABASE_URL=postgresql+asyncpg://warden_user:pass@postgres:5432/warden"
        )

    try:
        from sqlalchemy import create_engine
    except ImportError as exc:
        raise ImportError(
            "sqlalchemy not installed. Run: pip install sqlalchemy psycopg2-binary"
        ) from exc

    sync_url = _sync_url(DATABASE_URL)
    engine = create_engine(
        sync_url,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        connect_args={"connect_timeout": 10} if is_postgres() else {},
    )
    log.info("Sync DB engine: %s", DATABASE_URL.split("@")[-1])
    return engine


@lru_cache(maxsize=1)
def get_async_engine() -> Any:
    """
    Return an asynchronous SQLAlchemy AsyncEngine (asyncpg).
    Used in FastAPI lifespan and async request handlers.
    Raises RuntimeError when DATABASE_URL is empty.
    """
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set.")

    try:
        from sqlalchemy.ext.asyncio import create_async_engine
    except ImportError as exc:
        raise ImportError(
            "sqlalchemy[asyncio] not installed. "
            "Run: pip install sqlalchemy[asyncio] asyncpg"
        ) from exc

    async_url = _async_url(DATABASE_URL)
    engine = create_async_engine(
        async_url,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
    )
    log.info("Async DB engine: %s", DATABASE_URL.split("@")[-1])
    return engine


def get_connection():
    """Sync context manager — yields a SQLAlchemy Connection (psycopg2)."""
    return get_engine().connect()


def create_schema() -> None:
    """
    Create all Warden tables via the sync engine.
    Safe to call multiple times (IF NOT EXISTS on every statement).
    Typically called once on first deploy, or as part of a migration step.

    Run::

        DATABASE_URL=postgresql+asyncpg://... python -m warden.db.connection
    """
    engine = get_engine()
    from sqlalchemy import text

    # Tables are created in warden_core schema (init.sql already creates schemas).
    # This DDL is idempotent — safe to re-run.
    ddl_stmts = [
        """
        CREATE TABLE IF NOT EXISTS warden_core.threat_intel_items (
            id                  TEXT        PRIMARY KEY,
            source              TEXT        NOT NULL,
            title               TEXT        NOT NULL,
            url                 TEXT        NOT NULL,
            source_url_hash     TEXT        UNIQUE NOT NULL,
            published_at        TEXT,
            raw_description     TEXT,
            relevance_score     NUMERIC(4,3),
            owasp_category      TEXT,
            attack_pattern      TEXT,
            detection_hint      TEXT,
            countermeasure      TEXT,
            status              TEXT        NOT NULL DEFAULT 'new',
            rules_generated     INTEGER     NOT NULL DEFAULT 0,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            analyzed_at         TIMESTAMPTZ
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS warden_core.threat_intel_countermeasures (
            id              BIGSERIAL   PRIMARY KEY,
            threat_item_id  TEXT        NOT NULL
                            REFERENCES warden_core.threat_intel_items(id),
            rule_id         TEXT        NOT NULL,
            rule_type       TEXT        NOT NULL,
            rule_value      TEXT        NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS warden_core.rule_ledger (
            rule_id         TEXT        PRIMARY KEY,
            source          TEXT        NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            pattern_snippet TEXT,
            rule_type       TEXT,
            status          TEXT        NOT NULL DEFAULT 'active'
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS warden_core.billing_usage (
            id          BIGSERIAL     PRIMARY KEY,
            tenant_id   TEXT          NOT NULL,
            period      TEXT          NOT NULL,
            requests    INTEGER       NOT NULL DEFAULT 0,
            tokens_in   BIGINT        NOT NULL DEFAULT 0,
            tokens_out  BIGINT        NOT NULL DEFAULT 0,
            cost_usd    NUMERIC(10,6) NOT NULL DEFAULT 0,
            updated_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
            UNIQUE (tenant_id, period)
        )
        """,
        "CREATE INDEX IF NOT EXISTS threat_intel_status_idx ON warden_core.threat_intel_items(status)",
        "CREATE INDEX IF NOT EXISTS threat_intel_source_idx ON warden_core.threat_intel_items(source)",
        "CREATE INDEX IF NOT EXISTS rule_ledger_source_idx  ON warden_core.rule_ledger(source)",
        "CREATE INDEX IF NOT EXISTS billing_tenant_idx      ON warden_core.billing_usage(tenant_id)",
    ]

    with engine.begin() as conn:
        for stmt in ddl_stmts:
            conn.execute(text(stmt))

    log.info("Database schema created/verified.")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if not DATABASE_URL:
        print("ERROR: DATABASE_URL not set.")
        sys.exit(1)
    create_schema()
    print("Schema ready.")
