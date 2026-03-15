"""
warden/db/connection.py
━━━━━━━━━━━━━━━━━━━━━━
Database connection factory.  Supports PostgreSQL (via psycopg2) and
SQLite (via stdlib sqlite3).  The active backend is selected by DATABASE_URL.

Usage::

    from warden.db.connection import get_engine, is_postgres

    if is_postgres():
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    else:
        # fall through to sqlite3 path
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Any

log = logging.getLogger("warden.db.connection")

DATABASE_URL = os.getenv("DATABASE_URL", "")


def is_postgres() -> bool:
    """True when DATABASE_URL points to a PostgreSQL instance."""
    return DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://")


@lru_cache(maxsize=1)
def get_engine() -> Any:
    """
    Return a SQLAlchemy Engine for the configured database.
    Cached after first call.  Raises ImportError if sqlalchemy not installed.
    """
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. "
            "Set DATABASE_URL=postgresql://... to use PostgreSQL."
        )

    try:
        from sqlalchemy import create_engine
    except ImportError as exc:
        raise ImportError(
            "sqlalchemy not installed. Run: pip install sqlalchemy psycopg2-binary"
        ) from exc

    connect_args: dict[str, Any] = {}
    if is_postgres():
        connect_args["connect_timeout"] = 10

    engine = create_engine(
        DATABASE_URL,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,    # validates connections before use
        connect_args=connect_args,
    )
    log.info("Database engine created: %s", DATABASE_URL.split("@")[-1])  # hide creds
    return engine


def get_connection():
    """Context manager — yields a SQLAlchemy Connection."""
    engine = get_engine()
    from sqlalchemy import text as sa_text  # noqa: F401
    return engine.connect()


def create_schema() -> None:
    """
    Create all Warden tables in the configured PostgreSQL database.
    Safe to call multiple times (IF NOT EXISTS).
    Run once on first deploy:  python -m warden.db.connection
    """
    engine = get_engine()
    from sqlalchemy import text

    ddl = """
    CREATE TABLE IF NOT EXISTS threat_intel_items (
        id                  TEXT PRIMARY KEY,
        source              TEXT NOT NULL,
        title               TEXT NOT NULL,
        url                 TEXT NOT NULL,
        source_url_hash     TEXT UNIQUE NOT NULL,
        published_at        TEXT,
        raw_description     TEXT,
        relevance_score     REAL,
        owasp_category      TEXT,
        attack_pattern      TEXT,
        detection_hint      TEXT,
        countermeasure      TEXT,
        status              TEXT NOT NULL DEFAULT 'new',
        rules_generated     INTEGER NOT NULL DEFAULT 0,
        created_at          TEXT NOT NULL,
        analyzed_at         TEXT
    );

    CREATE TABLE IF NOT EXISTS threat_intel_countermeasures (
        id              SERIAL PRIMARY KEY,
        threat_item_id  TEXT NOT NULL REFERENCES threat_intel_items(id),
        rule_id         TEXT NOT NULL,
        rule_type       TEXT NOT NULL,
        rule_value      TEXT NOT NULL,
        created_at      TEXT NOT NULL DEFAULT NOW()::TEXT
    );

    CREATE TABLE IF NOT EXISTS rule_ledger (
        rule_id         TEXT PRIMARY KEY,
        source          TEXT NOT NULL,
        created_at      TEXT NOT NULL,
        pattern_snippet TEXT,
        rule_type       TEXT,
        status          TEXT NOT NULL DEFAULT 'active'
    );

    CREATE INDEX IF NOT EXISTS idx_threat_intel_status ON threat_intel_items(status);
    CREATE INDEX IF NOT EXISTS idx_threat_intel_source ON threat_intel_items(source);
    CREATE INDEX IF NOT EXISTS idx_rule_ledger_source  ON rule_ledger(source)
    """

    with engine.begin() as conn:
        for stmt in ddl.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
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
