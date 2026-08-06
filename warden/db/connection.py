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
from functools import lru_cache
from typing import Any

from warden.config import settings

log = logging.getLogger("warden.db.connection")

DATABASE_URL: str = settings.database_url

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


# ── Async session factory (FastAPI dependency injection) ──────────────────────

def _make_session_factory():
    """Build AsyncSessionLocal lazily so import doesn't fail when DATABASE_URL is unset."""
    try:
        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy.orm import sessionmaker
        return sessionmaker(
            get_async_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    except Exception:
        return None

_AsyncSessionLocal = None


async def get_db():
    """
    FastAPI dependency — yields an AsyncSession per request.

    Usage::

        @app.get("/example")
        async def handler(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(MyModel))
    """
    global _AsyncSessionLocal
    if _AsyncSessionLocal is None:
        _AsyncSessionLocal = _make_session_factory()
    if _AsyncSessionLocal is None:
        raise RuntimeError("DATABASE_URL not configured for async sessions.")
    async with _AsyncSessionLocal() as session:
        yield session


def create_schema() -> None:
    """Removed — Alembic is the only Postgres schema authority (D-1).

    This used to hold 13 tables of hand-maintained `CREATE TABLE IF NOT EXISTS`,
    a second source of truth alongside `warden/db/migrations` and the Postgres
    half of `data/init.sql`. Three partially-overlapping definitions is how the
    tree ended up with objects nobody created: `warden_core.monitors` and
    `marketplace_embeddings` lived only in migrations that nothing ran, and the
    `portal_users` TOTP columns lived only in an `ALTER` that could not fire.

    Kept as a raising stub rather than deleted outright so an out-of-tree caller
    gets a clear instruction instead of an AttributeError.
    """
    raise RuntimeError(
        "create_schema() is gone; the Postgres schema is applied by "
        "warden.db.migrate.upgrade_to_head() (alembic upgrade head)."
    )

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if not DATABASE_URL:
        print("ERROR: DATABASE_URL not set.")
        sys.exit(1)
    from warden.db.migrate import upgrade_to_head
    print("Schema:", upgrade_to_head().get("status"))
