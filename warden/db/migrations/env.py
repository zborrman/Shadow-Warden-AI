"""
warden/db/migrations/env.py
────────────────────────────
Alembic environment for Shadow Warden AI.

Supports both online (live DB) and offline (SQL script) modes.
DATABASE_URL is read from the environment — same as the application.
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

# Alembic Config object
config = context.config

# Set up logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Read DATABASE_URL from environment (convert asyncpg → psycopg2 for sync migrations)
_url = os.environ.get("DATABASE_URL", "")
if _url.startswith("postgresql+asyncpg://"):
    _url = _url.replace("postgresql+asyncpg://", "postgresql://", 1)
if not _url:
    raise RuntimeError("DATABASE_URL environment variable is not set.")

config.set_main_option("sqlalchemy.url", _url)

# Target metadata — None means migrations are written as raw SQL
target_metadata = None


def run_migrations_offline() -> None:
    """Generate SQL script without connecting to the database."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        # Ensure warden_core schema exists before any migration runs
        connection.execute(text("CREATE SCHEMA IF NOT EXISTS warden_core"))
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
