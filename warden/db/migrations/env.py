"""
warden/db/migrations/env.py
────────────────────────────
Alembic environment for Shadow Warden AI.

Supports both online (live DB) and offline (SQL script) modes.
DATABASE_URL is read from the environment — same as the application.
"""
from __future__ import annotations

import logging
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

# Alembic Config object
config = context.config

# ── Logging: do NOT clobber the application's configuration (OB-F19) ─────────
# `fileConfig()` tears down the root logger and rebuilds it from alembic.ini.
# That is correct for the standalone `alembic` CLI and destructive inside the
# gateway, which runs `alembic upgrade head` during startup: alembic.ini sets
# `[logger_root] level = WARN` and a plain
# `%(levelname)-5.5s [%(name)s] %(message)s` formatter, so from the moment
# migrations run the process
#
#   * drops every INFO and DEBUG line for the rest of its life, and
#   * stops emitting JSON, which is the format promtail's pipeline parses.
#
# The whole OB-9 correlation chain sat downstream of this: `_JsonFormatter` was
# installed at import, replaced a few seconds later, and every structured field
# after that point went nowhere. Verified on a running gateway 2026-08-23 — the
# last JSON line in the log is an alembic startup line.
#
# So configure logging only when nothing else already has. Under the CLI the
# root logger is bare and alembic.ini applies as before; under the gateway
# `_configure_json_logging()` has already installed its handler, and we leave it
# alone. `disable_existing_loggers=False` is belt-and-braces for the CLI path so
# loggers created before this point keep working.
if config.config_file_name is not None and not logging.getLogger().handlers:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

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
