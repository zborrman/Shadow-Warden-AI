"""
warden/db
━━━━━━━━
PostgreSQL / SQLite abstraction layer.

Set DATABASE_URL to switch storage backends:
  DATABASE_URL=postgresql://user:pass@host:5432/warden  -> PostgreSQL
  DATABASE_URL=                                          -> SQLite (default)

PostgreSQL is recommended for production deployments.  SQLite remains the
default for local development and air-gapped deployments.
"""
from warden.db.connection import get_connection, get_engine  # noqa: F401
