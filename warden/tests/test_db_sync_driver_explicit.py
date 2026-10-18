"""
warden/tests/test_db_sync_driver_explicit.py

SQLAlchemy 2.1 changed what a bare ``postgresql://`` URL means: psycopg 3 instead
of psycopg2. The image installs only psycopg2, so the dependency batch in #615
made every sync engine fail with ``No module named 'psycopg'`` — Alembic at boot
and the filter-events mirror. Both fail open, so the gateway kept serving and
the only symptom was rows that were never written.

These assert the driver our URLs resolve to, through SQLAlchemy itself, so they
hold whatever the library's default becomes next.
"""
from __future__ import annotations

import pytest
from sqlalchemy.engine import make_url

from warden.db.connection import _sync_url


@pytest.mark.parametrize("url", [
    "postgresql+asyncpg://u:p@postgres:5432/warden",
    "postgresql://u:p@postgres:5432/warden",
    "postgres://u:p@postgres:5432/warden",
    "postgresql+psycopg2://u:p@postgres:5432/warden",
])
def test_sync_url_resolves_to_psycopg2(url: str) -> None:
    out = _sync_url(url)
    assert make_url(out).get_dialect().driver == "psycopg2", out
    assert out.endswith("u:p@postgres:5432/warden")


def test_non_postgres_urls_are_untouched() -> None:
    assert _sync_url("sqlite:///tmp/x.db") == "sqlite:///tmp/x.db"


def test_alembic_env_names_the_driver() -> None:
    """env.py builds its own URL; it must not fall back to the library default."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "db" / "migrations" / "env.py").read_text(
        encoding="utf-8"
    )
    assert '"postgresql+psycopg2://"' in src
    assert 'replace("postgresql+asyncpg://", "postgresql://"' not in src
