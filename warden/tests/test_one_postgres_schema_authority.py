"""
warden/tests/test_one_postgres_schema_authority.py — one Postgres schema source.

The tree carried three partially-overlapping definitions of `warden_core`:
`data/init.sql`, `connection.py::create_schema()`, and the Alembic tree. That is
how it ended up with objects nobody created — `warden_core.monitors` and
`marketplace_embeddings` existed only in migrations that nothing ran, and the
`portal_users` TOTP columns only in an `ALTER TABLE IF EXISTS` that cannot fire
on a fresh volume, because the table does not exist yet at Postgres-init time.

Alembic is now the only authority. These guard the property rather than the
cleanup: a second source can come back the same way the first two did, one
convenient `CREATE TABLE` at a time.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_WARDEN = Path(__file__).resolve().parent.parent
_MIGRATIONS = _WARDEN / "db" / "migrations" / "versions"

# `warden_core.x` / `warden_analytics.x` — the schemas Alembic owns. A module DB
# is SQLite and unqualified, so this cannot catch those by accident.
_PG_CREATE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(warden_core|warden_analytics)\.",
    re.IGNORECASE,
)


def _python_sources():
    for py in sorted(_WARDEN.rglob("*.py")):
        rel = py.relative_to(_WARDEN)
        if rel.parts[0] in ("tests", "db"):
            continue          # db/ holds the migrations themselves
        try:
            yield rel, py.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue


def test_no_module_creates_a_warden_core_table():
    """Application code must not define Postgres tables.

    `data/init.sql` is exempt: it runs only when Postgres initialises an empty
    data directory, and revision 0012 adopted its whole contribution, which
    `test_alembic_is_a_superset_of_init_sql` keeps in step.
    """
    offenders = [
        f"{rel}" for rel, src in _python_sources() if _PG_CREATE.search(src)
    ]
    assert not offenders, (
        "Postgres tables are defined outside the Alembic tree: "
        f"{sorted(offenders)}. Add a revision under warden/db/migrations "
        "instead — a second schema source is how monitors, probe_results and "
        "the portal TOTP columns came to exist in no deployment."
    )


def test_create_schema_no_longer_applies_ddl():
    """The old hand-maintained list is a raising stub, not a working path.

    Left callable on purpose: an out-of-tree caller gets an instruction instead
    of an AttributeError.
    """
    from warden.db.connection import create_schema

    with pytest.raises(RuntimeError, match="upgrade_to_head"):
        create_schema()


def test_the_migration_tree_still_owns_the_tables_it_must():
    ddl = "\n".join(
        p.read_text(encoding="utf-8")
        for p in sorted(_MIGRATIONS.glob("*.py"))
        if p.name != "__init__.py"
    )
    for table in ("warden_core.monitors", "warden_core.probe_results",
                  "warden_core.portal_users", "marketplace_embeddings"):
        assert table in ddl, f"{table} is no longer defined by any migration"
    for column in ("totp_secret", "totp_enabled"):
        assert column in ddl, f"{column} is used by portal_router but no migration adds it"
