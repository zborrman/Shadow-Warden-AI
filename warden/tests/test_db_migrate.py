"""
warden/tests/test_db_migrate.py — D-1 schema-authority tests.

Two things are locked in here:

1. `warden/db/migrate.py` behaves safely without Postgres (the SQLite-only and
   test deployments must be untouched by making Alembic authoritative).
2. The migration tree stays **linear and idempotent**. Idempotency is not a
   style preference here — it is the property that made it safe to point
   `alembic upgrade head` at a production database that already had the tables
   but an empty `alembic_version`. A future revision that adds a bare
   `CREATE TABLE` would silently remove that guarantee, so it is asserted.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

_MIGRATIONS = Path(__file__).resolve().parent.parent / "db" / "migrations"
_VERSIONS = _MIGRATIONS / "versions"


def _revision_files() -> list[Path]:
    return sorted(p for p in _VERSIONS.glob("*.py") if p.name != "__init__.py")


# ── 1. Safe without Postgres ──────────────────────────────────────────────────

def test_upgrade_is_noop_without_database_url(monkeypatch):
    """Empty DATABASE_URL must short-circuit before touching SQLAlchemy."""
    from warden.db import migrate

    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "", raising=False)
    assert migrate.upgrade_to_head() == {"status": "skipped_no_database"}


def test_current_revision_is_none_without_database_url(monkeypatch):
    from warden.db import migrate

    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "", raising=False)
    assert migrate.current_revision() is None


def test_upgrade_pins_database_url_for_alembic_env(monkeypatch):
    """`migrations/env.py` reads os.environ["DATABASE_URL"] itself and raises when
    unset — it never looks at the Config we build. If `upgrade_to_head()` relied
    on the app and Alembic happening to read the same env var, a deployment that
    supplied the DSN any other way would fail every upgrade and fall back to
    `create_schema()` silently, forever. So the variable is pinned for the call
    and restored afterwards.

    Caught for real: an early version of this module passed the URL only through
    the Config, and the upgrade raised "DATABASE_URL environment variable is not
    set" whenever the env var was absent.
    """
    from warden.db import migrate

    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(
        "warden.db.connection.DATABASE_URL",
        "postgresql+asyncpg://u:p@localhost/db",
        raising=False,
    )

    seen: dict[str, str | None] = {}

    class _FakeConn:
        def execute(self, *_a, **_kw):
            class _R:
                @staticmethod
                def scalar():
                    return True          # advisory lock acquired
            return _R()
        def __enter__(self): return self
        def __exit__(self, *_): return False

    class _FakeEngine:
        @staticmethod
        def connect(): return _FakeConn()

    def _fake_upgrade(_cfg, _rev):
        seen["env"] = os.environ.get("DATABASE_URL")

    monkeypatch.setattr("warden.db.connection.get_engine", lambda: _FakeEngine())
    monkeypatch.setattr("alembic.command.upgrade", _fake_upgrade)

    assert migrate.upgrade_to_head()["status"] == "ok"
    # Alembic saw a psycopg2-style sync URL, not the asyncpg one, and not nothing.
    assert seen["env"] == "postgresql://u:p@localhost/db"
    # …and the process environment is left exactly as it was found.
    assert "DATABASE_URL" not in os.environ


def test_alembic_paths_resolve_independently_of_cwd():
    """script_location must not depend on the process working directory.

    `warden/alembic.ini` declares a repo-root-relative script_location; the
    container workdir is not guaranteed to be the repo root, so migrate.py
    resolves both paths from __file__.
    """
    from warden.db import migrate

    assert migrate._MIGRATIONS_DIR.is_absolute()
    assert (migrate._MIGRATIONS_DIR / "versions").is_dir()

    cfg = migrate._alembic_config("postgresql://u:p@localhost/db")
    loc = Path(cfg.get_main_option("script_location"))
    assert loc.is_absolute() and loc.is_dir()
    assert cfg.get_main_option("sqlalchemy.url") == "postgresql://u:p@localhost/db"


# ── 2. Migration tree integrity ───────────────────────────────────────────────

def test_revision_chain_is_linear_with_one_head():
    """A branched tree would make `upgrade head` ambiguous and fail at boot."""
    pytest.importorskip("alembic")
    from alembic.script import ScriptDirectory

    from warden.db import migrate

    script = ScriptDirectory(str(migrate._MIGRATIONS_DIR))
    heads = script.get_heads()
    assert len(heads) == 1, f"expected exactly one head, got {heads}"

    revs = list(script.walk_revisions())
    bases = [r.revision for r in revs if r.down_revision is None]
    assert len(bases) == 1, f"expected exactly one base revision, got {bases}"


# Bare CREATEs that would raise on a database where the object already exists.
_BARE_CREATE = re.compile(
    r"CREATE\s+(?:UNIQUE\s+)?(?:TABLE|INDEX|MATERIALIZED\s+VIEW|SCHEMA|EXTENSION)\s+"
    r"(?!IF\s+NOT\s+EXISTS)",
    re.IGNORECASE,
)

# TimescaleDB helpers that must be told not to error on re-run.
_TIMESCALE_CALL = re.compile(
    r"(create_hypertable|add_continuous_aggregate_policy|add_retention_policy|"
    r"add_compression_policy)\s*\((.*?)\)",
    re.IGNORECASE | re.DOTALL,
)


@pytest.mark.parametrize("path", _revision_files(), ids=lambda p: p.name)
def test_revision_ddl_is_idempotent(path: Path):
    """Every CREATE must be IF NOT EXISTS; every Timescale policy if_not_exists.

    This is what lets the tree run against the pre-existing production schema.
    """
    src = path.read_text(encoding="utf-8")

    # `upgrade()` only — a downgrade() legitimately uses bare DROP/CREATE.
    upgrade_src = src.split("def downgrade()")[0]

    bare = _BARE_CREATE.findall(upgrade_src)
    assert not bare, (
        f"{path.name}: {len(bare)} non-idempotent CREATE statement(s) in upgrade(). "
        "Migrations run against a live database that may already hold the object "
        "(alembic_version was empty until D-1) — use IF NOT EXISTS."
    )

    for fn, args in _TIMESCALE_CALL.findall(upgrade_src):
        assert "if_not_exists" in args.lower(), (
            f"{path.name}: {fn}(…) omits `if_not_exists => TRUE`, so re-running "
            "the migration would raise."
        )


_INIT_SQL = Path(__file__).resolve().parent.parent.parent / "data" / "init.sql"


def test_alembic_is_a_superset_of_init_sql():
    """`data/init.sql` runs only when Postgres initialises an empty data dir, so
    anything added to it later never reaches an existing deployment, and anything
    it creates is invisible to the migration tree. D-1b adopted its whole schema
    contribution into revision 0012; this keeps the two from drifting apart again.

    Add a table or column to init.sql without a matching migration and this fails
    — which is the point: the migration tree is the authority, init.sql is only a
    convenience for a brand-new container's first boot.
    """
    if not _INIT_SQL.exists():          # init.sql removed entirely — nothing to mirror
        pytest.skip("data/init.sql not present")

    init_src = _INIT_SQL.read_text(encoding="utf-8")
    tree = "\n".join(p.read_text(encoding="utf-8") for p in _revision_files())

    init_tables = set(
        re.findall(
            r"CREATE TABLE IF NOT EXISTS\s+([a-z_]+\.[a-z_]+)", init_src, re.IGNORECASE
        )
    )
    tree_tables = set(
        re.findall(
            r"CREATE TABLE IF NOT EXISTS\s+([a-z_]+\.[a-z_]+)", tree, re.IGNORECASE
        )
    )
    missing_tables = sorted(init_tables - tree_tables)
    assert not missing_tables, (
        f"init.sql creates {missing_tables} but no migration does. A deployment "
        "whose Postgres volume predates the addition will never get them."
    )

    init_cols = set(re.findall(r"ADD COLUMN IF NOT EXISTS\s+(\w+)", init_src, re.IGNORECASE))
    tree_cols = set(re.findall(r"ADD COLUMN IF NOT EXISTS\s+(\w+)", tree, re.IGNORECASE))
    missing_cols = sorted(init_cols - tree_cols)
    assert not missing_cols, (
        f"init.sql patches columns {missing_cols} that no migration adds. On a "
        "fresh volume init.sql's `ALTER TABLE IF EXISTS` is a no-op — the table "
        "is created later by the app — so those columns would exist nowhere."
    )


def test_portal_totp_columns_are_in_the_migration_tree():
    """Regression guard for the D-1b finding: `warden/portal_router.py` reads and
    writes `totp_secret`/`totp_enabled`, which existed in neither `create_schema()`
    nor any migration — only in an init.sql `ALTER` that cannot fire on a fresh
    volume. Portal MFA failed with "column does not exist" there."""
    tree = "\n".join(p.read_text(encoding="utf-8") for p in _revision_files())
    for col in ("totp_secret", "totp_enabled"):
        assert col in tree, f"{col} is used by portal_router.py but no migration adds it"


def test_alembic_tree_defines_the_tables_mounted_routers_query():
    """Guards the D-1 regression: /monitors and pgvector search are mounted and
    depend on tables that live *only* in the migration tree. If a revision that
    creates them is ever dropped, this fails instead of 500ing in production."""
    ddl = "\n".join(p.read_text(encoding="utf-8") for p in _revision_files())
    for table in (
        "warden_core.monitors",       # warden/api/monitor.py  (mounted at /monitors)
        "warden_core.probe_results",  # warden/workers/probe_worker.py
        "marketplace_embeddings",     # warden/marketplace/vector_search.py
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in ddl, (
            f"{table} is queried by shipped code but no migration creates it."
        )
