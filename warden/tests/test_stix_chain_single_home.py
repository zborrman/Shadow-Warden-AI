"""
warden/tests/test_stix_chain_single_home.py

D-6 / Phase 2 was deferred (see `docs/database-architecture.md` §8.2): the SEP
cluster has no production data, so migrating it now would move seven rows and
build schema for a subsystem with no users.

`sep_stix_chain` is the one piece that does **not** get cheaper to defer.
Everything else in that cluster is cheap to move later precisely because row
count is what makes a migration expensive. This table is a `prev_hash`-linked
chain and `verify_chain()` re-hashes each bundle from canonical JSON, so moving
it once it holds entries is an *audit* problem rather than a volume one — the
cost does not scale with rows, it appears the moment the first entry exists.

So the state to prevent is not "still on SQLite". It is **two homes at once**:
a chain that is half in one engine and half in another cannot be verified end
to end, and a partially-migrated tamper-evident log is worse than either whole
version of it. Whoever writes the first production entry picks the engine
permanently; this test makes sure that choice is made once, deliberately.
"""
from __future__ import annotations

import re
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1]
_TABLE = "sep_stix_chain"

_SQLITE_DDL = re.compile(
    rf"CREATE TABLE (?:IF NOT EXISTS )?[\"']?{_TABLE}\b", re.I
)
#: Alembic revisions and the Postgres bootstrap are the other possible home.
_PG_DDL = re.compile(
    rf"(?:create_table\(\s*[\"']{_TABLE}[\"']"
    rf"|CREATE TABLE (?:IF NOT EXISTS )?(?:\w+\.)?{_TABLE}\b)",
    re.I,
)


def _sqlite_homes() -> list[str]:
    out = []
    for path in _SRC.rglob("*.py"):
        parts = path.relative_to(_SRC).parts
        if "tests" in parts or "migrations" in parts:
            continue
        if _SQLITE_DDL.search(path.read_text(encoding="utf-8", errors="replace")):
            out.append(path.relative_to(_SRC.parent).as_posix())
    return sorted(out)


def _postgres_homes() -> list[str]:
    out = []
    candidates = list((_SRC / "db" / "migrations").rglob("*.py"))
    candidates += list((_SRC.parent / "data").glob("*.sql"))
    for path in candidates:
        if _PG_DDL.search(path.read_text(encoding="utf-8", errors="replace")):
            out.append(path.relative_to(_SRC.parent).as_posix())
    return sorted(out)


def test_the_chain_has_exactly_one_home():
    sqlite_homes = _sqlite_homes()
    pg_homes = _postgres_homes()

    assert not (sqlite_homes and pg_homes), (
        f"`{_TABLE}` is declared in both engines — SQLite {sqlite_homes} and "
        f"Postgres {pg_homes}. A prev_hash-linked chain split across two stores "
        "cannot be verified end to end, and `verify_chain()` re-hashes from "
        "canonical JSON, so the halves will not agree. Finish the move in one "
        "step and delete the old declaration, or do not start it."
    )
    assert sqlite_homes or pg_homes, (
        f"`{_TABLE}` is declared nowhere. It backs the tamper-evident transfer "
        "audit trail (communities/stix_audit.py); losing its DDL silently "
        "disables the audit chain."
    )


def test_it_is_currently_sqlite_and_that_is_the_recorded_decision():
    """Pins today's answer so a move is a deliberate edit, not a drift.

    Not an argument that SQLite is right — Phase 2 is deferred, not settled.
    It means the engine cannot change without this test changing with it.
    """
    assert _sqlite_homes() == ["warden/communities/stix_audit.py"], _sqlite_homes()
    assert _postgres_homes() == [], _postgres_homes()


def test_the_detector_would_see_a_postgres_home():
    """A guard that cannot fail is not a guard."""
    assert _PG_DDL.search('op.create_table("sep_stix_chain",')
    assert _PG_DDL.search("CREATE TABLE IF NOT EXISTS warden_core.sep_stix_chain (")
    assert not _PG_DDL.search("SELECT * FROM sep_stix_chain")
