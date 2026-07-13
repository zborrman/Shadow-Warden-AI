"""
Phase 6 — central DDL registry (warden/db/ddl_registry.py).

Covers:
  - register/registered introspection
  - DDL applied on first ensure_schema, skipped thereafter (DDL-once)
  - persistence across connections (tracking table, not just the in-process memo)
  - schema drift (changed DDL checksum) → re-applied
  - unknown db_key is a no-op
  - fail-safe: a broken tracking table still applies the DDL
  - staff cluster registers its schema and creates its tables
"""
from __future__ import annotations

import sqlite3

import pytest

from warden.db import ddl_registry as reg

_DDL_A = """
CREATE TABLE IF NOT EXISTS thing_a (id INTEGER PRIMARY KEY, v TEXT);
CREATE INDEX IF NOT EXISTS idx_thing_a ON thing_a(v);
"""
_DDL_A_V2 = """
CREATE TABLE IF NOT EXISTS thing_a (id INTEGER PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS thing_a2 (id INTEGER PRIMARY KEY);
"""


@pytest.fixture(autouse=True)
def _clean():
    """
    Isolate only this file's synthetic db_key. Never clear the whole registry:
    real modules register at import time, and wiping them would silently strip a
    module's DDL for every later test in the session.
    """
    reg._REGISTRY.pop("db1", None)
    reg.reset_memo()
    yield
    reg._REGISTRY.pop("db1", None)
    reg.reset_memo()


def _tables(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


class TestRegister:
    def test_register_and_introspect(self):
        reg.register("db1", "mod_a", _DDL_A)
        snap = reg.registered("db1")
        assert "mod_a" in snap["db1"]

    def test_checksum_is_whitespace_insensitive(self):
        assert reg.checksum("CREATE  TABLE x;") == reg.checksum("CREATE TABLE x;")

    def test_checksum_changes_with_content(self):
        assert reg.checksum(_DDL_A) != reg.checksum(_DDL_A_V2)


class TestEnsureSchema:
    def test_applies_ddl_and_creates_tables(self, tmp_path):
        reg.register("db1", "mod_a", _DDL_A)
        db = tmp_path / "t.db"
        con = sqlite3.connect(db)
        n = reg.ensure_schema(con, "db1", str(db))
        assert n == 1
        assert "thing_a" in _tables(con)
        con.close()

    def test_second_call_is_noop_ddl_once(self, tmp_path):
        reg.register("db1", "mod_a", _DDL_A)
        db = tmp_path / "t.db"
        con = sqlite3.connect(db)
        assert reg.ensure_schema(con, "db1", str(db)) == 1
        assert reg.ensure_schema(con, "db1", str(db)) == 0   # memoized
        con.close()

    def test_persists_across_processes(self, tmp_path):
        """A fresh process (memo cleared) must not re-run DDL — tracking table wins."""
        reg.register("db1", "mod_a", _DDL_A)
        db = tmp_path / "t.db"
        con = sqlite3.connect(db)
        reg.ensure_schema(con, "db1", str(db))
        con.commit()
        con.close()

        reg.reset_memo()                       # simulate a new process
        con2 = sqlite3.connect(db)
        assert reg.ensure_schema(con2, "db1", str(db)) == 0
        con2.close()

    def test_drift_reapplies(self, tmp_path):
        reg.register("db1", "mod_a", _DDL_A)
        db = tmp_path / "t.db"
        con = sqlite3.connect(db)
        reg.ensure_schema(con, "db1", str(db))
        con.commit()
        con.close()

        # Module ships new DDL → checksum changes → re-applied.
        reg.register("db1", "mod_a", _DDL_A_V2)
        reg.reset_memo()
        con2 = sqlite3.connect(db)
        assert reg.ensure_schema(con2, "db1", str(db)) == 1
        assert "thing_a2" in _tables(con2)
        con2.close()

    def test_unknown_db_key_is_noop(self, tmp_path):
        db = tmp_path / "t.db"
        con = sqlite3.connect(db)
        assert reg.ensure_schema(con, "nope", str(db)) == 0
        con.close()

    def test_separate_paths_tracked_independently(self, tmp_path):
        reg.register("db1", "mod_a", _DDL_A)
        a, b = tmp_path / "a.db", tmp_path / "b.db"
        ca, cb = sqlite3.connect(a), sqlite3.connect(b)
        assert reg.ensure_schema(ca, "db1", str(a)) == 1
        assert reg.ensure_schema(cb, "db1", str(b)) == 1   # different file → applied again
        ca.close()
        cb.close()


class TestFailSafe:
    def test_broken_tracking_still_applies_ddl(self, tmp_path):
        """If the tracking table can't be used, DDL must still run (never lose tables)."""
        reg.register("db1", "mod_a", _DDL_A)
        db = tmp_path / "t.db"
        con = sqlite3.connect(db)
        # Occupy the tracking table name with an incompatible schema.
        con.execute("CREATE TABLE _warden_ddl_applied (bogus INTEGER)")
        con.commit()
        reg.ensure_schema(con, "db1", str(db))
        assert "thing_a" in _tables(con)      # DDL applied despite tracking failure
        con.close()


class TestStaffCluster:
    def test_staff_modules_register_and_create_tables(self, tmp_path):
        # Plain imports — register() runs at import time. Never importlib.reload a
        # product module here: it rebinds its classes, so other test modules holding
        # the old class object start failing isinstance checks session-wide.
        import warden.staff.a2a as a2a
        import warden.staff.economics  # noqa: F401  (import → register side-effect)

        assert "staff_a2a" in reg.registered()
        assert "staff_economics" in reg.registered()

        db = tmp_path / "a2a.db"
        with a2a._conn(str(db)) as con:
            assert "staff_a2a_calls" in _tables(con)
            # Economics tables must NOT leak into the a2a file (per-DB keys).
            assert "staff_action_costs" not in _tables(con)
