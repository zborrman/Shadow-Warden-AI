"""
warden/tests/test_db_connection_reuse.py — per-thread connection reuse in open_db.

Measured through this seam, `sqlite3.connect` + the six pragmas + ensure_schema's
tracking check cost ~150x more than the write itself (188 write-txn/s opening per
call vs 28 871/s reused). The SQLite write lock was never the ceiling; this setup
was.

Reuse touches every database write in the product, so what is pinned here is the
safety envelope, not the speed:

  * a **nested** `open_db` for the same database gets its own connection, so an
    inner failure can never roll back — or commit — the transaction an outer
    frame is holding. `_do_purchase` writes a purchase and its escrow in one
    transaction while calling into other modules, so this is load-bearing.
  * a failed block **discards** the connection instead of handing a poisoned one
    to the next caller.
  * caches are **per thread** — a connection is never shared across threads,
    where two callers would interleave their transactions.
  * `WARDEN_DB_CONN_REUSE=false` restores the previous behaviour exactly.
"""
from __future__ import annotations

import sqlite3
import threading

import pytest

from warden.db import connect as connect_mod
from warden.db.connect import close_cached_connections, open_db


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "reuse.db")
    monkeypatch.setenv("WARDEN_DB_CONN_REUSE", "true")
    close_cached_connections()
    with open_db("reusetest", path, module_default_path=path) as con:
        con.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT)")
    yield path
    close_cached_connections()


def _conns(path: str, n: int = 3, **kw) -> list:
    """Collect the connection objects themselves.

    Not `id()`: CPython recycles addresses once a closed connection is freed, so
    a fresh-per-call path can hand back the same id and look like reuse.
    Holding the objects keeps every identity distinct.
    """
    seen = []
    for _ in range(n):
        with open_db("reusetest", path, module_default_path=path, **kw) as con:
            seen.append(con)
    return seen


def _distinct(objs) -> int:
    return len({id(o) for o in objs})


# ── It actually reuses ────────────────────────────────────────────────────────

def test_sequential_calls_share_one_connection(db):
    assert _distinct(_conns(db)) == 1


def test_kill_switch_restores_a_fresh_connection_per_call(db, monkeypatch):
    monkeypatch.setenv("WARDEN_DB_CONN_REUSE", "false")
    close_cached_connections()
    assert _distinct(_conns(db)) == 3


def test_non_default_parameters_are_never_cached(db):
    """Only the default combination is reusable; anything else opens its own."""
    assert _distinct(_conns(db, row_factory=False)) == 3


# ── The load-bearing safety property ──────────────────────────────────────────

def test_nested_open_gets_a_separate_connection(db):
    with (
        open_db("reusetest", db, module_default_path=db) as outer,
        open_db("reusetest", db, module_default_path=db) as inner,
    ):
        assert inner is not outer, (
            "a nested block reused the outer connection — its exit would "
            "commit the outer transaction mid-flight"
        )


def test_inner_failure_leaves_the_outer_block_usable(db):
    """A failed inner block must not take the enclosing one down with it.

    Note what is *not* tested here: an outer block that has already written and
    then nests another write on the same file deadlocks on its own write lock —
    SQLite is single-writer per file, and that is true with or without reuse.
    It is why `_do_purchase` passes its connection down (`con=con`) instead of
    nesting blocks. Reuse deliberately does not change that: a nested caller
    still gets its own connection.
    """
    with open_db("reusetest", db, module_default_path=db) as outer:
        with pytest.raises(RuntimeError), open_db(
            "reusetest", db, module_default_path=db
        ) as inner:
            inner.execute("INSERT INTO t (v) VALUES ('inner')")
            raise RuntimeError("inner blew up")
        # The enclosing connection is still healthy and can commit its own work.
        outer.execute("INSERT INTO t (v) VALUES ('outer')")

    with open_db("reusetest", db, module_default_path=db) as con:
        rows = {r[0] for r in con.execute("SELECT v FROM t").fetchall()}
    assert "outer" in rows, "the outer block could not commit after an inner failure"
    assert "inner" not in rows, "a failed inner block committed anyway"


def test_failed_block_discards_the_connection(db):
    with open_db("reusetest", db, module_default_path=db) as first:
        poisoned = first                      # held, so its id cannot be recycled

    with pytest.raises(ValueError), open_db("reusetest", db, module_default_path=db) as con:
        assert con is poisoned
        raise ValueError("boom")

    with open_db("reusetest", db, module_default_path=db) as after:
        assert after is not poisoned, "a connection from a failed block was reused"


def test_failed_block_rolls_back_its_writes(db):
    with pytest.raises(ValueError), open_db("reusetest", db, module_default_path=db) as con:
        con.execute("INSERT INTO t (v) VALUES ('doomed')")
        raise ValueError("boom")

    with open_db("reusetest", db, module_default_path=db) as con:
        assert con.execute("SELECT COUNT(*) FROM t WHERE v='doomed'").fetchone()[0] == 0


# ── Commit semantics are unchanged ────────────────────────────────────────────

def test_writes_are_committed_and_visible_to_a_fresh_connection(db):
    for i in range(50):
        with open_db("reusetest", db, module_default_path=db) as con:
            con.execute("INSERT INTO t (v) VALUES (?)", (str(i),))

    # A connection this cache has never handed out must see every row.
    fresh = sqlite3.connect(db)
    try:
        assert fresh.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 50
    finally:
        fresh.close()


# ── Isolation between threads ─────────────────────────────────────────────────

def test_threads_never_share_a_connection(db):
    seen: dict[int, int] = {}
    barrier = threading.Barrier(2)

    def work():
        barrier.wait()
        with open_db("reusetest", db, module_default_path=db) as con:
            seen[threading.get_ident()] = id(con)
        close_cached_connections()

    threads = [threading.Thread(target=work) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(seen) == 2
    assert len(set(seen.values())) == 2, "two threads shared one connection"


def test_concurrent_writers_all_commit(db):
    """The lock still serialises writers; nothing is lost."""
    def work(tag: str):
        for i in range(20):
            with open_db("reusetest", db, module_default_path=db) as con:
                con.execute("INSERT INTO t (v) VALUES (?)", (f"{tag}-{i}",))
        close_cached_connections()

    threads = [threading.Thread(target=work, args=(f"w{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with open_db("reusetest", db, module_default_path=db) as con:
        assert con.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 80


# ── Resource bounds ───────────────────────────────────────────────────────────

def test_cache_is_bounded(tmp_path, monkeypatch):
    """A long-lived worker thread must not accumulate descriptors without limit."""
    monkeypatch.setenv("WARDEN_DB_CONN_REUSE", "true")
    close_cached_connections()
    try:
        for i in range(connect_mod._MAX_CACHED_PER_THREAD + 10):
            path = str(tmp_path / f"db{i}.db")
            with open_db(f"k{i}", path, module_default_path=path) as con:
                con.execute("CREATE TABLE IF NOT EXISTS x (a INTEGER)")
        assert len(connect_mod._cache()) <= connect_mod._MAX_CACHED_PER_THREAD
    finally:
        close_cached_connections()


def test_close_cached_connections_is_safe_to_call_twice(db):
    close_cached_connections()
    close_cached_connections()
    with open_db("reusetest", db, module_default_path=db) as con:
        assert con.execute("SELECT 1").fetchone()[0] == 1
