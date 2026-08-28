"""warden/tests/test_ddl_memo_persists.py

The DDL registry's bookkeeping table was never written to.

`ensure_schema` records what it applied with an INSERT into
`_warden_ddl_applied`, then returned without committing. The INSERT sat in an
open transaction and was discarded when the connection closed, so the table
stayed permanently EMPTY. Every subsequent connection then read "nothing
applied" and re-executed the full DDL script for every registered module.

The docstring describes that full re-run as the rare path. It was the only
path, on every connection open, for every module in the registry.

Measured cost on production before the fix: `LemonBilling()` -- one
`open_persistent_db` -- took **5009.5ms**, reproducibly, in three separate
fresh processes. The DDL re-run needs a write lock, the four uvicorn workers
hold the database open, so it blocked and burned the entire 5000ms
`busy_timeout` before proceeding. `get_lemon_billing()` is a per-worker
singleton, so the first request served by each worker paid that 5 seconds.

That was the P99 tail: three ~5.02s stalls on the first requests after every
restart, with `mw.QuotaMiddleware` owning ~5024ms of a 5053ms trace -- because
QuotaMiddleware is where `/filter` first touches lemon.db.

This is a ghost-schema defect: a table consulted on every open that nothing
ever wrote to, so it always answered "nothing here" and always looked correct.
"""
from __future__ import annotations

import sqlite3

import pytest

from warden.db import ddl_registry as ddl

_DB_KEY = "memo_test_db"
_MODULE = "memo_test_module"
_DDL = """
CREATE TABLE IF NOT EXISTS memo_probe (
    id   INTEGER PRIMARY KEY,
    note TEXT
);
"""


@pytest.fixture
def db(tmp_path):
    ddl.register(_DB_KEY, _MODULE, _DDL)
    ddl.reset_memo()
    path = tmp_path / "memo.db"
    yield str(path)
    ddl.reset_memo()
    with ddl._lock:
        ddl._REGISTRY.pop(_DB_KEY, None)


def _open(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(path, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=5000")
    return con


def test_the_tracking_row_is_actually_persisted(db) -> None:
    """The row must survive the connection that wrote it."""
    con = _open(db)
    applied = ddl.ensure_schema(con, _DB_KEY, db)
    assert applied == 1, f"expected the module DDL to be applied once, got {applied}"
    con.close()

    # A different connection: this is the check the old code could never pass,
    # because the INSERT was never committed.
    other = _open(db)
    rows = other.execute(
        "SELECT module, checksum FROM _warden_ddl_applied"
    ).fetchall()
    other.close()

    assert rows, (
        "_warden_ddl_applied is empty after ensure_schema applied a module. "
        "The INSERT was never committed, so every future connection re-runs "
        "the entire DDL script"
    )
    assert rows[0][0] == _MODULE, f"wrong module recorded: {rows}"
    assert rows[0][1] == ddl.checksum(_DDL), "checksum recorded does not match the DDL"


def test_a_second_connection_does_no_work(db) -> None:
    """The whole point of the memo: opening the DB again must be cheap."""
    first = _open(db)
    assert ddl.ensure_schema(first, _DB_KEY, db) == 1
    first.close()

    # Clear the in-process memo so the decision has to come from the database.
    # (The implementation re-verifies against the connection on every call
    # anyway, which is exactly why an empty tracking table was so expensive.)
    ddl.reset_memo()

    second = _open(db)
    applied = ddl.ensure_schema(second, _DB_KEY, db)
    second.close()

    assert applied == 0, (
        f"ensure_schema re-applied {applied} module(s) on a second connection to "
        "an already-provisioned database. On a DB other processes hold open, "
        "that re-run blocks on the write lock and burns the full busy_timeout "
        "(measured: 5009.5ms per uvicorn worker in production)"
    )


def test_a_changed_ddl_still_re_applies(db) -> None:
    """The memo must not become a way to silently skip real schema drift."""
    con = _open(db)
    assert ddl.ensure_schema(con, _DB_KEY, db) == 1
    con.close()

    changed = _DDL + "\nCREATE TABLE IF NOT EXISTS memo_probe_2 (id INTEGER PRIMARY KEY);\n"
    ddl.register(_DB_KEY, _MODULE, changed)
    ddl.reset_memo()

    con2 = _open(db)
    applied = ddl.ensure_schema(con2, _DB_KEY, db)
    tables = {
        r[0]
        for r in con2.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    con2.close()

    assert applied == 1, (
        "the DDL checksum changed but ensure_schema skipped it — the memo is "
        "now hiding schema drift, which is worse than the cost it saves"
    )
    assert "memo_probe_2" in tables, f"the new table was not created: {sorted(tables)}"


def test_the_committed_state_is_reusable_across_processes(db) -> None:
    """Simulate a second worker: fresh memo, fresh connection, no DDL work."""
    con = _open(db)
    ddl.ensure_schema(con, _DB_KEY, db)
    con.close()

    total_applied = 0
    for _ in range(4):                       # four uvicorn workers
        ddl.reset_memo()
        c = _open(db)
        total_applied += ddl.ensure_schema(c, _DB_KEY, db)
        c.close()

    assert total_applied == 0, (
        f"{total_applied} DDL re-runs across 4 simulated workers; each one is a "
        "write-lock acquisition on a database the other workers hold open"
    )
