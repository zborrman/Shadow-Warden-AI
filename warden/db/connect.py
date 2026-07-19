"""
warden/db/connect.py
────────────────────
Single seam for opening a per-module SQLite (or Turso) connection.

Before this helper, every module hand-rolled its own connection boilerplate,
and mostly did it inconsistently — three separate defects the data-layer audit
called out:

  • F1 — pragmas: only ~13 of ~130 connect sites applied WAL + a busy_timeout.
    The rest ran library defaults (``busy_timeout=0``), i.e. an instant
    ``database is locked`` under any concurrent writer.
  • F2 — DDL-once: ~60 modules still ran ``executescript(CREATE TABLE …)`` on
    *every* connection, taking a write lock even on read paths.
  • lifecycle: commit/close was copy-pasted per module, occasionally wrong
    (bare connections that were never closed).

``open_db`` collapses all three into one context manager:

    from warden.db.connect import open_db

    with open_db("push", _DB_PATH) as con:
        con.execute("INSERT INTO push_device_tokens VALUES (…)")
    # pragmas applied, schema ensured once, committed + closed on exit.

It routes through :mod:`warden.db.turso` when a ``turso_name`` is given and that
logical DB is Turso-enabled — but only for the module's real DB path, never for
an explicit test path (tmp_path isolation), mirroring the per-module ``_conn``
helpers it replaces.
"""
from __future__ import annotations

import logging
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager, suppress
from typing import Any

from warden.db.ddl_registry import ensure_schema
from warden.db.sqlite_pragmas import init_pragmas

log = logging.getLogger("warden.db.connect")


@contextmanager
def open_db(
    db_key: str,
    db_path: str,
    *,
    turso_name: str | None = None,
    module_default_path: str | None = None,
    row_factory: bool = True,
    foreign_keys: bool = True,
    check_same_thread: bool = False,
) -> Generator[Any, None, None]:
    """
    Yield a connection with pragmas applied, schema ensured once, and
    commit/close handled on exit.

    Parameters
    ----------
    db_key
        Registry key passed to :func:`warden.db.ddl_registry.ensure_schema` —
        the schema-owner group. Must be **per physical DB file** (two modules
        that share one file share the key; distinct files never do).
    db_path
        Concrete file path, already resolved via ``config.data_path()``.
    turso_name
        When set *and* ``db_path`` is the module default *and* Turso is enabled
        for that name, route through :mod:`warden.db.turso` instead of local
        SQLite. An explicit non-default ``db_path`` always forces local SQLite,
        so ``tmp_path`` test isolation keeps working.
    module_default_path
        The module's canonical DB path. Used only to decide Turso eligibility;
        defaults to ``db_path`` (i.e. treat the given path as canonical).
    row_factory
        Set ``sqlite3.Row`` as the row factory (local SQLite only — Turso rows
        are already ``Row``-compatible). Default True.
    foreign_keys
        Passed through to :func:`init_pragmas`. Default True.
    check_same_thread
        Passed through to :func:`sqlite3.connect`. Default False (module DBs are
        accessed from background tasks / worker threads).
    """
    canonical = module_default_path if module_default_path is not None else db_path

    # ── Turso routing — only for the real DB, never an explicit test path ──────
    if turso_name and db_path == canonical:
        try:
            from warden.db.turso import get_connection, is_turso_enabled  # noqa: PLC0415

            if is_turso_enabled(turso_name):
                with get_connection(turso_name, fallback_path=db_path) as con:
                    with suppress(Exception):
                        ensure_schema(con, db_key, db_path)
                    yield con
                return
        except ImportError as exc:
            # turso adapter unavailable — fall through to local SQLite
            log.debug("turso adapter unavailable (%s); using local SQLite", exc)

    # ── Local SQLite ──────────────────────────────────────────────────────────
    con = sqlite3.connect(db_path, check_same_thread=check_same_thread)
    if row_factory:
        con.row_factory = sqlite3.Row
    init_pragmas(con, foreign_keys=foreign_keys)
    ensure_schema(con, db_key, db_path)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def open_persistent_db(
    db_key: str,
    db_path: str,
    *,
    row_factory: bool = True,
    foreign_keys: bool = True,
    check_same_thread: bool = False,
) -> sqlite3.Connection:
    """
    Return a long-lived connection with pragmas applied and schema ensured once.

    For the ``self._conn`` class pattern — one connection opened in ``__init__``
    and held for the instance's lifetime — where ``open_db``'s per-call
    context manager doesn't fit: these classes commit explicitly inside their
    own ``threading.Lock``-protected write methods, so there is no single call
    boundary to auto-commit/close around. The caller owns the returned
    connection and must call ``.close()`` itself.

    No Turso routing (unlike ``open_db``) — none of the ``self._conn``-holding
    modules are Turso-active; add it here if that changes.
    """
    con = sqlite3.connect(db_path, check_same_thread=check_same_thread)
    if row_factory:
        con.row_factory = sqlite3.Row
    init_pragmas(con, foreign_keys=foreign_keys)
    ensure_schema(con, db_key, db_path)
    return con


def open_db_readonly(
    db_path: str,
    *,
    row_factory: bool = True,
    check_same_thread: bool = False,
) -> sqlite3.Connection:
    """
    Return a read-only connection to a DB this process doesn't own the schema
    for (a peer module's tables, read by a cross-module report/collector).

    Uses SQLite's URI ``mode=ro`` — a missing file raises immediately instead
    of silently creating an empty one, which a plain read-write ``connect``
    would do. Callers already wrap these reads in a broad except-and-return-
    default clause, so this only tightens a foreign-schema read; it never
    applies pragmas or touches the DDL registry, since this connection never
    writes and doesn't own the table it's reading.
    """
    con = sqlite3.connect(
        f"file:{db_path}?mode=ro", uri=True, check_same_thread=check_same_thread
    )
    if row_factory:
        con.row_factory = sqlite3.Row
    return con
