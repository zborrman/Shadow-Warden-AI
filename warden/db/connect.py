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
import os
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager, suppress
from typing import Any

from warden.db.ddl_registry import ensure_schema
from warden.db.sqlite_pragmas import init_pragmas

log = logging.getLogger("warden.db.connect")

# ── Per-thread connection cache ───────────────────────────────────────────────
#
# Per-thread, never global: a SQLite connection opened with
# check_same_thread=False can be *passed* between threads, but two threads
# interleaving statements on one connection would interleave their
# transactions. One cache per thread removes that class of bug outright.

_MAX_CACHED_PER_THREAD = 32


class _Entry:
    __slots__ = ("con", "in_use", "ident", "orphaned")

    def __init__(self, con: sqlite3.Connection, ident: tuple | None) -> None:
        self.con = con
        self.in_use = False
        # Evicted from the cache while a frame still held it. That frame owns the
        # close; nothing hands this connection out again.
        self.orphaned = False
        # (st_dev, st_ino) at open time. A cached connection keeps writing to the
        # *inode* it opened, not to the path: on POSIX, deleting or replacing the
        # file leaves the connection happily writing to a ghost, and a restore
        # from `warden/backup/service.py` swapping a database file underneath is
        # exactly that scenario. Re-stat before every reuse.
        self.ident = ident


def _file_ident(db_path: str) -> tuple | None:
    try:
        st = os.stat(db_path)
        return (st.st_dev, st.st_ino)
    except OSError:
        return None


_tls = threading.local()


def _reuse_enabled() -> bool:
    """Kill switch. Set WARDEN_DB_CONN_REUSE=false to fall back to a fresh
    connection per call — the behaviour that shipped before this optimisation."""
    return os.getenv("WARDEN_DB_CONN_REUSE", "true").strip().lower() not in (
        "0", "false", "no", "off",
    )


def _cache() -> dict[tuple[str, str], _Entry]:
    cache = getattr(_tls, "cache", None)
    if cache is None:
        cache = {}
        _tls.cache = cache
    return cache


def _checkout(db_key: str, db_path: str) -> _Entry | None:
    """An idle cached connection for this key, or a new one. None ⇒ caller must
    open its own (the cached one is busy in an enclosing frame)."""
    cache = _cache()
    key = (db_key, db_path)
    entry = cache.get(key)

    if entry is not None:
        if entry.in_use:
            return None                       # nested call — do not share
        if _file_ident(db_path) != entry.ident:
            # The file was deleted or replaced since this connection opened it.
            with suppress(Exception):
                entry.con.close()
            del cache[key]
            entry = None
        else:
            # Re-run ensure_schema on every checkout, not just at creation.
            # Modules register their DDL at *import* time and several are
            # imported lazily inside functions, so the set of registered schemas
            # grows during a process's life. A connection that skipped this
            # would stay frozen at whatever was registered when it was opened,
            # and a later-imported module's tables would never be created on it
            # — "no such table: marketplace_purchases", which is exactly how
            # this surfaced. ensure_schema is memoized and costs one indexed
            # SELECT; the expense reuse removes is `sqlite3.connect` plus the
            # pragmas, not this.
            ensure_schema(entry.con, db_key, db_path)
            entry.in_use = True
            return entry

    if len(cache) >= _MAX_CACHED_PER_THREAD:
        # Bound the open file descriptors a long-lived worker thread can hold.
        for k, victim in list(cache.items()):
            if not victim.in_use:
                with suppress(Exception):
                    victim.con.close()
                del cache[k]
                break
        else:
            return None                       # everything busy — open a fresh one

    con = None
    try:
        con = sqlite3.connect(db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        init_pragmas(con, foreign_keys=True)
        ensure_schema(con, db_key, db_path)
    except Exception as exc:
        # `init_pragmas` and `ensure_schema` both run after connect() succeeded,
        # so a failure here leaves an open handle the caller never learns about.
        if con is not None:
            with suppress(Exception):
                con.close()
        log.debug("connect: could not open a cacheable connection (%s); using a fresh one", exc)
        return None

    entry = _Entry(con, _file_ident(db_path))
    entry.in_use = True
    cache[key] = entry
    return entry


def _discard(db_key: str, db_path: str, entry: _Entry) -> None:
    with suppress(Exception):
        entry.con.rollback()
    with suppress(Exception):
        entry.con.close()
    # Evict by identity: between this entry being handed out and being discarded,
    # the key may have been re-populated with a different connection (a nested
    # frame that reopened after an inode change). Popping blindly would throw
    # away a live one.
    cache = _cache()
    if cache.get((db_key, db_path)) is entry:
        del cache[(db_key, db_path)]


def close_cached_connections() -> None:
    """Close and forget this thread's cached connections.

    For tests that recreate a database file at a path already seen in this
    process, and for a worker that wants to release descriptors between jobs.
    """
    cache = getattr(_tls, "cache", None)
    if not cache:
        return
    for key, entry in list(cache.items()):
        if entry.in_use:
            # An enclosing frame is mid-block on this connection; closing it
            # would pull the transaction out from under that caller. Hand the
            # close to that frame instead and drop it from the cache, so it is
            # never handed out again.
            entry.orphaned = True
            del cache[key]
            continue
        with suppress(Exception):
            entry.con.close()
        del cache[key]


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
    #
    # Connection reuse. Measured through this seam, `sqlite3.connect` + the six
    # pragmas + ensure_schema's tracking-table check cost ~257x more than the
    # write itself: 160 write-txn/s opening per call, 41 169/s on a reused
    # connection. The write lock was never the ceiling — this setup was.
    #
    # Reuse is deliberately conservative: it applies only to the default
    # parameter combination, and only when no other frame on this thread is
    # already inside a block for the same (db_key, path). A nested caller gets a
    # brand-new connection exactly as before, so a nested failure still rolls
    # back only its own work and can never commit — or abort — the outer
    # transaction that wraps it. That property is load-bearing: `_do_purchase`
    # writes a purchase and its escrow in one transaction and calls into other
    # modules while holding it.
    reusable = (
        _reuse_enabled()
        and row_factory
        and foreign_keys
        and not check_same_thread
    )
    entry = _checkout(db_key, db_path) if reusable else None

    if entry is not None:
        try:
            yield entry.con
            entry.con.commit()
        except BaseException:
            # State after a failed statement is unknown — roll back and drop the
            # connection rather than hand a poisoned one to the next caller.
            _discard(db_key, db_path, entry)
            raise
        else:
            if entry.orphaned:
                with suppress(Exception):
                    entry.con.close()
            else:
                entry.in_use = False
        return

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
