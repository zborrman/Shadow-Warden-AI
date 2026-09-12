"""Per-database migrations must run once per process, not once per connection.

Why this is a ratchet and not a micro-optimisation: the production marketplace
database is on Turso, where every statement is a separate HTTPS request. The six
``_migrate_*`` helpers in ``listing.py`` and ``_ensure_columns`` in ``agent.py``
issue ~16 statements between them, nine of which are ``ALTER TABLE ... ADD
COLUMN`` calls that are *expected to fail* because the column already exists.
Run per connection, that cost ``GET /marketplace/listings`` 9.5 s to return an
empty list, measured in production on 2026-09-12 against a ``/health`` of 10 ms.

Local SQLite hides this completely — the statements are microseconds — so the
defect is invisible to a test that only asserts results. These tests assert the
*number of statements*, which is the property that regressed.
"""
from __future__ import annotations

from contextlib import contextmanager

import pytest

from warden.marketplace import agent as agent_mod
from warden.marketplace import listing as listing_mod


@pytest.fixture
def market_db(tmp_path, monkeypatch):
    """A private marketplace database, with both memos cleared around the test."""
    path = str(tmp_path / "mkt.db")
    monkeypatch.setenv("MARKETPLACE_DB_PATH", path)
    listing_mod.reset_migration_memo()
    agent_mod.reset_column_memo()
    yield path
    listing_mod.reset_migration_memo()
    agent_mod.reset_column_memo()


def test_listing_migrations_run_once_per_database(market_db, monkeypatch):
    calls: list[str] = []
    for name in (
        "_migrate_chain_column",
        "_migrate_sponsored_columns",
        "_migrate_kya_column",
        "_migrate_idempotency_column",
        "_migrate_order_consolidation_columns",
        "_migrate_relax_asset_id_nullable",
    ):
        original = getattr(listing_mod, name)

        def spy(con, _n=name, _o=original):
            calls.append(_n)
            return _o(con)

        monkeypatch.setattr(listing_mod, name, spy)

    for _ in range(3):
        with listing_mod._conn():
            pass

    assert sorted(set(calls)) == sorted(calls), "a migration ran more than once"
    assert len(calls) == 6, f"expected each of the 6 migrations once, got {calls}"


def test_reset_migration_memo_forces_a_rerun(market_db, monkeypatch):
    calls = []
    original = listing_mod._migrate_chain_column
    monkeypatch.setattr(
        listing_mod,
        "_migrate_chain_column",
        lambda con: (calls.append(1), original(con))[1],
    )

    with listing_mod._conn():
        pass
    with listing_mod._conn():
        pass
    assert len(calls) == 1

    listing_mod.reset_migration_memo()
    with listing_mod._conn():
        pass
    assert len(calls) == 2, "reset_migration_memo() must make the next open re-migrate"


def test_agent_column_backfill_runs_once_per_database(market_db, monkeypatch):
    calls = []
    original = agent_mod._ensure_columns
    monkeypatch.setattr(
        agent_mod,
        "_ensure_columns",
        lambda con: (calls.append(1), original(con))[1],
    )

    for _ in range(4):
        with agent_mod._conn():
            pass

    assert len(calls) == 1, f"_ensure_columns ran {len(calls)} times, expected 1"

    agent_mod.reset_column_memo()
    with agent_mod._conn():
        pass
    assert len(calls) == 2


def test_second_open_is_cheap_in_statements(market_db, monkeypatch):
    """The ratchet: a warm connection must not re-issue schema statements.

    Counted with sqlite's own trace callback rather than by spying on our
    helpers, so it still fails if someone reintroduces the per-connection work
    by another route.
    """
    counter = {"n": 0}
    real_open_db = listing_mod.open_db

    @contextmanager
    def traced_open_db(*args, **kwargs):
        with real_open_db(*args, **kwargs) as con:
            con.set_trace_callback(lambda _sql: counter.__setitem__("n", counter["n"] + 1))
            try:
                yield con
            finally:
                con.set_trace_callback(None)

    monkeypatch.setattr(listing_mod, "open_db", traced_open_db)

    with listing_mod._conn():
        pass
    cold = counter["n"]

    counter["n"] = 0
    with listing_mod._conn():
        pass
    warm = counter["n"]

    assert cold > warm, f"cold open issued {cold} statements, warm {warm}"
    assert warm <= 3, (
        f"a warm connection issued {warm} statements; schema work has leaked "
        "back onto the per-connection path (see this module's docstring)"
    )
