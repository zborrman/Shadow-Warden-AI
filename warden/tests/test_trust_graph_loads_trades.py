"""warden/tests/test_trust_graph_loads_trades.py — SW-11 follow-up.

`TrustGraph.build_graph()` must actually read the marketplace database.

It took an optional `db_path` and passed it straight to `open_db_readonly`, so
the no-argument call — which is how every caller in the codebase uses it —
opened `file:None?mode=ro` and raised `unable to open database file`.
`_load_trades` caught that and returned an empty aggregate, so TrustRank has
been computed over an empty graph for the life of the feature: every trust
score 0, every leaderboard empty, every Sybil check trivially clean, and
`GET /marketplace/agents/{id}/trust` answering 200 the whole time.

`_db_path()` was in the same module, resolving on every call by design (DE-6
P2). It was simply never called from `_load_trades`.

Nothing caught this because every observable was a legitimate value for a
marketplace with no trades yet. The only way to tell the two apart is to put a
trade in and check it comes back.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from warden.db.ddl_registry import ensure_schema
from warden.marketplace.trust_graph import TrustGraph


def _seeded_db(db: Path, *, rows: bool) -> Path:
    """A marketplace database with the real schema, optionally holding trades.

    The DDL comes from the registry rather than from a `CREATE TABLE` written
    here. A fixture that invents its own columns tests the fixture: the real
    `marketplace_purchases` has twelve, including `purchase_id`, `asset_id` and
    `escrow_id`, and a hand-rolled six-column stand-in is how the clearing bug
    in #325 passed its own tests while settling every trade at $0.00.
    """
    import warden.marketplace.listing  # noqa: F401,PLC0415 — registers the DDL

    con = sqlite3.connect(db)
    ensure_schema(con, "marketplace", str(db))
    if rows:
        con.executemany(
            "INSERT INTO marketplace_purchases "
            "(purchase_id, listing_id, asset_id, buyer_agent, seller_agent,"
            " price_paid, status, purchased_at) VALUES (?,?,?,?,?,?,?,?)",
            [
                ("p1", "l1", "a1", "agent_buyer", "agent_seller",
                 10.0, "completed", "2026-09-01"),
                ("p2", "l2", "a2", "agent_buyer", "agent_third",
                 5.0, "completed", "2026-09-02"),
            ],
        )
    con.commit()
    con.close()
    return db


@pytest.fixture
def marketplace_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A marketplace database holding two completed trades between three agents."""
    db = _seeded_db(tmp_path / "warden_marketplace.db", rows=True)
    monkeypatch.setattr("warden.marketplace.trust_graph._db_path", lambda: str(db))
    return db


def test_build_graph_reads_the_database_without_being_told_where_it_is(
    marketplace_db: Path,
) -> None:
    """The no-argument call is the only one anyone makes."""
    tg = TrustGraph()
    tg.build_graph()

    ranked = tg.top_agents(n=10)
    assert ranked, (
        "build_graph() with no arguments produced an empty ranking from a "
        "database with two completed trades in it. That is the state the whole "
        "feature was in: indistinguishable from a marketplace nobody has used."
    )
    assert {e["agent_id"] for e in ranked} & {"agent_seller", "agent_third"}, (
        f"the sellers are missing from the ranking: {ranked}"
    )
    assert tg.edges(), "no edges were built from two recorded trades"


def test_an_explicit_path_still_wins(marketplace_db: Path, tmp_path: Path) -> None:
    """The parameter has to keep working; the fix is a fallback, not a override.

    `warden/tests` and the backup tooling both pass a path explicitly.
    """
    empty = _seeded_db(tmp_path / "empty.db", rows=False)

    tg = TrustGraph()
    tg.build_graph(db_path=str(empty))
    assert not tg.top_agents(n=10), (
        "an explicitly-passed empty database still produced a ranking, so the "
        "argument is being ignored in favour of the default"
    )
