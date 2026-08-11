"""
warden/tests/test_community_transfer_stats.py

`communities/intelligence.py::_fetch_transfer_stats` asked `sep_transfers` for
three columns and got all three wrong: the table has `source_community_id` and
`target_community_id`, and it has no data-class column at all — data class
lives on `sep_pod_tags`. Every call raised into a `log.debug`, so community
intelligence reported an all-zero `TransferStats`, which is exactly what a
community that has never transferred anything looks like.

The fixture builds its tables from the **real DDL constants in `sep.py`**, not
from hand-written CREATE statements. That is the whole point: six fixtures in
this workstream passed against schemas production never had, and one of them
(`marketplace_escrows`) even taught the ghost-table ratchet to accept an
invented name.
"""
from __future__ import annotations

import os
import sqlite3

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")


def _sep_db(tmp_path) -> str:
    # `sep_pod_tags` is declared in sep.py, `sep_transfers` in peering.py —
    # they share one file (SEP_DB_PATH). Both DDLs come from the writers.
    from warden.communities.peering import _PEERING_DDL  # noqa: PLC0415
    from warden.communities.sep import _SEP_DDL  # noqa: PLC0415

    path = str(tmp_path / "sep.db")
    con = sqlite3.connect(path)
    con.executescript(_SEP_DDL)
    con.executescript(_PEERING_DDL)
    con.commit()
    con.close()
    return path


def _insert_transfer(path, *, tid, src, dst, entity, status="ACCEPTED"):
    con = sqlite3.connect(path)
    con.execute(
        "INSERT INTO sep_transfers (transfer_id, peering_id, source_community_id, "
        "target_community_id, source_entity_id, source_ueciid, target_ueciid, "
        "initiator_mid, purpose, status, causal_proof_json, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (tid, "peer-1", src, dst, entity, "SEP-00000000001", "SEP-00000000002",
         "mid-1", "test", status, "{}", "2026-08-11T00:00:00Z"),
    )
    con.commit()
    con.close()


def _tag(path, *, entity, community, data_class):
    con = sqlite3.connect(path)
    con.execute(
        "INSERT INTO sep_pod_tags (entity_id, community_id, jurisdiction, data_class) "
        "VALUES (?,?,?,?)",
        (entity, community, "EU", data_class),
    )
    con.commit()
    con.close()


def test_transfer_stats_counts_transfers_and_their_data_class(tmp_path, monkeypatch):
    from warden.communities import intelligence as intel

    db = _sep_db(tmp_path)
    _insert_transfer(db, tid="t1", src="comm-a", dst="comm-b", entity="e1")
    _insert_transfer(db, tid="t2", src="comm-a", dst="comm-b", entity="e2")
    _insert_transfer(db, tid="t3", src="comm-a", dst="comm-c", entity="e3",
                     status="REJECTED")
    _tag(db, entity="e1", community="comm-a", data_class="PHI")
    _tag(db, entity="e2", community="comm-a", data_class="PHI")
    # e3 has no pod tag — its class falls back to GENERAL rather than vanishing.

    monkeypatch.setattr(intel, "_SEP_DB_PATH", db)
    stats = intel._fetch_transfer_stats("comm-a")

    assert stats.total == 3
    assert stats.accepted == 2
    assert stats.rejected == 1
    assert stats.by_data_class == {"PHI": 2, "GENERAL": 1}
    assert stats.top_target_communities[0] == {"community_id": "comm-b", "count": 2}


def test_transfer_stats_scopes_to_the_asking_community(tmp_path, monkeypatch):
    from warden.communities import intelligence as intel

    db = _sep_db(tmp_path)
    _insert_transfer(db, tid="t1", src="comm-a", dst="comm-b", entity="e1")
    _insert_transfer(db, tid="t2", src="comm-z", dst="comm-b", entity="e2")

    monkeypatch.setattr(intel, "_SEP_DB_PATH", db)
    assert intel._fetch_transfer_stats("comm-a").total == 1


def test_transfer_stats_is_zero_only_when_there_are_no_transfers(tmp_path, monkeypatch):
    """The bug's signature was a zero that meant 'the query raised'. Prove a
    zero now means what it says."""
    from warden.communities import intelligence as intel

    db = _sep_db(tmp_path)
    monkeypatch.setattr(intel, "_SEP_DB_PATH", db)
    stats = intel._fetch_transfer_stats("comm-empty")
    assert stats.total == 0 and stats.by_data_class == {}


def test_intelligence_no_longer_names_the_columns_that_do_not_exist():
    import ast
    import inspect

    from warden.communities import intelligence as intel

    for node in ast.walk(ast.parse(inspect.getsource(intel))):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if "sep_transfers" not in node.value:
                continue
            for ghost in ("source_community=", "target_community ", "target_data_class"):
                assert ghost not in node.value, f"intelligence.py asks for {ghost!r} again"
