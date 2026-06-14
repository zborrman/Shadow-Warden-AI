"""Tests for warden.marketplace.sybil_guard."""
import os
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("STRICT_MODE", "false")

from warden.marketplace.sybil_guard import SybilGuard, _mem_flags


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_mem_flags():
    """Reset in-memory flag store between tests."""
    _mem_flags.clear()
    yield
    _mem_flags.clear()


@pytest.fixture()
def empty_db(tmp_path):
    db = str(tmp_path / "mkt.db")
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE marketplace_purchases "
        "(id INTEGER PRIMARY KEY, buyer_agent TEXT, seller_agent TEXT, "
        " price_paid REAL, status TEXT, purchased_at TEXT)"
    )
    con.commit()
    con.close()
    return db


@pytest.fixture()
def circular_db(tmp_path):
    db = str(tmp_path / "circular.db")
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE marketplace_purchases "
        "(id INTEGER PRIMARY KEY, buyer_agent TEXT, seller_agent TEXT, "
        " price_paid REAL, status TEXT, purchased_at TEXT)"
    )
    now = datetime.now(UTC).isoformat()
    con.executemany(
        "INSERT INTO marketplace_purchases (buyer_agent,seller_agent,price_paid,status,purchased_at) VALUES (?,?,?,?,?)",
        [
            ("alice", "bob",   1.0, "completed", now),
            ("bob",   "alice", 1.0, "completed", now),   # circular
            ("carol", "dave",  1.0, "completed", now),   # one-way only
        ],
    )
    con.commit()
    con.close()
    return db


@pytest.fixture()
def spike_db(tmp_path):
    """Agent with a big 24h volume spike vs low 30-day baseline."""
    db = str(tmp_path / "spike.db")
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE marketplace_purchases "
        "(id INTEGER PRIMARY KEY, buyer_agent TEXT, seller_agent TEXT, "
        " price_paid REAL, status TEXT, purchased_at TEXT)"
    )
    now = datetime.now(UTC)
    rows = []
    # 28 days of 1 trade/day for baseline
    for i in range(2, 30):
        ts = (now - timedelta(days=i)).isoformat()
        rows.append(("spike_agent", "other", 1.0, "completed", ts))
    # Today: 50 trades (massive spike)
    for _ in range(50):
        rows.append(("spike_agent", "other", 1.0, "completed", now.isoformat()))
    con.executemany(
        "INSERT INTO marketplace_purchases (buyer_agent,seller_agent,price_paid,status,purchased_at) VALUES (?,?,?,?,?)",
        rows,
    )
    con.commit()
    con.close()
    return db


# ── Circular trade detection ──────────────────────────────────────────────────

def test_detect_no_circles_empty(empty_db):
    assert SybilGuard().detect_circular_trades(empty_db) == []


def test_detect_circles_found(circular_db):
    circles = SybilGuard().detect_circular_trades(circular_db)
    assert len(circles) >= 1
    pair = circles[0]
    assert "alice" in pair and "bob" in pair


def test_detect_no_circle_for_one_way(circular_db):
    circles = SybilGuard().detect_circular_trades(circular_db)
    flat = [a for pair in circles for a in pair]
    assert "carol" not in flat or "dave" not in flat


# ── Volume spike detection ────────────────────────────────────────────────────

def test_volume_spike_empty_db_returns_zero(empty_db):
    assert SybilGuard().detect_volume_spike("nobody", empty_db) == 0.0


def test_volume_spike_high_z_score(spike_db):
    z = SybilGuard().detect_volume_spike("spike_agent", spike_db)
    assert z > 3.0, f"expected z > 3.0, got {z}"


def test_volume_spike_normal_agent_low_z(circular_db):
    z = SybilGuard().detect_volume_spike("alice", circular_db)
    assert z < 3.0


# ── Combined penalty ──────────────────────────────────────────────────────────

def test_penalty_zero_for_clean_agent(empty_db):
    assert SybilGuard().compute_sybil_penalty("clean", empty_db) == 0.0


def test_penalty_nonzero_for_circular(circular_db):
    p = SybilGuard().compute_sybil_penalty("alice", circular_db)
    assert p >= 0.5


def test_penalty_capped_at_one(spike_db):
    sg = SybilGuard()
    sg.flag_suspicious("spike_agent", "circular")
    p = sg.compute_sybil_penalty("spike_agent", spike_db)
    assert 0.0 <= p <= 1.0


# ── Flag / unflag ─────────────────────────────────────────────────────────────

def test_flag_and_is_flagged():
    sg = SybilGuard()
    sg.flag_suspicious("bad_actor", "wash_trade")
    assert sg.is_flagged("bad_actor")


def test_unflagged_agent_not_flagged():
    assert not SybilGuard().is_flagged("honest_agent")


def test_get_flag_reason():
    sg = SybilGuard()
    sg.flag_suspicious("agent_x", "volume_spike")
    assert sg.get_flag_reason("agent_x") == "volume_spike"


def test_clear_flag():
    sg = SybilGuard()
    sg.flag_suspicious("temp", "test")
    sg.clear_flag("temp")
    assert not sg.is_flagged("temp")


def test_list_flagged():
    sg = SybilGuard()
    sg.flag_suspicious("a1", "r1")
    sg.flag_suspicious("a2", "r2")
    flags = sg.list_flagged()
    ids = [f["agent_id"] for f in flags]
    assert "a1" in ids and "a2" in ids
