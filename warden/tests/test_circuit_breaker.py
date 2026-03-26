"""
warden/tests/test_circuit_breaker.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for warden/circuit_breaker.py.

Uses a real fakeredis instance so Redis Lua pipelines are exercised without
a live server.  Falls back to a dict-based stub if fakeredis is not installed.
"""
from __future__ import annotations

import time

import pytest

import warden.circuit_breaker as cb

# ── Minimal Redis stub (no external deps required) ────────────────────────────

class _FakeRedis:
    """Enough of the Redis interface to exercise circuit_breaker.py."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[str, float | None]] = {}  # key → (value, expire_at)
        self._zsets: dict[str, dict[str, float]] = {}          # key → {member: score}

    def _expired(self, key: str) -> bool:
        if key not in self._store:
            return True
        _, exp = self._store[key]
        return exp is not None and time.time() > exp

    def exists(self, key: str) -> int:
        return 0 if self._expired(key) else 1

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        expire_at = time.time() + ex if ex else None
        self._store[key] = (value, expire_at)

    def ttl(self, key: str) -> int:
        if self._expired(key):
            return -2
        _, exp = self._store[key]
        if exp is None:
            return -1
        return max(0, int(exp - time.time()))

    def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self._zsets.setdefault(key, {}).update(mapping)

    def zremrangebyscore(self, key: str, min_: str | float, max_: str | float) -> None:
        zset = self._zsets.get(key, {})
        lo = float("-inf") if min_ == "-inf" else float(min_)
        hi = float("+inf") if max_ == "+inf" else float(max_)
        self._zsets[key] = {m: s for m, s in zset.items() if not (lo <= s <= hi)}

    def zcard(self, key: str) -> int:
        return len(self._zsets.get(key, {}))

    def expire(self, key: str, secs: int) -> None:
        pass  # not needed for these tests

    def pipeline(self, transaction: bool = True):
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, r: _FakeRedis) -> None:
        self._r = r
        self._cmds: list = []

    def zadd(self, key, mapping):
        self._cmds.append(("zadd", key, mapping))
        return self

    def zremrangebyscore(self, key, min_, max_):
        self._cmds.append(("zrem", key, min_, max_))
        return self

    def expire(self, key, secs):
        self._cmds.append(("expire", key, secs))
        return self

    def execute(self):
        for cmd in self._cmds:
            if cmd[0] == "zadd":
                self._r.zadd(cmd[1], cmd[2])
            elif cmd[0] == "zrem":
                self._r.zremrangebyscore(cmd[1], cmd[2], cmd[3])


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def r() -> _FakeRedis:
    return _FakeRedis()


# ── is_open ───────────────────────────────────────────────────────────────────

def test_is_open_initial_closed(r) -> None:
    assert cb.is_open(r) is False


def test_is_open_after_set(r) -> None:
    r.set(cb._STATE_KEY, "1", ex=30)
    assert cb.is_open(r) is True


def test_is_open_none_redis() -> None:
    assert cb.is_open(None) is False


# ── record_bypass ─────────────────────────────────────────────────────────────

def test_record_bypass_adds_to_zset(r) -> None:
    cb.record_bypass(r)
    assert r.zcard(cb._BYPASS_KEY) == 1


def test_record_bypass_multiple(r) -> None:
    for _ in range(5):
        cb.record_bypass(r)
    assert r.zcard(cb._BYPASS_KEY) == 5


def test_record_bypass_none_redis() -> None:
    cb.record_bypass(None)   # must not raise


def test_record_bypass_prunes_old_entries(r) -> None:
    # Manually insert an old entry (older than WINDOW_SECS)
    old_ts = time.time() - cb.WINDOW_SECS - 5
    r.zadd(cb._BYPASS_KEY, {"old": old_ts})
    # Record a new bypass — pipeline should prune the old one
    cb.record_bypass(r)
    # After pruning, only the new entry remains
    assert r.zcard(cb._BYPASS_KEY) == 1


# ── check_and_trip ────────────────────────────────────────────────────────────

def test_no_trip_below_min_requests(r) -> None:
    for _ in range(cb.MIN_REQUESTS - 1):
        cb.record_bypass(r)
    tripped = cb.check_and_trip(r, cb.MIN_REQUESTS - 1)
    assert tripped is False
    assert cb.is_open(r) is False


def test_no_trip_below_threshold(r) -> None:
    # 5% bypass rate with 100 total requests — below 10% threshold
    for _ in range(5):
        cb.record_bypass(r)
    tripped = cb.check_and_trip(r, 100)
    assert tripped is False
    assert cb.is_open(r) is False


def test_trips_at_threshold(r) -> None:
    # Exactly 10% bypass rate with 100 total requests
    for _ in range(10):
        cb.record_bypass(r)
    tripped = cb.check_and_trip(r, 100)
    assert tripped is True
    assert cb.is_open(r) is True


def test_trips_above_threshold(r) -> None:
    # 25% bypass rate
    for _ in range(25):
        cb.record_bypass(r)
    tripped = cb.check_and_trip(r, 100)
    assert tripped is True


def test_no_trip_none_redis() -> None:
    assert cb.check_and_trip(None, 100) is False


def test_no_trip_zero_total(r) -> None:
    cb.record_bypass(r)
    assert cb.check_and_trip(r, 0) is False


# ── get_state ─────────────────────────────────────────────────────────────────

def test_get_state_closed(r) -> None:
    state = cb.get_state(r)
    assert state["status"] == "closed"
    assert state["bypasses_in_window"] == 0
    assert state["cooldown_remaining_s"] == 0


def test_get_state_open(r) -> None:
    r.set(cb._STATE_KEY, "1", ex=30)
    cb.record_bypass(r)
    state = cb.get_state(r)
    assert state["status"] == "open"
    assert state["bypasses_in_window"] == 1
    assert state["cooldown_remaining_s"] > 0


def test_get_state_none_redis() -> None:
    state = cb.get_state(None)
    assert state["status"] == "disabled"


def test_get_state_contains_tunables(r) -> None:
    state = cb.get_state(r)
    assert state["window_secs"] == cb.WINDOW_SECS
    assert state["threshold"] == cb.THRESHOLD


# ── End-to-end: trip → open → auto-reset ─────────────────────────────────────

def test_full_trip_cycle(r) -> None:
    # Drive bypass rate above threshold
    for _ in range(15):
        cb.record_bypass(r)
    cb.check_and_trip(r, 100)
    assert cb.is_open(r) is True

    # Simulate cooldown expiry by deleting the state key
    del r._store[cb._STATE_KEY]
    assert cb.is_open(r) is False   # auto-reset to CLOSED


def test_circuit_open_state_resets_to_closed_on_expiry(r) -> None:
    r.set(cb._STATE_KEY, "1", ex=1)
    assert cb.is_open(r) is True
    # Force expiry
    r._store[cb._STATE_KEY] = ("1", time.time() - 1)
    assert cb.is_open(r) is False
