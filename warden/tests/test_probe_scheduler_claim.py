"""
warden/tests/test_probe_scheduler_claim.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`probe_scheduler()` is spawned from main.py's lifespan, so it runs once per
uvicorn worker. Production runs --workers 4, and the schedule used to live in a
per-process dict, so every monitor was probed four times at the same second —
verified in prod as four `probe_results` rows sharing one timestamp, and
`Uptime probe scheduler started` logged four times per boot.

The claim key names a wall-clock interval *bucket*, so "which interval" is
derived from the clock rather than remembered per process. These tests pin that
one worker probes a bucket, that a worker restarting late in an interval does
not get a second bite at it, and that a Redis outage restores the old
duplicate-probe behaviour rather than taking monitoring dark.
"""
from __future__ import annotations

import pytest

from warden.workers import probe_worker as pw

#: A 60s bucket boundary (1_000_020 == 16_667 * 60). Picking a round-looking
#: number instead put "start" and "start + 59.9s" in different buckets.
_T0 = 1_000_020.0

_MONITOR = {"id": "mon-1", "tenant_id": "t1", "name": "API", "url": "https://x.test/",
            "interval_s": 60, "check_type": "http"}


class _FakeRedis:
    """Grants the first claim per key, denies repeats — redis-py NX semantics."""

    def __init__(self, grant: bool = True):
        self.calls: list[dict] = []
        self.held: set[str] = set()
        self._grant = grant

    def set(self, key, value, nx=False, px=None):
        self.calls.append({"key": key, "value": value, "nx": nx, "px": px})
        if not self._grant or key in self.held:
            return None
        self.held.add(key)
        return True


@pytest.fixture(autouse=True)
def _reset():
    pw._last_bucket.clear()
    yield
    pw._last_bucket.clear()


def _patch(monkeypatch, client, *, monitors=(_MONITOR,), now=None):
    monkeypatch.setattr(pw.cache, "_get_client", lambda: client)
    monkeypatch.setattr(pw, "_load_monitors", _async_return(list(monitors)))
    if now is not None:
        monkeypatch.setattr(pw.time, "time", lambda: now)


# ── The bucket ────────────────────────────────────────────────────────────────

def test_bucket_is_shared_across_processes():
    """Two processes at the same wall-clock instant must agree on the bucket."""
    assert pw._bucket(60, _T0) == pw._bucket(60, _T0 + 59.9)
    assert pw._bucket(60, _T0 + 60.0) == pw._bucket(60, _T0) + 1


def test_bucket_survives_a_zero_interval():
    """interval_s=0 must not divide by zero."""
    assert pw._bucket(0, 123.0) == 123


# ── The claim ─────────────────────────────────────────────────────────────────

async def test_claim_granted_once_per_bucket(monkeypatch):
    redis = _FakeRedis()
    _patch(monkeypatch, redis)

    bucket = pw._bucket(60, _T0)
    assert await pw._claim(_MONITOR, bucket, _T0) is True
    assert await pw._claim(_MONITOR, bucket, _T0) is False


async def test_claim_key_names_the_bucket(monkeypatch):
    redis = _FakeRedis()
    _patch(monkeypatch, redis)

    await pw._claim(_MONITOR, 42, _T0)
    assert redis.calls[0]["key"] == f"{pw._CLAIM_PREFIX}mon-1:42"
    assert redis.calls[0]["nx"] is True


async def test_claim_ttl_runs_to_the_end_of_its_bucket(monkeypatch):
    """A TTL that expired mid-bucket is what let a restarted worker re-probe."""
    redis = _FakeRedis()
    _patch(monkeypatch, redis)

    now = _T0 + 10.0
    bucket = pw._bucket(60, now)
    await pw._claim(_MONITOR, bucket, now)

    remaining = (bucket + 1) * 60 - now
    assert redis.calls[0]["px"] == int((remaining + pw._CLAIM_MARGIN_S) * 1000)
    assert redis.calls[0]["px"] > remaining * 1000     # margin, never short


async def test_claim_ttl_has_a_floor(monkeypatch):
    """A claim made in the last instant of a bucket still gets a usable TTL."""
    redis = _FakeRedis()
    _patch(monkeypatch, redis)

    now = _T0 + 59.999
    await pw._claim(_MONITOR, pw._bucket(60, now), now)
    assert redis.calls[0]["px"] >= 1000


async def test_claim_fails_open_when_redis_is_absent(monkeypatch):
    """No Redis: probe anyway (duplicates beat blindness) — and count it."""
    _patch(monkeypatch, None)
    counted: list[tuple] = []
    monkeypatch.setattr(pw, "record_failopen",
                        lambda stage, reason, exc=None: counted.append((stage, reason)))

    assert await pw._claim(_MONITOR, 1, 60.0) is True
    assert counted == [("probe_claim", pw.Reason.REDIS_UNAVAILABLE)]


async def test_claim_fails_open_when_redis_raises(monkeypatch):
    class _Boom:
        def set(self, *a, **k):
            raise RuntimeError("connection reset")

    _patch(monkeypatch, _Boom())
    counted: list[tuple] = []
    monkeypatch.setattr(pw, "record_failopen",
                        lambda stage, reason, exc=None: counted.append((stage, reason)))

    assert await pw._claim(_MONITOR, 1, 60.0) is True
    assert counted == [("probe_claim", pw.Reason.BACKEND_ERROR)]


# ── The tick ──────────────────────────────────────────────────────────────────

async def test_four_workers_one_probe(monkeypatch):
    """The regression itself: independent processes, one probe per bucket."""
    redis = _FakeRedis()
    _patch(monkeypatch, redis, now=_T0)
    probed = _record_probes(monkeypatch)

    for _ in range(4):
        pw._last_bucket.clear()      # each worker has its own local memory
        await pw._scheduler_tick()

    assert probed == ["mon-1"]


async def test_restart_late_in_an_interval_does_not_reprobe(monkeypatch):
    """CodeRabbit on #432: a worker restarting at 59/60s must not get a second bite.

    With a monitor-only key expiring at a fraction of the interval, the restarted
    worker had no local history, found the monitor due, and claimed a bucket that
    had already been served. The bucket is in the key, so it now loses.
    """
    redis = _FakeRedis()
    _patch(monkeypatch, redis, now=_T0 + 1.0)
    probed = _record_probes(monkeypatch)

    await pw._scheduler_tick()                                  # established, 1s in
    assert probed == ["mon-1"]

    pw._last_bucket.clear()                                     # a fresh worker
    monkeypatch.setattr(pw.time, "time", lambda: _T0 + 59.0)   # 59s in
    await pw._scheduler_tick()
    assert probed == ["mon-1"]                                  # still one

    monkeypatch.setattr(pw.time, "time", lambda: _T0 + 61.0)   # next bucket
    await pw._scheduler_tick()
    assert probed == ["mon-1", "mon-1"]


async def test_tick_records_the_bucket_for_the_loser_too(monkeypatch):
    """A loser that did not would re-query Redis on every 5s tick."""
    redis = _FakeRedis(grant=False)
    _patch(monkeypatch, redis, now=_T0)
    _record_probes(monkeypatch)

    await pw._scheduler_tick()
    assert pw._last_bucket["mon-1"] == pw._bucket(60, _T0)

    await pw._scheduler_tick()
    assert len(redis.calls) == 1


async def test_tick_makes_no_claim_when_nothing_is_due(monkeypatch):
    redis = _FakeRedis()
    _patch(monkeypatch, redis, monitors=(), now=_T0)

    await pw._scheduler_tick()
    assert redis.calls == []


async def test_intervals_are_independent(monkeypatch):
    """A 60s and a 300s monitor advance on their own buckets, not together."""
    slow = {**_MONITOR, "id": "mon-slow", "interval_s": 300}
    redis = _FakeRedis()
    _patch(monkeypatch, redis, monitors=(_MONITOR, slow), now=_T0)
    probed = _record_probes(monkeypatch)

    await pw._scheduler_tick()
    assert sorted(probed) == ["mon-1", "mon-slow"]

    monkeypatch.setattr(pw.time, "time", lambda: _T0 + 120.0)   # +2 minutes
    await pw._scheduler_tick()
    assert sorted(probed) == ["mon-1", "mon-1", "mon-slow"]     # slow not due yet


# ── helpers ───────────────────────────────────────────────────────────────────

def _record_probes(monkeypatch) -> list[str]:
    probed: list[str] = []

    async def _fake(monitor):
        probed.append(monitor["id"])

    monkeypatch.setattr(pw, "_run_probe", _fake)
    return probed


def _async_return(value):
    async def _inner(*_a, **_k):
        return value
    return _inner
