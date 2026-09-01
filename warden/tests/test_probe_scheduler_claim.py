"""
warden/tests/test_probe_scheduler_claim.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`probe_scheduler()` is spawned from main.py's lifespan, so it runs once per
uvicorn worker, and `_last_run` is per-process. Production runs --workers 4, so
every monitor was probed four times at the same second — verified in prod as
four `probe_results` rows sharing one timestamp, and `Uptime probe scheduler
started` logged four times per boot.

These tests pin the claim that makes exactly one worker probe, and — just as
importantly — that a Redis outage restores the old duplicate-probe behaviour
rather than taking monitoring dark.
"""
from __future__ import annotations

import pytest

from warden.workers import probe_worker as pw

_MONITOR = {"id": "mon-1", "tenant_id": "t1", "name": "API", "url": "https://x.test/",
            "interval_s": 60, "check_type": "http"}


class _FakeRedis:
    """Records SET calls; grants the first claim per key, denies the rest."""

    def __init__(self, grant: bool = True):
        self.calls: list[dict] = []
        self._held: set[str] = set()
        self._grant = grant

    def set(self, key, value, nx=False, px=None):
        self.calls.append({"key": key, "value": value, "nx": nx, "px": px})
        if not self._grant or key in self._held:
            return None            # redis-py returns None when NX loses
        self._held.add(key)
        return True


@pytest.fixture(autouse=True)
def _reset_last_run():
    pw._last_run.clear()
    yield
    pw._last_run.clear()


def _patch_redis(monkeypatch, client):
    monkeypatch.setattr(pw.cache, "_get_client", lambda: client)


async def test_claim_granted_once_then_denied(monkeypatch):
    """Two workers, one interval: the first claims, the second is refused."""
    redis = _FakeRedis()
    _patch_redis(monkeypatch, redis)

    assert await pw._claim(_MONITOR) is True
    assert await pw._claim(_MONITOR) is False


async def test_claim_ttl_expires_before_next_due(monkeypatch):
    """A full-interval TTL would race the due check — it must be shorter."""
    redis = _FakeRedis()
    _patch_redis(monkeypatch, redis)

    await pw._claim(_MONITOR)

    px = redis.calls[0]["px"]
    assert redis.calls[0]["nx"] is True
    assert px == int(60 * 1000 * pw._CLAIM_TTL_FRACTION)
    assert px < 60 * 1000
    assert redis.calls[0]["key"] == f"{pw._CLAIM_PREFIX}mon-1"


async def test_claim_ttl_has_a_floor(monkeypatch):
    """A sub-second interval must not produce a TTL of 0 (never expiring NX)."""
    redis = _FakeRedis()
    _patch_redis(monkeypatch, redis)

    await pw._claim({**_MONITOR, "interval_s": 0})
    assert redis.calls[0]["px"] >= 1000


async def test_claim_fails_open_when_redis_is_absent(monkeypatch):
    """No Redis: probe anyway (duplicates beat blindness) — and count it."""
    _patch_redis(monkeypatch, None)
    counted: list[tuple] = []
    monkeypatch.setattr(pw, "record_failopen",
                        lambda stage, reason, exc=None: counted.append((stage, reason)))

    assert await pw._claim(_MONITOR) is True
    assert counted == [("probe_claim", pw.Reason.REDIS_UNAVAILABLE)]


async def test_claim_fails_open_when_redis_raises(monkeypatch):
    class _Boom:
        def set(self, *a, **k):
            raise RuntimeError("connection reset")

    _patch_redis(monkeypatch, _Boom())
    counted: list[tuple] = []
    monkeypatch.setattr(pw, "record_failopen",
                        lambda stage, reason, exc=None: counted.append((stage, reason)))

    assert await pw._claim(_MONITOR) is True
    assert counted == [("probe_claim", pw.Reason.BACKEND_ERROR)]


async def test_tick_probes_only_what_it_claimed(monkeypatch):
    """The regression itself: two processes, one probe."""
    redis = _FakeRedis()
    _patch_redis(monkeypatch, redis)
    monkeypatch.setattr(pw, "_load_monitors", _async_return([_MONITOR]))

    probed: list[str] = []

    async def _fake_probe(m):
        probed.append(m["id"])

    monkeypatch.setattr(pw, "_run_probe", _fake_probe)

    await pw._scheduler_tick()          # worker A
    pw._last_run.clear()                # worker B has its own _last_run
    await pw._scheduler_tick()          # worker B — same interval, same key

    assert probed == ["mon-1"]


async def test_tick_advances_last_run_for_the_loser_too(monkeypatch):
    """A loser that kept its old timestamp would re-claim every 5s tick."""
    redis = _FakeRedis(grant=False)
    _patch_redis(monkeypatch, redis)
    monkeypatch.setattr(pw, "_load_monitors", _async_return([_MONITOR]))
    monkeypatch.setattr(pw, "_run_probe", _async_noop)

    await pw._scheduler_tick()
    assert "mon-1" in pw._last_run

    await pw._scheduler_tick()          # not due again — no second claim attempt
    assert len(redis.calls) == 1


async def test_tick_without_due_monitors_makes_no_claim(monkeypatch):
    redis = _FakeRedis()
    _patch_redis(monkeypatch, redis)
    monkeypatch.setattr(pw, "_load_monitors", _async_return([]))

    await pw._scheduler_tick()
    assert redis.calls == []


def _async_return(value):
    async def _inner(*_a, **_k):
        return value
    return _inner


async def _async_noop(*_a, **_k):
    return None
