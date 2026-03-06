"""
warden/tests/test_tenant_rate_limit.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for per-tenant rate limiting.

cache.check_tenant_rate_limit() is tested with a FakeRedis backend so no
real Redis connection is required.  The /filter integration path is covered
by patching check_tenant_rate_limit to verify the 429 is raised correctly.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from warden.cache import check_tenant_rate_limit


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_redis(counts: dict[str, int]):
    """Return a mock Redis client that tracks incr() calls per key."""
    r = MagicMock()

    def _incr(key):
        counts[key] = counts.get(key, 0) + 1
        return counts[key]

    r.incr.side_effect = _incr
    r.expire.return_value = True
    return r


# ── Unit tests for check_tenant_rate_limit ────────────────────────────────────

def test_first_request_allowed():
    counts: dict[str, int] = {}
    r = _make_redis(counts)
    with patch("warden.cache._get_client", return_value=r):
        assert check_tenant_rate_limit("acme", limit=5) is False


def test_at_limit_still_allowed():
    """The Nth request exactly at the limit must be allowed."""
    counts: dict[str, int] = {}
    r = _make_redis(counts)
    with patch("warden.cache._get_client", return_value=r):
        for _ in range(5):
            result = check_tenant_rate_limit("acme", limit=5)
        assert result is False  # 5th request == limit, not over


def test_over_limit_blocked():
    """The (N+1)th request over the limit must be blocked."""
    counts: dict[str, int] = {}
    r = _make_redis(counts)
    with patch("warden.cache._get_client", return_value=r):
        for _ in range(5):
            check_tenant_rate_limit("acme", limit=5)
        assert check_tenant_rate_limit("acme", limit=5) is True  # 6th → blocked


def test_different_tenants_isolated():
    """Each tenant has an independent counter."""
    counts: dict[str, int] = {}
    r = _make_redis(counts)
    with patch("warden.cache._get_client", return_value=r):
        # Exhaust tenant_a's limit
        for _ in range(3):
            check_tenant_rate_limit("tenant_a", limit=3)
        assert check_tenant_rate_limit("tenant_a", limit=3) is True   # blocked

        # tenant_b still fresh
        assert check_tenant_rate_limit("tenant_b", limit=3) is False  # allowed


def test_expire_called_on_first_increment():
    """TTL must be set on the first request (count == 1) to auto-expire keys."""
    counts: dict[str, int] = {}
    r = _make_redis(counts)
    with patch("warden.cache._get_client", return_value=r):
        check_tenant_rate_limit("new_tenant", limit=10)
    r.expire.assert_called_once()
    args = r.expire.call_args[0]
    assert args[1] == 60  # 60-second TTL


def test_expire_not_called_on_subsequent_increments():
    """TTL must only be set on the first increment, not on subsequent ones."""
    counts: dict[str, int] = {}
    r = _make_redis(counts)
    with patch("warden.cache._get_client", return_value=r):
        for _ in range(3):
            check_tenant_rate_limit("existing_tenant", limit=10)
    # expire called only once (first increment)
    assert r.expire.call_count == 1


def test_redis_unavailable_fail_open():
    """When Redis is down the function must return False (fail-open)."""
    with patch("warden.cache._get_client", return_value=None):
        assert check_tenant_rate_limit("acme", limit=1) is False


def test_redis_error_fail_open():
    """Transient Redis errors (network blip, timeout) must not raise."""
    r = MagicMock()
    r.incr.side_effect = Exception("connection reset")
    with patch("warden.cache._get_client", return_value=r):
        assert check_tenant_rate_limit("acme", limit=10) is False


# ── Integration: 429 raised when limit exceeded ───────────────────────────────

@pytest.mark.integration
@pytest.mark.slow
def test_filter_returns_429_when_tenant_rate_exceeded(client):
    """The /filter endpoint must return 429 when check_tenant_rate_limit is True."""
    with patch("warden.main.check_tenant_rate_limit", return_value=True):
        resp = client.post("/filter", json={"content": "hello", "tenant_id": "trial"})
    assert resp.status_code == 429
    assert "rate limit" in resp.json()["detail"].lower()


@pytest.mark.integration
@pytest.mark.slow
def test_filter_passes_when_tenant_rate_ok(client):
    """Normal requests must not be affected when rate limit is not exceeded."""
    with patch("warden.main.check_tenant_rate_limit", return_value=False):
        resp = client.post("/filter", json={"content": "What is 2+2?", "tenant_id": "acme"})
    assert resp.status_code == 200
