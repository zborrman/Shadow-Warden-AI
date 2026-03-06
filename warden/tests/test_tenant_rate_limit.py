"""
warden/tests/test_tenant_rate_limit.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for per-tenant rate limiting (token-bucket algorithm).

check_tenant_rate_limit() now executes an atomic Redis Lua script.
Tests mock r.eval() — no real Redis connection required.
The /filter integration path is covered by patching check_tenant_rate_limit
to verify the 429 is raised correctly.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from warden.cache import check_tenant_rate_limit


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_redis(eval_return: int = 1):
    """Return a mock Redis client with a fixed eval() return value.

    eval_return=1  →  token consumed, request allowed.
    eval_return=0  →  bucket empty, request blocked.
    """
    r = MagicMock()
    r.eval.return_value = eval_return
    return r


# ── Unit tests for check_tenant_rate_limit ────────────────────────────────────

def test_allowed_when_eval_returns_1():
    """Lua returning 1 (token consumed) → function returns False (allow)."""
    r = _make_redis(eval_return=1)
    with patch("warden.cache._get_client", return_value=r):
        assert check_tenant_rate_limit("acme", limit=60) is False


def test_blocked_when_eval_returns_0():
    """Lua returning 0 (bucket empty) → function returns True (block)."""
    r = _make_redis(eval_return=0)
    with patch("warden.cache._get_client", return_value=r):
        assert check_tenant_rate_limit("acme", limit=60) is True


def test_eval_called_with_correct_key():
    """Redis key must be warden:tokens:{tenant_id}."""
    r = _make_redis()
    with patch("warden.cache._get_client", return_value=r):
        check_tenant_rate_limit("my-tenant", limit=30)
    # positional args: (script, numkeys, KEYS[1], ARGV[1..4])
    assert r.eval.call_args[0][2] == "warden:tokens:my-tenant"


def test_eval_capacity_equals_limit():
    """ARGV[1] (capacity) must equal the limit passed in."""
    r = _make_redis()
    with patch("warden.cache._get_client", return_value=r):
        check_tenant_rate_limit("acme", limit=100)
    capacity = r.eval.call_args[0][3]  # ARGV[1]
    assert float(capacity) == 100.0


def test_eval_refill_rate_is_limit_per_60():
    """ARGV[2] (refill_rate) must equal limit / 60."""
    r = _make_redis()
    with patch("warden.cache._get_client", return_value=r):
        check_tenant_rate_limit("acme", limit=120)
    refill_rate = r.eval.call_args[0][4]  # ARGV[2]
    assert abs(float(refill_rate) - 120 / 60.0) < 1e-9


def test_eval_ttl_is_120():
    """ARGV[4] (TTL) must be 120 seconds so idle buckets auto-expire."""
    r = _make_redis()
    with patch("warden.cache._get_client", return_value=r):
        check_tenant_rate_limit("acme", limit=60)
    ttl = r.eval.call_args[0][6]  # ARGV[4]
    assert ttl == 120


def test_different_tenants_isolated():
    """Each tenant maps to a distinct Redis key."""
    r = _make_redis(eval_return=1)
    with patch("warden.cache._get_client", return_value=r):
        check_tenant_rate_limit("tenant_a", limit=5)
        check_tenant_rate_limit("tenant_b", limit=5)
    calls = r.eval.call_args_list
    key_a = calls[0][0][2]
    key_b = calls[1][0][2]
    assert key_a == "warden:tokens:tenant_a"
    assert key_b == "warden:tokens:tenant_b"
    assert key_a != key_b


def test_sequential_allowed_then_blocked():
    """Simulate bucket draining: first call allowed, second blocked."""
    r = MagicMock()
    r.eval.side_effect = [1, 0]  # first call: token available; second: empty
    with patch("warden.cache._get_client", return_value=r):
        assert check_tenant_rate_limit("acme", limit=1) is False  # allowed
        assert check_tenant_rate_limit("acme", limit=1) is True   # blocked


def test_redis_unavailable_fail_open():
    """When Redis is down the function must return False (fail-open)."""
    with patch("warden.cache._get_client", return_value=None):
        assert check_tenant_rate_limit("acme", limit=1) is False


def test_redis_error_fail_open():
    """Transient Redis errors (network blip, timeout) must not raise."""
    r = MagicMock()
    r.eval.side_effect = Exception("connection reset")
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
