"""
Credential-stuffing gate on the cookie-auth endpoints.

`/auth/login` previously had no rate limit at any layer: the Cloudflare custom
rule named "Bypass API" matched `contains "/api/"` — which is the same-origin
auth proxy path — and skipped all rate limiting rules, while nothing in-app
counted attempts. These tests pin the in-app half so the edge is defence in
depth rather than the only control.
"""
from __future__ import annotations

import pytest

from warden.auth import router as auth_router


@pytest.fixture(autouse=True)
def _clear_counters():
    with auth_router._rate_lock:
        auth_router._rate_store.clear()
    yield
    with auth_router._rate_lock:
        auth_router._rate_store.clear()


class TestRateCheck:
    def test_allows_up_to_the_limit(self):
        assert all(
            auth_router._rate_check("198.51.100.1", limit=3, window=60, bucket="login")
            for _ in range(3)
        )

    def test_blocks_past_the_limit(self):
        for _ in range(3):
            auth_router._rate_check("198.51.100.1", limit=3, window=60, bucket="login")
        assert (
            auth_router._rate_check("198.51.100.1", limit=3, window=60, bucket="login")
            is False
        )

    def test_buckets_are_independent(self):
        """A login flood must not spend the signup allowance, or vice versa."""
        for _ in range(3):
            auth_router._rate_check("198.51.100.1", limit=3, window=60, bucket="login")

        assert (
            auth_router._rate_check("198.51.100.1", limit=3, window=60, bucket="login")
            is False
        )
        assert (
            auth_router._rate_check("198.51.100.1", limit=3, window=60, bucket="signup")
            is True
        )

    def test_callers_are_independent(self):
        for _ in range(3):
            auth_router._rate_check("198.51.100.1", limit=3, window=60, bucket="login")

        assert (
            auth_router._rate_check("198.51.100.2", limit=3, window=60, bucket="login")
            is True
        )

    def test_old_attempts_fall_out_of_the_window(self):
        import time

        auth_router._rate_check("198.51.100.1", limit=1, window=60, bucket="login")
        with auth_router._rate_lock:
            # age the recorded attempt past the window
            auth_router._rate_store["login:198.51.100.1"] = [time.time() - 120]

        assert (
            auth_router._rate_check("198.51.100.1", limit=1, window=60, bucket="login")
            is True
        )

    def test_signup_defaults_are_unchanged(self):
        """Default args must still express the original signup-only behaviour."""
        limit = auth_router._SIGNUP_RATE_LIMIT
        for _ in range(limit):
            assert auth_router._rate_check("198.51.100.9") is True
        assert auth_router._rate_check("198.51.100.9") is False


class TestStoreIsBounded:
    """The counter store must not grow once per distinct source address.

    Keying on the real client IP (rather than the one constant proxy address it
    used to see) means an attacker rotating addresses would otherwise allocate a
    dict entry per request, forever.
    """

    def test_aged_out_buckets_are_dropped(self, monkeypatch):
        import time

        monkeypatch.setattr(auth_router, "_RATE_STORE_MAX_KEYS", 5)
        stale = time.time() - (auth_router._SIGNUP_RATE_WINDOW + 60)

        with auth_router._rate_lock:
            for i in range(50):
                auth_router._rate_store[f"login:198.51.100.{i}"] = [stale]

        auth_router._rate_check("203.0.113.1", limit=3, window=60, bucket="login")

        assert len(auth_router._rate_store) == 1
        assert "login:203.0.113.1" in auth_router._rate_store

    def test_active_buckets_are_capped(self, monkeypatch):
        import time

        monkeypatch.setattr(auth_router, "_RATE_STORE_MAX_KEYS", 10)
        now = time.time()

        with auth_router._rate_lock:
            for i in range(50):
                # all fresh — nothing has aged out, so the cap must bite
                auth_router._rate_store[f"login:198.51.100.{i}"] = [now - i]

        auth_router._rate_check("203.0.113.1", limit=3, window=60, bucket="login")

        assert len(auth_router._rate_store) <= 11

    def test_sweep_keeps_the_most_recently_active(self, monkeypatch):
        import time

        monkeypatch.setattr(auth_router, "_RATE_STORE_MAX_KEYS", 3)
        now = time.time()

        with auth_router._rate_lock:
            for i in range(10):
                auth_router._rate_store[f"login:198.51.100.{i}"] = [now - i]
            auth_router._sweep_rate_store(now)

        # lower index == more recent timestamp == kept
        assert "login:198.51.100.0" in auth_router._rate_store
        assert "login:198.51.100.9" not in auth_router._rate_store

    def test_limit_still_enforced_while_sweeping(self, monkeypatch):
        """A sweep must never hand an over-limit caller a fresh allowance."""
        import time

        monkeypatch.setattr(auth_router, "_RATE_STORE_MAX_KEYS", 2)
        now = time.time()

        for _ in range(3):
            auth_router._rate_check("203.0.113.7", limit=3, window=60, bucket="login")

        with auth_router._rate_lock:
            for i in range(20):
                auth_router._rate_store[f"login:198.51.100.{i}"] = [now]

        assert (
            auth_router._rate_check("203.0.113.7", limit=3, window=60, bucket="login")
            is False
        )


class TestLoginEndpoint:
    def test_login_returns_429_once_the_limit_is_hit(self, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        monkeypatch.setattr(auth_router, "_LOGIN_RATE_LIMIT", 3)
        monkeypatch.setattr(auth_router, "_LOGIN_RATE_WINDOW", 60)

        app = FastAPI()
        app.include_router(auth_router.router)
        client = TestClient(app)

        payload = {"email": "nobody@example.com", "password": "wrong-password"}

        # Wrong credentials → 401, but each attempt is still counted.
        for _ in range(3):
            assert client.post("/auth/login", json=payload).status_code == 401

        assert client.post("/auth/login", json=payload).status_code == 429

    def test_limit_applies_before_credential_check(self, monkeypatch):
        """429 must not depend on the password being wrong — otherwise a valid
        credential gives an attacker an unmetered oracle."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        monkeypatch.setattr(auth_router, "_LOGIN_RATE_LIMIT", 1)
        monkeypatch.setattr(auth_router, "_LOGIN_RATE_WINDOW", 60)

        app = FastAPI()
        app.include_router(auth_router.router)
        client = TestClient(app)

        client.post("/auth/login", json={"email": "a@example.com", "password": "x"})
        # Second call is refused before any lookup happens — even malformed JSON.
        assert client.post("/auth/login", content=b"not json").status_code == 429
