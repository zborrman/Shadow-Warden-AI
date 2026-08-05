"""
HttpOnly-cookie session auth (warden/auth/router.py) — the SQLite user store,
JWT issue/decode helpers, and the four endpoints (login/signup/logout/me).

Rate-limit behaviour has its own file (test_auth_rate_limit.py); this file
covers everything else: credential validation, cookie issuance, the DB and
env-var user stores, and the JWT secret fallback chain.
"""
from __future__ import annotations

import time

import bcrypt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.auth import router as auth_router


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Point the SQLite user store at a throwaway file per test."""
    # D-4: patch the settings field, not a module constant. warden/auth/router.py
    # and warden/auth/user_store.py both resolve this path per call from the same
    # place; patching one module's snapshot would point them at two files.
    monkeypatch.setattr(auth_router.settings, "auth_db_path", str(tmp_path / "test_auth.db"))
    # Pin the Postgres side too: without this a developer who happens to have
    # DATABASE_URL exported runs these against a real database.
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with auth_router._rate_lock:
        auth_router._rate_store.clear()
    yield
    with auth_router._rate_lock:
        auth_router._rate_store.clear()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(auth_router.router)
    return TestClient(app)


# ── SQLite user store ────────────────────────────────────────────────────────

class TestDbUserStore:
    def test_create_then_get_roundtrip(self):
        ok = auth_router._db_create_user("alice@example.com", "hash123")
        assert ok is True
        assert auth_router._db_get_user("alice@example.com") == "hash123"

    def test_get_missing_user_returns_none(self):
        assert auth_router._db_get_user("nobody@example.com") is None

    def test_create_duplicate_email_returns_false(self):
        assert auth_router._db_create_user("bob@example.com", "h1") is True
        assert auth_router._db_create_user("bob@example.com", "h2") is False

    def test_email_lookup_is_case_insensitive(self):
        auth_router._db_create_user("Carol@Example.com", "h1")
        assert auth_router._db_get_user("carol@example.com") == "h1"

    def test_db_get_user_error_returns_none(self, monkeypatch):
        def _boom():
            raise RuntimeError("disk full")

        monkeypatch.setattr(auth_router, "_db", _boom)
        assert auth_router._db_get_user("x@example.com") is None

    def test_db_create_user_error_returns_false(self, monkeypatch):
        def _boom():
            raise RuntimeError("disk full")

        monkeypatch.setattr(auth_router, "_db", _boom)
        assert auth_router._db_create_user("x@example.com", "h") is False


# ── Env-var user store ───────────────────────────────────────────────────────

class TestEnvUsers:
    def test_empty_by_default(self, monkeypatch):
        monkeypatch.setattr(auth_router.settings, "auth_users_json", "")
        monkeypatch.setattr(auth_router.settings, "auth_admin_email", "")
        monkeypatch.setattr(auth_router.settings, "auth_admin_password_hash", "")
        assert auth_router._load_env_users() == {}

    def test_auth_users_json_parsed(self, monkeypatch):
        monkeypatch.setattr(
            auth_router.settings, "auth_users_json",
            '[{"email": "Dana@Example.com", "password_hash": "hh"}]',
        )
        users = auth_router._load_env_users()
        assert users == {"dana@example.com": "hh"}

    def test_auth_users_json_malformed_falls_back(self, monkeypatch):
        monkeypatch.setattr(auth_router.settings, "auth_users_json", "not json")
        monkeypatch.setattr(auth_router.settings, "auth_admin_email", "admin@example.com")
        monkeypatch.setattr(auth_router.settings, "auth_admin_password_hash", "adminhash")
        users = auth_router._load_env_users()
        assert users == {"admin@example.com": "adminhash"}

    def test_admin_single_user_shortcut(self, monkeypatch):
        monkeypatch.setattr(auth_router.settings, "auth_users_json", "")
        monkeypatch.setattr(auth_router.settings, "auth_admin_email", "Root@Example.com")
        monkeypatch.setattr(auth_router.settings, "auth_admin_password_hash", "roothash")
        assert auth_router._load_env_users() == {"root@example.com": "roothash"}

    def test_email_exists_checks_both_stores(self, monkeypatch):
        monkeypatch.setattr(auth_router.settings, "auth_users_json", "")
        monkeypatch.setattr(auth_router.settings, "auth_admin_email", "")
        monkeypatch.setattr(auth_router.settings, "auth_admin_password_hash", "")
        auth_router._db_create_user("db-user@example.com", "h")
        assert auth_router._email_exists("db-user@example.com") is True
        assert auth_router._email_exists("nobody@example.com") is False

    def test_lookup_password_hash_prefers_db(self, monkeypatch):
        monkeypatch.setattr(auth_router.settings, "auth_users_json", "")
        monkeypatch.setattr(auth_router.settings, "auth_admin_email", "shared@example.com")
        monkeypatch.setattr(auth_router.settings, "auth_admin_password_hash", "env-hash")
        auth_router._db_create_user("shared@example.com", "db-hash")
        assert auth_router._lookup_password_hash("shared@example.com") == "db-hash"

    def test_lookup_password_hash_falls_back_to_env(self, monkeypatch):
        monkeypatch.setattr(auth_router.settings, "auth_users_json", "")
        monkeypatch.setattr(auth_router.settings, "auth_admin_email", "envonly@example.com")
        monkeypatch.setattr(auth_router.settings, "auth_admin_password_hash", "env-hash")
        assert auth_router._lookup_password_hash("envonly@example.com") == "env-hash"


# ── JWT helpers ──────────────────────────────────────────────────────────────

class TestJwtHelpers:
    def test_secret_prefers_auth_jwt_secret(self, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "explicit-secret")
        assert auth_router._secret() == "explicit-secret"

    def test_secret_falls_back_to_vault_master_key(self, monkeypatch):
        monkeypatch.delenv("AUTH_JWT_SECRET", raising=False)
        monkeypatch.setenv("VAULT_MASTER_KEY", "vault-seed")
        monkeypatch.delenv("SAML_JWT_SECRET", raising=False)
        s = auth_router._secret()
        assert s and s != "vault-seed"  # derived (sha256), not the raw seed

    def test_secret_falls_back_to_saml_jwt_secret(self, monkeypatch):
        monkeypatch.delenv("AUTH_JWT_SECRET", raising=False)
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.setenv("SAML_JWT_SECRET", "saml-seed")
        assert auth_router._secret()

    def test_secret_raises_when_unconfigured(self, monkeypatch):
        monkeypatch.delenv("AUTH_JWT_SECRET", raising=False)
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.delenv("SAML_JWT_SECRET", raising=False)
        with pytest.raises(RuntimeError, match="AUTH_JWT_SECRET"):
            auth_router._secret()

    def test_issue_and_decode_roundtrip(self, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "roundtrip-secret")
        token = auth_router._issue("user@example.com")
        payload = auth_router._decode(token)
        assert payload is not None
        assert payload["sub"] == "user@example.com"

    def test_decode_invalid_token_returns_none(self, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "roundtrip-secret")
        assert auth_router._decode("not-a-jwt") is None

    def test_decode_wrong_secret_returns_none(self, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "secret-a")
        token = auth_router._issue("user@example.com")
        monkeypatch.setenv("AUTH_JWT_SECRET", "secret-b")
        assert auth_router._decode(token) is None

    def test_issue_without_jose_raises(self, monkeypatch):
        monkeypatch.setattr(auth_router, "_JOSE_OK", False)
        with pytest.raises(RuntimeError, match="python-jose"):
            auth_router._issue("user@example.com")

    def test_decode_without_jose_returns_none(self, monkeypatch):
        monkeypatch.setattr(auth_router, "_JOSE_OK", False)
        assert auth_router._decode("anything") is None


# ── /auth/signup ─────────────────────────────────────────────────────────────

class TestSignupEndpoint:
    def test_signup_success_sets_cookies(self, client, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "test-secret")
        resp = client.post(
            "/auth/signup", json={"email": "new@example.com", "password": "longenough"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["email"] == "new@example.com"
        assert body["created"] is True
        # The cookie's explicit `domain=.shadow-warden-ai.com` means httpx's
        # cookie jar won't attach it to a testserver-host response — assert on
        # the raw Set-Cookie headers instead.
        set_cookie = resp.headers.get_list("set-cookie")
        assert any(c.startswith(f"{auth_router._COOKIE}=") for c in set_cookie)
        assert any(c.startswith("sw_logged_in=1") for c in set_cookie)

    def test_signup_invalid_json_returns_400(self, client):
        resp = client.post("/auth/signup", content=b"not json")
        assert resp.status_code == 400

    def test_signup_invalid_email_returns_422(self, client):
        resp = client.post(
            "/auth/signup", json={"email": "not-an-email", "password": "longenough"}
        )
        assert resp.status_code == 422

    def test_signup_short_password_returns_422(self, client):
        resp = client.post(
            "/auth/signup", json={"email": "short@example.com", "password": "short"}
        )
        assert resp.status_code == 422

    def test_signup_duplicate_email_returns_409(self, client, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "test-secret")
        payload = {"email": "dup@example.com", "password": "longenough"}
        assert client.post("/auth/signup", json=payload).status_code == 200
        resp2 = client.post("/auth/signup", json=payload)
        assert resp2.status_code == 409

    def test_signup_db_race_returns_409(self, client, monkeypatch):
        """_email_exists can miss a concurrent insert; the store's own uniqueness
        check (surfaced via user_store.create_user returning False) is the real
        guard — exercise that path directly.

        D-4 moved that seam from _db_create_user to user_store.create_user, which
        now applies the same guarantee across both the Postgres and SQLite
        backends."""
        monkeypatch.setenv("AUTH_JWT_SECRET", "test-secret")
        monkeypatch.setattr(auth_router, "_email_exists", lambda email: False)
        monkeypatch.setattr(auth_router.user_store, "create_user", lambda email, h: False)
        resp = client.post(
            "/auth/signup", json={"email": "race@example.com", "password": "longenough"}
        )
        assert resp.status_code == 409

    def test_signup_bcrypt_failure_returns_500(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("bcrypt broke")

        monkeypatch.setattr(auth_router.bcrypt, "hashpw", _boom)
        resp = client.post(
            "/auth/signup", json={"email": "boom@example.com", "password": "longenough"}
        )
        assert resp.status_code == 500

    def test_signup_returns_429_once_the_limit_is_hit(self, client, monkeypatch):
        # _rate_check's `limit` default is bound at module-def time to
        # settings.auth_signup_rate_limit — monkeypatching _SIGNUP_RATE_LIMIT
        # after the fact does not change it, so drive the loop off the real
        # default instead (same approach as test_signup_defaults_are_unchanged
        # in test_auth_rate_limit.py).
        limit = auth_router._SIGNUP_RATE_LIMIT
        for i in range(limit):
            resp = client.post(
                "/auth/signup",
                json={"email": f"u{i}@example.com", "password": "longenough"},
            )
            assert resp.status_code == 200
        resp = client.post(
            "/auth/signup",
            json={"email": "onemore@example.com", "password": "longenough"},
        )
        assert resp.status_code == 429

    def test_signup_token_issue_failure_returns_500(self, client, monkeypatch):
        monkeypatch.delenv("AUTH_JWT_SECRET", raising=False)
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.delenv("SAML_JWT_SECRET", raising=False)
        resp = client.post(
            "/auth/signup", json={"email": "nosecret@example.com", "password": "longenough"}
        )
        assert resp.status_code == 500


# ── /auth/login ──────────────────────────────────────────────────────────────

class TestLoginEndpoint:
    def test_login_success_sets_cookies(self, client, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "test-secret")
        pw_hash = bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode()
        auth_router._db_create_user("login@example.com", pw_hash)

        resp = client.post(
            "/auth/login", json={"email": "login@example.com", "password": "correct-password"}
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "login@example.com"
        set_cookie = resp.headers.get_list("set-cookie")
        assert any(c.startswith(f"{auth_router._COOKIE}=") for c in set_cookie)

    def test_login_unknown_email_returns_401(self, client):
        resp = client.post(
            "/auth/login", json={"email": "ghost@example.com", "password": "whatever"}
        )
        assert resp.status_code == 401

    def test_login_wrong_password_returns_401(self, client):
        pw_hash = bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode()
        auth_router._db_create_user("wrongpw@example.com", pw_hash)
        resp = client.post(
            "/auth/login", json={"email": "wrongpw@example.com", "password": "nope"}
        )
        assert resp.status_code == 401

    def test_login_malformed_hash_treated_as_invalid(self, client):
        # A corrupt stored hash must fail closed (401), not raise 500.
        auth_router._db_create_user("corrupt@example.com", "not-a-bcrypt-hash")
        resp = client.post(
            "/auth/login", json={"email": "corrupt@example.com", "password": "whatever"}
        )
        assert resp.status_code == 401

    def test_login_invalid_json_returns_400(self, client):
        resp = client.post("/auth/login", content=b"not json")
        assert resp.status_code == 400

    def test_login_token_issue_failure_returns_500(self, client, monkeypatch):
        pw_hash = bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode()
        auth_router._db_create_user("nosecret2@example.com", pw_hash)
        monkeypatch.delenv("AUTH_JWT_SECRET", raising=False)
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.delenv("SAML_JWT_SECRET", raising=False)
        resp = client.post(
            "/auth/login",
            json={"email": "nosecret2@example.com", "password": "correct-password"},
        )
        assert resp.status_code == 500


# ── /auth/logout, /auth/me ───────────────────────────────────────────────────

class TestLogoutAndMe:
    def test_logout_clears_cookies(self, client):
        resp = client.post("/auth/logout")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        set_cookie = resp.headers.get_list("set-cookie")
        assert any(auth_router._COOKIE in c and "Max-Age=0" in c for c in set_cookie)

    def test_me_without_cookie_returns_401(self, client):
        resp = client.get("/auth/me")
        assert resp.status_code == 401
        assert resp.json()["authenticated"] is False

    def test_me_with_invalid_cookie_returns_401(self, client):
        client.cookies.set(auth_router._COOKIE, "garbage")
        resp = client.get("/auth/me")
        assert resp.status_code == 401

    def test_me_with_valid_cookie_returns_authenticated(self, client, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "test-secret")
        token = auth_router._issue("me@example.com")
        client.cookies.set(auth_router._COOKIE, token)
        resp = client.get("/auth/me")
        assert resp.status_code == 200
        body = resp.json()
        assert body["authenticated"] is True
        assert body["email"] == "me@example.com"
        assert body["exp"] > time.time()
