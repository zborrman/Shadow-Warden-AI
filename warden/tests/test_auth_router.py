"""
The site's account endpoints (warden/auth/router.py), retired 2026-11-26.

In production the site login checked passwords against the portal's own
account table with no second factor and no per-account lockout. Login and
sign-up now answer 410 and point at the portal; nothing in the module issues a
credential. Logout and /me stay so a leftover cookie can be read and cleared.
"""
from __future__ import annotations

import inspect
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.auth import router as auth_router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(auth_router.router)
    return TestClient(app)


def _token(email: str, secret: str) -> str:
    from jose import jwt
    now = int(time.time())
    return jwt.encode({"sub": email, "iat": now, "exp": now + 600}, secret, algorithm="HS256")


# ── retired endpoints ────────────────────────────────────────────────────────

class TestRetiredEndpoints:
    @pytest.mark.parametrize("path, where", [
        ("/auth/login", auth_router.PORTAL_LOGIN_URL),
        ("/auth/signup", auth_router.PORTAL_REGISTER_URL),
    ])
    def test_answers_410_and_points_at_the_portal(self, client, path, where):
        resp = client.post(path, json={"email": "a@example.com", "password": "Valid-Pass-2026!"})
        assert resp.status_code == 410
        assert resp.json()["location"] == where
        assert where in resp.headers["link"]

    @pytest.mark.parametrize("path", ["/auth/login", "/auth/signup"])
    def test_sets_no_cookie_whatever_is_sent(self, client, path):
        for body in ({"email": "a@example.com", "password": "x"}, {}, None):
            resp = client.post(path, json=body)
            assert resp.status_code == 410
            assert not resp.headers.get_list("set-cookie")

    def test_the_module_can_no_longer_issue_a_session(self):
        # A future edit that brings a password check back must fail here first.
        src = inspect.getsource(auth_router)
        for banned in ("set_cookie(", "bcrypt", "find_password_hash", "create_user", "jwt.encode"):
            assert banned not in src, banned

    def test_the_portal_urls_are_https_on_our_domain(self):
        for url in (auth_router.PORTAL_LOGIN_URL, auth_router.PORTAL_REGISTER_URL):
            assert url.startswith("https://portal.shadow-warden-ai.com/")


# ── JWT secret + decode (used by /me for a leftover cookie) ──────────────────

class TestJwtHelpers:
    def test_secret_prefers_auth_jwt_secret(self, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "explicit-secret")
        assert auth_router._secret() == "explicit-secret"

    def test_secret_falls_back_to_vault_master_key(self, monkeypatch):
        monkeypatch.delenv("AUTH_JWT_SECRET", raising=False)
        monkeypatch.setenv("VAULT_MASTER_KEY", "vault-seed")
        monkeypatch.delenv("SAML_JWT_SECRET", raising=False)
        s = auth_router._secret()
        assert s and s != "vault-seed"

    def test_secret_raises_when_unconfigured(self, monkeypatch):
        monkeypatch.delenv("AUTH_JWT_SECRET", raising=False)
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.delenv("SAML_JWT_SECRET", raising=False)
        with pytest.raises(RuntimeError, match="AUTH_JWT_SECRET"):
            auth_router._secret()

    def test_decode_roundtrip(self, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "roundtrip-secret")
        assert auth_router._decode(_token("u@example.com", "roundtrip-secret"))["sub"] == "u@example.com"

    def test_decode_wrong_secret_returns_none(self, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "secret-b")
        assert auth_router._decode(_token("u@example.com", "secret-a")) is None

    def test_decode_unconfigured_secret_returns_none(self, monkeypatch):
        for k in ("AUTH_JWT_SECRET", "VAULT_MASTER_KEY", "SAML_JWT_SECRET"):
            monkeypatch.delenv(k, raising=False)
        assert auth_router._decode("anything") is None

    def test_decode_without_jose_returns_none(self, monkeypatch):
        monkeypatch.setattr(auth_router, "_JOSE_OK", False)
        assert auth_router._decode("anything") is None


# ── logout + me ──────────────────────────────────────────────────────────────

class TestLogoutAndMe:
    def test_logout_clears_cookies(self, client):
        resp = client.post("/auth/logout")
        assert resp.status_code == 200
        set_cookie = resp.headers.get_list("set-cookie")
        assert any(auth_router._COOKIE in c and "Max-Age=0" in c for c in set_cookie)
        assert any("sw_logged_in" in c and "Max-Age=0" in c for c in set_cookie)

    def test_me_without_cookie_returns_401(self, client):
        resp = client.get("/auth/me")
        assert resp.status_code == 401
        assert resp.json()["authenticated"] is False

    def test_me_with_invalid_cookie_returns_401(self, client):
        client.cookies.set(auth_router._COOKIE, "garbage")
        assert client.get("/auth/me").status_code == 401

    def test_me_reads_a_leftover_valid_cookie(self, client, monkeypatch):
        monkeypatch.setenv("AUTH_JWT_SECRET", "test-secret")
        client.cookies.set(auth_router._COOKIE, _token("me@example.com", "test-secret"))
        resp = client.get("/auth/me")
        assert resp.status_code == 200
        assert resp.json()["email"] == "me@example.com"
