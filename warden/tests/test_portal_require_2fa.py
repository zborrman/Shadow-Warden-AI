"""Two-step sign-in is required for every portal account (2026-11-27).

Before this, a password alone opened a full session for any account that had
not turned 2FA on (all eight production accounts), and the only way to turn it
on was from inside that session. Now a password without an authenticator buys
a setup_session that opens /auth/totp/enroll/* and nothing else; the session
and the refresh cookie come only after the first code is confirmed.
"""
from __future__ import annotations

import bcrypt
import pyotp
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import warden.portal_router as pr
from warden.db.connection import get_db
from warden.limiter import limiter

_PW = "Seller-Pass-2026!"


def _user(**kw):
    u = {"id": "u-1", "email": "owner@example.com", "tenant_id": "tenant-a", "role": "owner",
         "password_hash": bcrypt.hashpw(_PW.encode(), bcrypt.gensalt(rounds=4)).decode(),
         "totp_enabled": False, "totp_secret": None}
    u.update(kw)
    return u


class _Rows:
    def mappings(self):
        return self

    def first(self):
        return None


class _DB:
    """Applies the two TOTP writes to the in-memory user, ignores the rest."""

    def __init__(self, users):
        self.users = users

    async def execute(self, stmt, params=None):
        sql, p = str(stmt), dict(params or {})
        for u in self.users.values():
            if u["id"] == p.get("id"):
                if "totp_secret=:s" in sql:
                    u["totp_secret"], u["totp_enabled"] = p["s"], False
                if "totp_enabled=TRUE" in sql:
                    u["totp_enabled"] = True
        return _Rows()

    async def commit(self):
        return None


@pytest.fixture
def make(monkeypatch):
    def _make(**user_kw):
        limiter.reset()
        users = {"owner@example.com": _user(**user_kw)}

        async def by_email(_db, email):
            return users.get(email.lower())

        async def by_id(_db, uid):
            return next((u for u in users.values() if u["id"] == uid), None)

        monkeypatch.setattr(pr, "_get_user_by_email", by_email)
        monkeypatch.setattr(pr, "_get_user_by_id", by_id)
        import warden.limiter as lim
        monkeypatch.setattr(lim, "get_client_ip", lambda r: "203.0.113.7")
        app = FastAPI()
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
        app.include_router(pr.router, prefix="/portal")
        db = _DB(users)
        app.dependency_overrides[get_db] = lambda: db
        return TestClient(app), users
    yield _make
    limiter.reset()


def _login(c):
    return c.post("/portal/auth/login", json={"email": "owner@example.com", "password": _PW})


def test_a_password_without_an_authenticator_opens_no_session(make):
    c, _ = make()
    r = _login(c)
    assert r.status_code == 200
    body = r.json()
    assert body["requires_totp_setup"] is True and body["setup_session"]
    assert "access_token" not in body
    assert not r.headers.get_list("set-cookie"), "no refresh cookie before enrolment"


def test_the_setup_session_is_not_a_session(make):
    c, _ = make()
    setup = _login(c).json()["setup_session"]
    r = c.get("/portal/auth/totp/status", headers={"Authorization": f"Bearer {setup}"})
    assert r.status_code == 401


def test_a_totp_pending_token_is_not_a_session_either(make):
    c, _ = make()
    pending = pr._issue_totp_session("u-1")
    r = c.get("/portal/auth/totp/status", headers={"Authorization": f"Bearer {pending}"})
    assert r.status_code == 401


def test_enrolment_opens_the_session_only_after_a_right_code(make):
    c, users = make()
    setup = _login(c).json()["setup_session"]
    started = c.post("/portal/auth/totp/enroll/start", json={"setup_session": setup})
    assert started.status_code == 200
    secret = started.json()["secret"]
    assert started.json()["otpauth_uri"].startswith("otpauth://totp/")

    wrong = c.post("/portal/auth/totp/enroll/finish", json={"setup_session": setup, "code": "000000"})
    assert wrong.status_code == 400
    assert users["owner@example.com"]["totp_enabled"] is False

    ok = c.post("/portal/auth/totp/enroll/finish",
                json={"setup_session": setup, "code": pyotp.TOTP(secret).now()})
    assert ok.status_code == 200
    assert ok.json()["access_token"]
    assert any(c_.startswith(f"{pr._COOKIE_NAME}=") for c_ in ok.headers.get_list("set-cookie"))
    assert users["owner@example.com"]["totp_enabled"] is True


@pytest.mark.parametrize("kind", ["pending", "access"])
def test_enrolment_takes_only_a_setup_session(make, kind):
    c, _ = make()
    token = pr._issue_totp_session("u-1") if kind == "pending" else pr._issue_access_token("u-1", "tenant-a", "owner")
    r = c.post("/portal/auth/totp/enroll/start", json={"setup_session": token})
    assert r.status_code == 401


def test_an_account_with_an_authenticator_still_gets_the_code_step(make):
    c, _ = make(totp_enabled=True, totp_secret=pyotp.random_base32())
    body = _login(c).json()
    assert body["requires_totp"] is True and "setup_session" not in body


def test_an_old_refresh_cookie_cannot_skip_enrolment(make):
    c, _ = make()
    c.cookies.set(pr._COOKIE_NAME, pr._issue_refresh_token("u-1"))
    r = c.post("/portal/auth/refresh")
    assert r.status_code == 401
    assert any(pr._COOKIE_NAME in h and "Max-Age=0" in h for h in r.headers.get_list("set-cookie"))


def test_a_refresh_with_an_authenticator_still_works(make):
    c, _ = make(totp_enabled=True, totp_secret=pyotp.random_base32())
    c.cookies.set(pr._COOKIE_NAME, pr._issue_refresh_token("u-1"))
    assert c.post("/portal/auth/refresh").status_code == 200
