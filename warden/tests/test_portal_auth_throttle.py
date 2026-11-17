"""
The portal's sign-in routes are throttled, per address and per account.

Re-audit 2026-11-16: ``/portal/auth/login``, ``/register``, ``/totp/complete``,
``/forgot-password`` and ``/reset-password`` had no limit of any kind, so a
password or a six-digit authenticator code could be guessed at line rate. Login
also answered an unknown email faster than a known one (no bcrypt ran), which
told an attacker which addresses had accounts. Reset tokens were stored as
issued, so a database read yielded working reset links.
"""
from __future__ import annotations

import hashlib

import bcrypt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import warden.portal_router as pr
from warden.db.connection import get_db
from warden.limiter import limiter

_PW = "correct horse battery"
_USER = {
    "id": "u-1", "email": "owner@example.com", "tenant_id": "tenant-a", "role": "owner",
    "password_hash": bcrypt.hashpw(_PW.encode(), bcrypt.gensalt(rounds=4)).decode(),
    "totp_enabled": False, "totp_secret": None,
}


class _Rows:
    def __init__(self, row):
        self._row = row

    def mappings(self):
        return self

    def first(self):
        return self._row


class _DB:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    async def execute(self, stmt, params=None):
        self.calls.append((str(stmt), dict(params or {})))
        return _Rows(None)

    async def commit(self):
        return None


@pytest.fixture
def db():
    return _DB()


@pytest.fixture
def client(db, monkeypatch):
    limiter.reset()
    users = {_USER["email"]: dict(_USER)}

    async def by_email(_db, email):
        return users.get(email.lower())

    async def by_id(_db, uid):
        return next((u for u in users.values() if u["id"] == uid), None)

    monkeypatch.setattr(pr, "_get_user_by_email", by_email)
    monkeypatch.setattr(pr, "_get_user_by_id", by_id)
    monkeypatch.setattr(pr, "_issue_access_token", lambda *a: "access")
    monkeypatch.setattr(pr, "_issue_refresh_token", lambda *a: "refresh")
    # TestClient's peer is not a trusted proxy; let the header stand in for it.
    import warden.limiter as lim

    monkeypatch.setattr(lim, "get_client_ip", lambda r: r.headers.get("x-forwarded-for", "t"))
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
    app.include_router(pr.router, prefix="/portal")
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app), users
    limiter.reset()


def _login(c, email, pw, ip):
    return c.post("/portal/auth/login", json={"email": email, "password": pw},
                  headers={"X-Forwarded-For": ip})


def test_one_address_gets_ten_login_attempts_a_minute(client):
    c, _ = client
    codes = [_login(c, f"x{i}@example.com", "nope", "10.0.0.1").status_code for i in range(11)]
    assert codes[:10] == [401] * 10
    assert codes[10] == 429


def test_an_account_locks_after_ten_failures_from_any_address(client):
    c, _ = client
    for i in range(10):
        assert _login(c, _USER["email"], "wrong", f"10.1.0.{i}").status_code == 401
    # The right password, from a fresh address, is refused while the lock holds.
    locked = _login(c, _USER["email"], _PW, "10.2.0.1")
    assert locked.status_code == 429
    assert locked.headers["Retry-After"] == "900"
    # Another account is unaffected.
    assert _login(c, "other@example.com", "x", "10.2.0.2").status_code == 401


def test_the_lockout_says_nothing_about_whether_the_email_exists(client):
    c, _ = client
    for i in range(10):
        _login(c, "nobody@example.com", "wrong", f"10.3.0.{i}")
    assert _login(c, "nobody@example.com", "wrong", "10.4.0.1").status_code == 429


def test_an_unknown_email_still_runs_bcrypt(client, monkeypatch):
    c, _ = client
    seen: list[bytes] = []
    real = bcrypt.checkpw
    monkeypatch.setattr(pr.bcrypt, "checkpw", lambda pw, h: seen.append(h) or real(pw, h))
    assert _login(c, "nobody@example.com", "pw", "10.5.0.1").status_code == 401
    assert seen and seen[0].startswith(b"$2")


def test_the_right_password_still_signs_in(client):
    c, _ = client
    resp = _login(c, _USER["email"], _PW, "10.6.0.1")
    assert resp.status_code == 200, resp.text
    assert resp.json()["access_token"] == "access"


def test_authenticator_codes_lock_after_five_wrong_guesses(client, monkeypatch):
    import pyotp

    c, users = client
    secret = pyotp.random_base32()
    users[_USER["email"]].update(totp_enabled=True, totp_secret=secret)
    monkeypatch.setattr(pr, "_decode_token", lambda t: {"type": "totp_pending", "sub": "u-1"})
    good = pyotp.TOTP(secret).now()
    bad = f"{(int(good) + 500_000) % 1_000_000:06d}"

    def guess(code, ip):
        return c.post("/portal/auth/totp/complete", json={"totp_session": "s", "code": code},
                      headers={"X-Forwarded-For": ip})

    for i in range(5):
        assert guess(bad, f"10.7.0.{i}").status_code == 401
    assert guess(good, "10.8.0.1").status_code == 429


def test_register_and_recovery_are_limited_per_address(client):
    c, _ = client
    hdr = {"X-Forwarded-For": "10.9.0.1"}
    reg = [c.post("/portal/auth/register",
                  json={"email": f"n{i}@example.com", "password": "longenough"},
                  headers=hdr).status_code for i in range(6)]
    assert reg[:5] == [201] * 5 and reg[5] == 429
    fp = [c.post("/portal/auth/forgot-password", json={"email": "a@example.com"},
                 headers={"X-Forwarded-For": "10.9.0.2"}).status_code for _ in range(6)]
    assert fp[:5] == [202] * 5 and fp[5] == 429


def test_reset_tokens_are_stored_hashed(client, db, monkeypatch):
    c, _ = client
    sent: list[str] = []

    async def capture(_to, token):
        sent.append(token)

    monkeypatch.setattr(pr, "_send_password_reset_email", capture)
    assert c.post("/portal/auth/forgot-password", json={"email": _USER["email"]},
                  headers={"X-Forwarded-For": "10.10.0.1"}).status_code == 202
    stored = [p["t"] for sql, p in db.calls if "reset_token=:t" in sql]
    assert sent and stored
    assert stored[0] != sent[0]
    assert stored[0] == hashlib.sha256(sent[0].encode()).hexdigest()

    c.post("/portal/auth/reset-password", json={"token": sent[0], "new_password": "newpassword1"},
           headers={"X-Forwarded-For": "10.10.0.2"})
    looked_up = [p["t"] for sql, p in db.calls if "WHERE reset_token = :t" in sql]
    assert looked_up == [stored[0]]


def test_no_reset_token_reaches_the_log(caplog, monkeypatch):
    import asyncio

    monkeypatch.setattr(pr, "_SMTP_HOST", "")
    with caplog.at_level("DEBUG", logger="warden.portal"):
        asyncio.run(pr._send_password_reset_email("owner@example.com", "TOKEN-123"))
    text = caplog.text
    assert "TOKEN-123" not in text and "owner@example.com" not in text
