"""
Portal account export and closure (GDPR Art. 15/17/20).

Closing asks for the password (and the authenticator code when 2FA is on) and
a typed DELETE; the last owner of a tenant takes the store data and API keys
with them, anyone else only their own login.
"""
from __future__ import annotations

from datetime import UTC, datetime

import bcrypt
import pyotp
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import warden.portal_router as pr
from warden.db.connection import get_db
from warden.limiter import limiter

PW = "correct horse battery"
_USER = {
    "id": "u1", "email": "seller@example.org", "display_name": "Seller", "tenant_id": "t1",
    "role": "owner", "password_hash": bcrypt.hashpw(PW.encode(), bcrypt.gensalt(4)).decode(),
    "totp_enabled": False, "totp_secret": None, "created_at": datetime(2026, 11, 1, tzinfo=UTC),
}


class _Rows:
    def __init__(self, row):
        self._row = row

    def mappings(self):
        return self

    def first(self):
        return self._row


class _DB:
    def __init__(self, others: int = 0):
        self.others = others
        self.calls: list[str] = []
        self.committed = False

    async def execute(self, stmt, params=None):
        self.calls.append(" ".join(str(stmt).split()))
        return _Rows({"n": self.others} if "COUNT(*)" in str(stmt) else None)

    async def commit(self):
        self.committed = True


def _client(monkeypatch, db, user=None, role="owner"):
    limiter.reset()
    u = dict(user or _USER)

    async def by_id(_db, uid):
        return u if uid == u["id"] else None

    purged: list[str] = []
    monkeypatch.setattr(pr, "_get_user_by_id", by_id)
    monkeypatch.setattr(pr, "purge_tenant", lambda t: purged.append(t) or {"products": 2})
    monkeypatch.setattr(pr, "export_tenant", lambda t: {"tenant_id": t, "stores": []})
    app = FastAPI()
    app.state.limiter = limiter
    app.include_router(pr.router, prefix="/portal")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[pr.require_portal_user] = lambda: pr._PortalUser(
        user_id=u["id"], tenant_id=u["tenant_id"], role=role)
    return TestClient(app), purged


def _close(c, **body):
    return c.post("/portal/me/close", json={"password": PW, "confirm": "DELETE"} | body)


def test_export_returns_the_account_and_its_stores(monkeypatch):
    c, _ = _client(monkeypatch, _DB())
    r = c.get("/portal/me/export")
    assert r.status_code == 200
    assert r.json()["account"]["email"] == "seller@example.org"
    assert r.json()["stores"] == []


def test_the_last_owner_takes_store_data_keys_and_login(monkeypatch):
    db = _DB(others=0)
    c, purged = _client(monkeypatch, db)
    r = _close(c)
    assert r.status_code == 200, r.text
    assert r.json() == {"closed": True, "store_data_removed": True}
    assert purged == ["t1"]
    assert any("DELETE FROM warden_core.portal_api_keys WHERE tenant_id" in s for s in db.calls)
    assert any("DELETE FROM warden_core.portal_users WHERE id" in s for s in db.calls)
    assert db.committed
    assert "warden_refresh" in r.headers.get("set-cookie", "")


def test_a_teammate_only_removes_their_own_login(monkeypatch):
    db = _DB(others=1)
    c, purged = _client(monkeypatch, db)
    assert _close(c).json()["store_data_removed"] is False
    assert purged == []
    assert not any("DELETE FROM warden_core.portal_api_keys" in s for s in db.calls)
    assert any("SET created_by=NULL" in s for s in db.calls)


@pytest.mark.parametrize("body,status", [
    ({"password": "wrong"}, 401),
    ({"confirm": "delete"}, 422),
    ({"confirm": ""}, 422),
])
def test_nothing_is_removed_without_password_and_confirmation(monkeypatch, body, status):
    db = _DB()
    c, purged = _client(monkeypatch, db)
    assert _close(c, **body).status_code == status
    assert purged == [] and not db.committed


def test_two_factor_accounts_need_a_current_code(monkeypatch):
    secret = pyotp.random_base32()
    db = _DB()
    c, purged = _client(monkeypatch, db, user=_USER | {"totp_enabled": True, "totp_secret": secret})
    assert _close(c).status_code == 401
    assert _close(c, totp_code="000000").status_code == 401
    assert purged == []
    assert _close(c, totp_code=pyotp.TOTP(secret).now()).status_code == 200
    assert purged == ["t1"]
