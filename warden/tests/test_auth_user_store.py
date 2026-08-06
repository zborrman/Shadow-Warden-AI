"""
warden/tests/test_auth_user_store.py — D-4 unified account store.

What is worth pinning here is not "does it read a row" but the properties that
make merging two live authentication stores safe:

  * **Nothing changes without Postgres.** The site login path must behave
    exactly as it did — air-gapped, dev and test deployments have no
    DATABASE_URL, and auth here is fail-closed.
  * **Postgres wins on conflict.** An address present in both stores must not
    have two working passwords.
  * **Uniqueness spans both stores**, so a site signup cannot shadow an existing
    portal account.
  * **Promotion only follows a verified password.** `note_successful_login`
    writes a usable credential; called on a failed attempt it would let an
    attacker seed Postgres rows.
  * **A Postgres write failure does not silently reroute to SQLite** — a quiet
    fallback is precisely how the two stores forked in the first place.
"""
from __future__ import annotations

import bcrypt
import pytest

from warden.auth import user_store


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(user_store.settings, "auth_db_path", str(tmp_path / "auth.db"))
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "", raising=False)
    yield


def _seed_sqlite(email: str, pw_hash: str) -> None:
    from warden.db.connect import open_db

    path = user_store.sqlite_path()
    with open_db("auth", path, module_default_path=path) as con:
        con.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw_hash))


# ── SQLite-only deployment behaves exactly as before ──────────────────────────

def test_without_postgres_everything_uses_sqlite():
    assert user_store.postgres_enabled() is False
    assert user_store.create_user("a@example.com", "h1") is True
    assert user_store.find_password_hash("a@example.com") == "h1"
    assert user_store.email_exists("a@example.com") is True
    assert user_store.email_exists("nobody@example.com") is False


def test_duplicate_signup_rejected_without_postgres():
    assert user_store.create_user("dup@example.com", "h1") is True
    assert user_store.create_user("dup@example.com", "h2") is False
    assert user_store.find_password_hash("dup@example.com") == "h1"


def test_email_matching_is_case_insensitive():
    user_store.create_user("Mixed@Example.com", "h1")
    assert user_store.find_password_hash("mixed@example.com") == "h1"


def test_promotion_is_a_noop_without_postgres():
    _seed_sqlite("x@example.com", "h")
    assert user_store.note_successful_login("x@example.com", "h") is False


def test_bulk_import_is_a_noop_without_postgres():
    _seed_sqlite("x@example.com", "h")
    assert user_store.import_sqlite_users() == {
        "read": 0, "imported": 0, "skipped": 0, "failed": 0
    }


# ── With Postgres configured ──────────────────────────────────────────────────

@pytest.fixture
def pg(monkeypatch):
    """A fake portal_users table behind the module's Postgres accessors."""
    rows: dict[str, dict] = {}

    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)
    monkeypatch.setattr(user_store, "_pg_get", lambda e: rows.get(e.lower()))

    def _insert(email, pw_hash):
        email = email.lower()
        if email in rows:
            return False
        rows[email] = {"email": email, "password_hash": pw_hash, "tenant_id": "t", "role": "owner"}
        return True

    monkeypatch.setattr(user_store, "_pg_insert", _insert)
    return rows


def test_postgres_wins_when_an_account_exists_in_both(pg):
    """One address must not have two working passwords."""
    _seed_sqlite("both@example.com", "sqlite-hash")
    pg["both@example.com"] = {"email": "both@example.com", "password_hash": "pg-hash"}
    assert user_store.find_password_hash("both@example.com") == "pg-hash"


def test_sqlite_account_still_resolves_when_postgres_lacks_it(pg):
    """Nobody is locked out mid-migration."""
    _seed_sqlite("legacy@example.com", "sqlite-hash")
    assert user_store.find_password_hash("legacy@example.com") == "sqlite-hash"


def test_signup_writes_to_postgres_when_configured(pg):
    assert user_store.create_user("new@example.com", "h") is True
    assert "new@example.com" in pg


def test_uniqueness_spans_both_stores(pg):
    """A site signup must not shadow an existing portal account."""
    pg["portal@example.com"] = {"email": "portal@example.com", "password_hash": "pg"}
    assert user_store.create_user("portal@example.com", "attacker-chosen") is False

    _seed_sqlite("sqliteonly@example.com", "old")
    assert user_store.create_user("sqliteonly@example.com", "attacker-chosen") is False


def test_successful_login_promotes_a_sqlite_account(pg):
    pw_hash = bcrypt.hashpw(b"correct horse", bcrypt.gensalt(rounds=4)).decode()
    _seed_sqlite("promote@example.com", pw_hash)

    assert user_store.note_successful_login("promote@example.com", pw_hash) is True
    assert pg["promote@example.com"]["password_hash"] == pw_hash
    # The promoted hash still verifies — accounts move without a password reset.
    assert bcrypt.checkpw(b"correct horse", pg["promote@example.com"]["password_hash"].encode())
    # Idempotent: a second login does not re-insert.
    assert user_store.note_successful_login("promote@example.com", pw_hash) is False


def test_bulk_import_copies_hashes_verbatim_and_is_rerunnable(pg):
    pw_hash = bcrypt.hashpw(b"pw", bcrypt.gensalt(rounds=4)).decode()
    _seed_sqlite("one@example.com", pw_hash)
    _seed_sqlite("two@example.com", "h2")

    first = user_store.import_sqlite_users()
    assert first["read"] == 2 and first["imported"] == 2 and first["failed"] == 0
    assert pg["one@example.com"]["password_hash"] == pw_hash

    second = user_store.import_sqlite_users()
    assert second["imported"] == 0 and second["skipped"] == 2


def test_postgres_write_failure_does_not_fall_back_to_sqlite(monkeypatch, pg):
    """A silent reroute would fork the stores again — the signup must fail."""
    def _boom(email, pw_hash):
        raise RuntimeError("postgres write failed")

    monkeypatch.setattr(user_store, "_pg_insert", _boom)

    with pytest.raises(RuntimeError):
        user_store.create_user("nofallback@example.com", "h")

    # Nothing was written to SQLite behind the caller's back.
    assert user_store._sqlite_get("nofallback@example.com") is None


def test_unreachable_postgres_still_serves_sqlite_reads(monkeypatch):
    """A transient outage must degrade to the fallback, not lock everyone out."""
    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)
    _seed_sqlite("degraded@example.com", "sqlite-hash")

    def _boom():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(user_store, "_engine", _boom)
    assert user_store.find_password_hash("degraded@example.com") == "sqlite-hash"


# ── Router integration ────────────────────────────────────────────────────────

def test_router_and_store_resolve_the_same_sqlite_file():
    """Two modules holding independent snapshots of one path is how they end up
    reading two different databases — that regression is what broke five auth
    tests when this seam was introduced."""
    from warden.auth import router as auth_router

    assert auth_router._db_path() == user_store.sqlite_path()


def test_login_promotes_only_after_the_password_verifies(monkeypatch, tmp_path):
    """Promotion writes a usable credential — a failed attempt must not create
    a Postgres row."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.auth import router as auth_router

    monkeypatch.setenv("AUTH_JWT_SECRET", "test-secret")
    monkeypatch.setattr(auth_router.settings, "auth_db_path", str(tmp_path / "a.db"))
    monkeypatch.setattr(auth_router.settings, "auth_users_json", "")
    monkeypatch.setattr(auth_router.settings, "auth_admin_email", "")
    monkeypatch.setattr(auth_router.settings, "auth_admin_password_hash", "")

    pw_hash = bcrypt.hashpw(b"longenough", bcrypt.gensalt(rounds=4)).decode()
    _seed_sqlite("login@example.com", pw_hash)

    promoted: list[str] = []
    monkeypatch.setattr(
        auth_router.user_store, "note_successful_login",
        lambda email, h: promoted.append(email) or True,
    )

    app = FastAPI()
    app.include_router(auth_router.router)
    client = TestClient(app)

    bad = client.post("/auth/login", json={"email": "login@example.com", "password": "wrong"})
    assert bad.status_code == 401
    assert promoted == [], "a failed login must never promote an account"

    ok = client.post("/auth/login", json={"email": "login@example.com", "password": "longenough"})
    assert ok.status_code == 200
    assert promoted == ["login@example.com"]
