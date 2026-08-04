"""
warden/auth/user_store.py — one account store behind two front doors (D-4).

The split this closes
─────────────────────
Two independent user stores shipped side by side, both mounted:

  * `warden/auth/router.py`  — SQLite `users(email, password_hash)` in
    `warden_auth.db`, issuing the `sw_session` cookie the marketing site's nav
    reads. Four endpoints: signup, login, logout, me.
  * `warden/portal_router.py` — Postgres `warden_core.portal_users`, the actual
    customer portal: TOTP, refresh tokens, password reset, API keys, billing.

Same product, same email address, two disconnected password stores. Signing up
on the site did not create a portal account and vice versa, and — the reason
this is a correctness bug and not just duplication — a GDPR erasure or export
request served from one store silently misses the rows in the other.

Why `portal_users` wins
───────────────────────
It is a strict superset (uuid id, tenant_id, role, display_name, verification,
reset tokens, TOTP, notification prefs, last_login_at) of the SQLite table's
four columns, and it is what every richer feature already reads. Inventing a
third `users` table to unify two would have been the worse trade.

Both routers hash with the **same** `bcrypt` library and `gensalt()` defaults,
so a stored hash is portable between them verbatim: accounts move without a
password reset, which is what makes this migration non-breaking.

Why SQLite does not simply go away
──────────────────────────────────
`auth/router.py` is deliberately dependency-free — it must keep working in
air-gapped, dev and test deployments where `DATABASE_URL` is unset, and auth in
this project is fail-closed. Making site login require Postgres to be reachable
would trade a data-split bug for an availability one. So:

  * Postgres is authoritative **when it is configured**; SQLite is the fallback
    read and the sole store when it is not.
  * A user found only in SQLite who authenticates successfully is **promoted**
    into Postgres on the spot (`note_successful_login`) — lazy migration, so the
    two stores converge through normal traffic instead of a flag day.
  * `import_sqlite_users()` does the same in bulk for accounts that never log in
    again.

Promotion happens only *after* the caller has verified the password. Never call
it on an attempt that failed: it would let an attacker seed Postgres rows.
"""
from __future__ import annotations

import logging
import sqlite3
import uuid
from typing import Any

from warden.config import settings
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.auth.user_store")


# The SQLite fallback table's schema is registered *here*, with the code that
# opens it. It used to live in `router.py`, which meant any process importing
# only this module — a worker, a migration script, a test — opened the database
# without the DDL ever being registered and got "no such table: users".
_AUTH_DDL = """
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT    NOT NULL,
        created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );
"""
register("auth", "warden.auth.router", _AUTH_DDL)


def sqlite_path() -> str:
    """The one resolver for `warden_auth.db`.

    Resolved per call, never captured at import, and imported by
    `warden/auth/router.py` rather than duplicated there — two modules each
    holding their own snapshot of this path is exactly how they end up reading
    two different databases.
    """
    return settings.auth_db_path


# ── Backend availability ──────────────────────────────────────────────────────

def postgres_enabled() -> bool:
    """True when the Postgres account store is configured.

    Only checks configuration, not reachability — a transient outage must not
    silently reroute writes to SQLite and fork the two stores again. Read paths
    handle an unreachable database by falling through to SQLite; write paths
    surface the failure instead.
    """
    try:
        from warden.db.connection import DATABASE_URL

        return bool(DATABASE_URL)
    except Exception:
        return False


def _engine() -> Any:
    from warden.db.connection import get_engine

    return get_engine()


# ── Reads ─────────────────────────────────────────────────────────────────────

def _pg_get(email: str) -> dict | None:
    if not postgres_enabled():
        return None
    try:
        from sqlalchemy import text

        with _engine().connect() as conn:
            row = conn.execute(
                text("SELECT id, email, password_hash, tenant_id, role FROM warden_core.portal_users WHERE email = :e"),
                {"e": email.lower()},
            ).mappings().first()
        return dict(row) if row else None
    except Exception as exc:
        log.warning("auth: portal_users read failed, falling back to SQLite: %s", exc)
        return None


def _sqlite_get(email: str) -> str | None:
    try:
        with open_db("auth", sqlite_path(), module_default_path=sqlite_path()) as con:
            row = con.execute(
                "SELECT password_hash FROM users WHERE email = ? COLLATE NOCASE", (email,)
            ).fetchone()
        return row[0] if row else None
    except Exception as exc:
        log.warning("auth: sqlite read error: %s", exc)
        return None


def find_password_hash(email: str) -> str | None:
    """Stored bcrypt hash for *email*, Postgres first then SQLite.

    Postgres wins when an account exists in both — it is the store the portal
    reads, and letting the older SQLite password keep working would mean one
    address with two valid passwords.
    """
    user = _pg_get(email)
    if user and user.get("password_hash"):
        return str(user["password_hash"])
    return _sqlite_get(email)


def email_exists(email: str) -> bool:
    """True when *email* is registered in either store."""
    return find_password_hash(email) is not None


# ── Writes ────────────────────────────────────────────────────────────────────

def _pg_insert(email: str, pw_hash: str) -> bool:
    """Insert into portal_users with the same shape portal registration uses.

    Returns False when the email is already taken (which is a caller-visible
    409, not an error) and raises on anything else, so a genuine backend failure
    is never mistaken for a duplicate.
    """
    from sqlalchemy import text

    email = email.lower()
    with _engine().begin() as conn:
        taken = conn.execute(
            text("SELECT 1 FROM warden_core.portal_users WHERE email = :e"), {"e": email}
        ).first()
        if taken:
            return False
        conn.execute(
            text("""
                INSERT INTO warden_core.portal_users (id, email, password_hash, display_name, tenant_id, role)
                VALUES (:id, :email, :pw, :name, :tid, 'owner')
            """),
            {
                "id": str(uuid.uuid4()),
                "email": email,
                "pw": pw_hash,
                "name": email.split("@")[0],
                # Matches portal registration's format so a site-created account
                # is indistinguishable from a portal-created one downstream.
                "tid": f"tenant_{uuid.uuid4().hex[:12]}",
            },
        )
    return True


def create_user(email: str, pw_hash: str) -> bool:
    """Register a new account. False when the email is already taken.

    Writes to Postgres when configured, else SQLite. The uniqueness check spans
    **both** stores, so a site signup cannot shadow an existing portal account
    (or the reverse) with a second password.
    """
    email = email.lower()
    if email_exists(email):
        return False

    if postgres_enabled():
        try:
            return _pg_insert(email, pw_hash)
        except Exception as exc:
            # Deliberately not falling back to SQLite: a silent reroute is how
            # the two stores forked in the first place. Fail the signup loudly.
            log.error("auth: portal_users insert failed: %s", exc)
            raise

    try:
        with open_db("auth", sqlite_path(), module_default_path=sqlite_path()) as con:
            con.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw_hash)
            )
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception as exc:
        log.error("auth: sqlite write error: %s", exc)
        return False


# ── Lazy migration ────────────────────────────────────────────────────────────

def note_successful_login(email: str, pw_hash: str) -> bool:
    """Promote a SQLite-only account into Postgres after a *verified* login.

    Call only once the password has been checked — this writes a usable
    credential, so calling it on a failed attempt would let an attacker create
    Postgres rows. Best-effort: a promotion failure leaves the account working
    exactly as before, in SQLite.

    Returns True when a row was promoted.
    """
    if not postgres_enabled():
        return False
    try:
        if _pg_get(email) is not None:
            return False                      # already there; nothing to do
        promoted = _pg_insert(email, pw_hash)
        if promoted:
            log.info("auth: promoted SQLite account to portal_users [email=%s]", email.lower())
        return promoted
    except Exception as exc:
        log.warning("auth: account promotion failed (still usable in SQLite): %s", exc)
        return False


def import_sqlite_users() -> dict[str, int]:
    """Bulk-copy every `warden_auth.db` account into `portal_users`.

    For accounts that would otherwise wait for their owner's next login. Safe to
    re-run: rows already present are skipped, and hashes are copied verbatim so
    nobody is asked to reset a password.
    """
    result = {"read": 0, "imported": 0, "skipped": 0, "failed": 0}
    if not postgres_enabled():
        return result
    try:
        with open_db("auth", sqlite_path(), module_default_path=sqlite_path()) as con:
            rows = con.execute("SELECT email, password_hash FROM users").fetchall()
    except Exception as exc:
        log.warning("auth: could not read SQLite users for import: %s", exc)
        return result

    for row in rows:
        result["read"] += 1
        email, pw_hash = row[0], row[1]
        try:
            if _pg_get(email) is not None:
                result["skipped"] += 1
            elif _pg_insert(email, pw_hash):
                result["imported"] += 1
            else:
                result["skipped"] += 1
        except Exception as exc:
            result["failed"] += 1
            log.warning("auth: import failed for one account: %s", exc)

    log.info("auth: SQLite → portal_users import %s", result)
    return result
