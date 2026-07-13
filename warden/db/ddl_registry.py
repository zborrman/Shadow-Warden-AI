"""
warden/db/ddl_registry.py
──────────────────────────
Central DDL registry — one place that knows every module's SQLite schema.

Replaces the "run CREATE TABLE IF NOT EXISTS on every single connection" pattern
scattered across ~98 modules with a registered-once / applied-once model.

Why not one Alembic tree?
────────────────────────
The Alembic tree under warden/db/migrations targets the *PostgreSQL* app DB
(DATABASE_URL). The ~98 module DBs are independent per-feature SQLite files
(WARDEN_DATA_DIR, see config.data_path) that are created on demand and may not
exist at all in a given deployment. Forcing them through Alembic would couple
optional subsystems to a global migration run. The registry gives the same wins
— central schema visibility, DDL-once, drift detection — without that coupling.

Model
─────
  register(db_key, module, ddl)      — module declares its schema at import time
  ensure_schema(conn, db_key, path)  — apply any *pending* DDL for that DB, once

``ensure_schema`` is:
  • **Lazy** — applied on first connection in the process, not at startup. A worker
    or test that never runs the FastAPI lifespan still gets its tables. This is the
    key safety property; a startup-only apply_all() would silently break them.
  • **Memoized** — an in-process set short-circuits repeat calls, so the hot path
    costs one set lookup instead of an executescript.
  • **Persistent** — applied DDL is recorded in ``_warden_ddl_applied`` (module,
    checksum) so it is not re-executed across restarts, and a changed checksum is
    detected as schema drift and re-applied (DDL must stay idempotent —
    CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS).

Fail-safe: any registry error falls back to executing the DDL directly, so a
registry bug can never leave a module without its tables.
"""
from __future__ import annotations

import hashlib
import logging
import threading
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.db.ddl_registry")

_TRACKING_DDL = """
CREATE TABLE IF NOT EXISTS _warden_ddl_applied (
    module     TEXT PRIMARY KEY,
    checksum   TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
"""

# db_key → {module_name: ddl}
_REGISTRY: dict[str, dict[str, str]] = {}
# (db_path, module, checksum) already applied in this process
_applied: set[tuple[str, str, str]] = set()
_lock = threading.RLock()


def checksum(ddl: str) -> str:
    """Stable short hash of a DDL script — whitespace-insensitive."""
    normalized = " ".join(ddl.split())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def register(db_key: str, module: str, ddl: str) -> None:
    """
    Declare a module's schema. Called at import time by each module.

    db_key : logical database ("staff", "marketplace", "sep", …) — matches the
             Turso db_name when the module routes through warden.db.turso.
    module : unique schema owner name within that db_key.
    """
    with _lock:
        _REGISTRY.setdefault(db_key, {})[module] = ddl


def registered(db_key: str | None = None) -> dict[str, dict[str, str]]:
    """Introspection snapshot: what schema is registered (audit / health)."""
    with _lock:
        if db_key is not None:
            return {db_key: dict(_REGISTRY.get(db_key, {}))}
        return {k: dict(v) for k, v in _REGISTRY.items()}


def ensure_schema(conn: Any, db_key: str, db_path: str = "") -> int:
    """
    Apply any pending DDL registered under ``db_key`` to ``conn``. Returns the
    number of module schemas applied (0 when everything is already current).

    ``db_path`` scopes the in-process memo — pass the concrete file path so two
    different SQLite files sharing a db_key are tracked independently.
    Fail-safe: on any tracking error, the DDL is executed directly.
    """
    with _lock:
        modules = dict(_REGISTRY.get(db_key, {}))
    if not modules:
        return 0

    scope = db_path or db_key
    pending: list[tuple[str, str, str]] = []   # (module, ddl, checksum)
    for module, ddl in modules.items():
        cs = checksum(ddl)
        if (scope, module, cs) in _applied:
            continue
        pending.append((module, ddl, cs))
    if not pending:
        return 0

    applied = 0
    try:
        conn.executescript(_TRACKING_DDL)
        rows = conn.execute("SELECT module, checksum FROM _warden_ddl_applied").fetchall()
        seen = {r[0]: r[1] for r in rows}
    except Exception as exc:  # noqa: BLE001
        # Tracking unavailable (e.g. exotic backend) — apply DDL directly, stay safe.
        log.debug("ddl_registry: tracking unavailable for %s (%s); applying directly", db_key, exc)
        seen = {}

    now = datetime.now(UTC).isoformat()
    for module, ddl, cs in pending:
        if seen.get(module) == cs:
            _applied.add((scope, module, cs))
            continue
        try:
            conn.executescript(ddl)
            try:
                conn.execute(
                    "INSERT INTO _warden_ddl_applied (module, checksum, applied_at) "
                    "VALUES (?,?,?) "
                    "ON CONFLICT(module) DO UPDATE SET checksum=excluded.checksum, "
                    "applied_at=excluded.applied_at",
                    (module, cs, now),
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("ddl_registry: could not record %s/%s: %s", db_key, module, exc)
            _applied.add((scope, module, cs))
            applied += 1
            if module in seen:
                log.info("ddl_registry: schema drift in %s/%s — DDL re-applied", db_key, module)
        except Exception as exc:  # noqa: BLE001
            log.warning("ddl_registry: DDL failed for %s/%s: %s", db_key, module, exc)

    return applied


def reset_memo() -> None:
    """Clear the in-process applied-memo (tests only)."""
    with _lock:
        _applied.clear()
