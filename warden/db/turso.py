"""
warden/db/turso.py — Turso/libSQL connection adapter.

Provides a sqlite3-compatible synchronous interface to Turso databases via
the libsql HTTP pipeline API, so existing SQLite code can be switched to
Turso by changing the connection factory with zero logic changes.

Connection selection:
  TURSO_URL_<DB>  + TURSO_TOKEN_<DB>  → use Turso (remote)
  fallback                             → use local SQLite (existing behavior)

Supported DB names (maps to env-var suffixes):
  billing_audit, acp, marketplace, sep, staff, gsam

Usage:
  from warden.db.turso import get_connection, is_turso_enabled

  with get_connection("billing_audit", fallback_path="/tmp/x.db") as con:
      con.execute("INSERT INTO ...")   # works for both SQLite and Turso
      con.commit()   # no-op on Turso (auto-commit); commit on SQLite
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

import httpx

log = logging.getLogger("warden.db.turso")

# Maps short name → (url_env, token_env)
_DB_ENV: dict[str, tuple[str, str]] = {
    "billing_audit": ("TURSO_URL_BILLING_AUDIT", "TURSO_TOKEN_BILLING_AUDIT"),
    "acp":           ("TURSO_URL_ACP",            "TURSO_TOKEN_ACP"),
    "marketplace":   ("TURSO_URL_MARKETPLACE",    "TURSO_TOKEN_MARKETPLACE"),
    "sep":           ("TURSO_URL_SEP",             "TURSO_TOKEN_SEP"),
    "staff":         ("TURSO_URL_STAFF",           "TURSO_TOKEN_STAFF"),
    "gsam":          ("TURSO_URL_GSAM",            "TURSO_TOKEN_GSAM"),
}

_client_cache: dict[str, _TursoConnection] = {}
_cache_lock   = threading.Lock()


# ── Row wrapper (mimics sqlite3.Row) ──────────────────────────────────────────

class _TursoRow:
    """sqlite3.Row-compatible row wrapper for Turso results."""

    def __init__(self, columns: list[str], values: list[Any]) -> None:
        self._cols = columns
        self._vals = values
        self._map  = dict(zip(columns, values, strict=False))

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._vals[key]
        return self._map[key]

    def keys(self) -> list[str]:
        return self._cols

    def __iter__(self):
        return iter(self._vals)

    def __len__(self) -> int:
        return len(self._vals)


# ── Cursor wrapper ────────────────────────────────────────────────────────────

class _TursoCursor:
    """sqlite3.Cursor-compatible cursor backed by Turso HTTP API."""

    def __init__(self, connection: _TursoConnection) -> None:
        self._con  = connection
        self._rows: list[_TursoRow] = []
        self._idx  = 0
        self.rowcount = -1

    def execute(self, sql: str, parameters: tuple | list = ()) -> _TursoCursor:
        self._rows, self.rowcount = self._con._execute(sql, list(parameters))
        self._idx = 0
        return self

    def executemany(self, sql: str, seq_of_parameters) -> _TursoCursor:
        for params in seq_of_parameters:
            self._rows, self.rowcount = self._con._execute(sql, list(params))
        self._idx = 0
        return self

    def fetchone(self) -> _TursoRow | None:
        if self._idx < len(self._rows):
            row = self._rows[self._idx]
            self._idx += 1
            return row
        return None

    def fetchall(self) -> list[_TursoRow]:
        rows = self._rows[self._idx:]
        self._idx = len(self._rows)
        return rows

    def fetchmany(self, size: int = 1) -> list[_TursoRow]:
        rows = self._rows[self._idx:self._idx + size]
        self._idx += len(rows)
        return rows

    def __iter__(self):
        return iter(self._rows)

    @property
    def lastrowid(self) -> int | None:
        return self._con._last_insert_rowid


# ── Connection wrapper ────────────────────────────────────────────────────────

class _TursoConnection:
    """
    sqlite3.Connection-compatible class backed by Turso HTTP pipeline API.

    Thread-safety: each call acquires a per-connection lock (matching sqlite3
    check_same_thread=False semantics used in existing code).
    """

    def __init__(self, url: str, auth_token: str) -> None:
        # Strip libsql:// prefix for HTTP API calls
        base = url.replace("libsql://", "https://")
        self._api_url = f"{base}/v2/pipeline"
        self._auth    = f"Bearer {auth_token}"
        self._lock    = threading.RLock()
        self._last_insert_rowid: int | None = None
        self.row_factory = None   # unused; always returns _TursoRow

    def _execute(self, sql: str, params: list) -> tuple[list[_TursoRow], int]:
        """Send one statement to Turso and return (rows, rowcount)."""
        with self._lock:
            payload = {
                "requests": [
                    {
                        "type": "execute",
                        "stmt": {
                            "sql": sql,
                            "args": [_encode_arg(p) for p in params],
                        },
                    },
                    {"type": "close"},
                ]
            }
            try:
                resp = httpx.post(
                    self._api_url,
                    json=payload,
                    headers={
                        "Authorization": self._auth,
                        "Content-Type":  "application/json",
                    },
                    timeout=10,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise sqlite3.OperationalError(
                    f"Turso HTTP error {exc.response.status_code}: {exc.response.text}"
                ) from exc
            except httpx.RequestError as exc:
                raise sqlite3.OperationalError(f"Turso request error: {exc}") from exc

            data   = resp.json()
            result = data["results"][0]
            if result.get("type") == "error":
                raise sqlite3.OperationalError(result.get("error", {}).get("message", "unknown"))

            cols    = [c["name"] for c in result.get("response", {}).get("result", {}).get("cols", [])]
            raw_rows = result.get("response", {}).get("result", {}).get("rows", [])
            rows     = [_TursoRow(cols, [_decode_val(v) for v in r]) for r in raw_rows]

            # Capture last_insert_rowid for INSERT statements
            rowcount = result.get("response", {}).get("result", {}).get("affected_row_count", -1)
            last_id  = result.get("response", {}).get("result", {}).get("last_insert_rowid")
            if last_id is not None:
                self._last_insert_rowid = int(last_id)

            return rows, rowcount

    def execute(self, sql: str, parameters: tuple | list = ()) -> _TursoCursor:
        cur = _TursoCursor(self)
        cur.execute(sql, parameters)
        return cur

    def executemany(self, sql: str, seq_of_parameters) -> _TursoCursor:
        cur = _TursoCursor(self)
        for params in seq_of_parameters:
            cur.execute(sql, params)
        return cur

    def executescript(self, script: str) -> None:
        """Execute a multi-statement SQL script (split on ;)."""
        for stmt in _split_script(script):
            try:
                self._execute(stmt, [])
            except sqlite3.OperationalError as exc:
                # "already exists" errors are OK during schema init
                if "already exists" not in str(exc).lower():
                    log.warning("Turso executescript error (ignored): %s | sql: %.80s", exc, stmt)

    def commit(self) -> None:
        pass  # Turso auto-commits each request

    def rollback(self) -> None:
        pass  # No transaction support in HTTP pipeline mode

    def close(self) -> None:
        pass  # Connection is stateless HTTP; nothing to close

    def __enter__(self) -> _TursoConnection:
        return self

    def __exit__(self, *_) -> None:
        pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _encode_arg(v: Any) -> dict:
    """Encode a Python value to a Turso typed argument."""
    if v is None:
        return {"type": "null"}
    if isinstance(v, bool):
        return {"type": "integer", "value": "1" if v else "0"}
    if isinstance(v, int):
        return {"type": "integer", "value": str(v)}
    if isinstance(v, float):
        return {"type": "float", "value": str(v)}
    if isinstance(v, bytes):
        return {"type": "blob", "base64": v.hex()}
    return {"type": "text", "value": str(v)}


def _decode_val(v: dict) -> Any:
    """Decode a Turso typed value to a Python type."""
    t = v.get("type")
    val = v.get("value")
    if t == "null" or val is None:
        return None
    if t == "integer":
        return int(val)
    if t == "float":
        return float(val)
    if t == "blob":
        return bytes.fromhex(v.get("base64", ""))
    return val   # text


def _split_script(script: str) -> list[str]:
    """Split a multi-statement SQL script into individual statements."""
    stmts = [s.strip() for s in script.split(";")]
    return [s for s in stmts if s and not s.startswith("--")]


# ── Public API ────────────────────────────────────────────────────────────────

def is_turso_enabled(db_name: str) -> bool:
    """Return True if Turso env vars are set for this database."""
    if db_name not in _DB_ENV:
        return False
    url_var, token_var = _DB_ENV[db_name]
    return bool(os.getenv(url_var)) and bool(os.getenv(token_var))


def get_turso_client(db_name: str) -> _TursoConnection:
    """Return a cached Turso connection for the named database."""
    with _cache_lock:
        if db_name not in _client_cache:
            url_var, token_var = _DB_ENV[db_name]
            url   = os.getenv(url_var, "")
            token = os.getenv(token_var, "")
            if not url or not token:
                raise ValueError(
                    f"Turso not configured for '{db_name}': "
                    f"set {url_var} and {token_var} env vars"
                )
            _client_cache[db_name] = _TursoConnection(url, token)
            log.info("Turso: connected to %s (%s)", db_name, url)
        return _client_cache[db_name]


@contextmanager
def get_connection(
    db_name: str,
    fallback_path: str,
) -> Generator[sqlite3.Connection | _TursoConnection, None, None]:
    """
    Context manager that yields a Turso connection (if configured) or a
    local sqlite3.Connection (if not).

    Drop-in replacement for sqlite3.connect() in any warden module.

    Example:
        with get_connection("billing_audit", fallback_path=_DB_PATH) as con:
            con.execute("INSERT INTO ...")
            con.commit()
    """
    if is_turso_enabled(db_name):
        client = get_turso_client(db_name)
        yield client
    else:
        con = sqlite3.connect(fallback_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        try:
            yield con
            con.commit()
        finally:
            con.close()


def run_schema_migration(db_name: str, ddl: str) -> None:
    """Run schema DDL against the Turso database (called on startup)."""
    if not is_turso_enabled(db_name):
        return
    client = get_turso_client(db_name)
    log.info("Turso: running schema migration for %s", db_name)
    client.executescript(ddl)
    log.info("Turso: migration complete for %s", db_name)
