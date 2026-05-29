"""
warden/semantic_layer/repository.py  (FE-42)
CRUD for SemanticModel definitions — SQLite-backed, per-tenant.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

from warden.semantic_layer.models import SemanticModel

log = logging.getLogger("warden.semantic_layer.repository")

_DB_PATH = os.getenv("SEMANTIC_DB_PATH", "/tmp/warden_semantic.db")
_db_lock = threading.RLock()


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    with _db_lock:
        con = sqlite3.connect(db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        _ensure_schema(con)
        try:
            yield con
            con.commit()
        finally:
            con.close()


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS semantic_models (
            id          TEXT PRIMARY KEY,
            tenant_id   TEXT NOT NULL,
            name        TEXT NOT NULL,
            definition  TEXT NOT NULL,    -- JSON of SemanticModel
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sm_tenant ON semantic_models(tenant_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_sm_name ON semantic_models(tenant_id, name);

        CREATE TABLE IF NOT EXISTS semantic_query_log (
            id          TEXT PRIMARY KEY,
            tenant_id   TEXT NOT NULL,
            model_id    TEXT NOT NULL,
            metrics     TEXT,
            dimensions  TEXT,
            sql_text    TEXT,
            exec_ms     REAL,
            row_count   INTEGER,
            created_at  TEXT NOT NULL
        );
    """)


def create_model(model: SemanticModel) -> SemanticModel:
    if not model.id:
        model.id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    model.created_at = now
    model.updated_at = now
    with _conn() as con:
        con.execute(
            "INSERT INTO semantic_models(id, tenant_id, name, definition, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?)",
            (model.id, model.owner_tenant, model.name,
             json.dumps(model.to_dict()), now, now),
        )
    log.info("SemanticModel created: %s (%s)", model.name, model.id)
    return model


def get_model(model_id: str, tenant_id: str) -> SemanticModel | None:
    with _conn() as con:
        row = con.execute(
            "SELECT definition FROM semantic_models WHERE id=? AND tenant_id=?",
            (model_id, tenant_id),
        ).fetchone()
    if not row:
        return None
    return SemanticModel(**json.loads(row["definition"]))


def get_model_by_name(name: str, tenant_id: str) -> SemanticModel | None:
    with _conn() as con:
        row = con.execute(
            "SELECT definition FROM semantic_models WHERE name=? AND tenant_id=?",
            (name, tenant_id),
        ).fetchone()
    if not row:
        return None
    return SemanticModel(**json.loads(row["definition"]))


def list_models(tenant_id: str) -> list[SemanticModel]:
    with _conn() as con:
        rows = con.execute(
            "SELECT definition FROM semantic_models WHERE tenant_id=? ORDER BY name",
            (tenant_id,),
        ).fetchall()
    return [SemanticModel(**json.loads(r["definition"])) for r in rows]


def update_model(model: SemanticModel) -> SemanticModel:
    model.updated_at = datetime.now(UTC).isoformat()
    with _conn() as con:
        cur = con.execute(
            "UPDATE semantic_models SET definition=?, name=?, updated_at=? WHERE id=? AND tenant_id=?",
            (json.dumps(model.to_dict()), model.name, model.updated_at,
             model.id, model.owner_tenant),
        )
        if cur.rowcount == 0:
            raise KeyError(f"Model {model.id!r} not found")
    return model


def delete_model(model_id: str, tenant_id: str) -> bool:
    with _conn() as con:
        cur = con.execute(
            "DELETE FROM semantic_models WHERE id=? AND tenant_id=?",
            (model_id, tenant_id),
        )
    return cur.rowcount > 0


def log_query(
    tenant_id: str, model_id: str, metrics: list[str], dimensions: list[str],
    sql_text: str, exec_ms: float, row_count: int,
) -> None:
    try:
        with _conn() as con:
            con.execute(
                "INSERT INTO semantic_query_log(id, tenant_id, model_id, metrics, dimensions, "
                "sql_text, exec_ms, row_count, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), tenant_id, model_id,
                 json.dumps(metrics), json.dumps(dimensions),
                 sql_text, exec_ms, row_count, datetime.now(UTC).isoformat()),
            )
    except Exception as exc:
        log.debug("Query log failed: %s", exc)


def query_usage_stats(tenant_id: str, limit: int = 20) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT model_id, metrics, dimensions, exec_ms, row_count, created_at "
            "FROM semantic_query_log WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]
