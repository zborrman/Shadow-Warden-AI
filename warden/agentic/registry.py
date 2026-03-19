"""
warden/agentic/registry.py
──────────────────────────
SQLite-backed agent consent registry for the AP2 Agentic Payment Protocol.

Tables
──────
  agents       — registered AI agents with per-tenant spending controls
  activity_log — immutable audit trail of all mandate decisions (AI Act compliant)

Environment variables
─────────────────────
  AGENT_REGISTRY_DB_PATH — SQLite path (default /warden/data/agent_registry.db)

Thread-safe: all writes protected by threading.Lock + WAL journal mode.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger("warden.agentic.registry")


def _db_path() -> Path:
    return Path(os.getenv("AGENT_REGISTRY_DB_PATH", "/warden/data/agent_registry.db"))


class AgentRegistry:
    """Thread-safe SQLite registry for AP2 agent consent records and activity log."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or _db_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = self._open()
        self._init_schema()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id             TEXT PRIMARY KEY,
                    tenant_id            TEXT NOT NULL,
                    name                 TEXT NOT NULL,
                    provider             TEXT NOT NULL DEFAULT '',
                    status               TEXT NOT NULL DEFAULT 'active',
                    max_per_item         REAL NOT NULL DEFAULT 0.0,
                    monthly_budget       REAL NOT NULL DEFAULT 0.0,
                    require_confirmation INTEGER NOT NULL DEFAULT 0,
                    allowed_categories   TEXT NOT NULL DEFAULT '[]',
                    mandate_ttl_seconds  INTEGER NOT NULL DEFAULT 300,
                    created_at           TEXT NOT NULL,
                    updated_at           TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_agents_tenant
                    ON agents(tenant_id);
                CREATE INDEX IF NOT EXISTS idx_agents_status
                    ON agents(status);

                CREATE TABLE IF NOT EXISTS activity_log (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id      TEXT NOT NULL,
                    agent_id       TEXT NOT NULL,
                    action         TEXT NOT NULL,
                    sku            TEXT NOT NULL DEFAULT '',
                    amount         REAL NOT NULL DEFAULT 0.0,
                    currency       TEXT NOT NULL DEFAULT 'USD',
                    status         TEXT NOT NULL,
                    reason         TEXT NOT NULL DEFAULT '',
                    transaction_id TEXT NOT NULL DEFAULT '',
                    timestamp      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_activity_tenant
                    ON activity_log(tenant_id);
                CREATE INDEX IF NOT EXISTS idx_activity_agent
                    ON activity_log(agent_id);
                CREATE INDEX IF NOT EXISTS idx_activity_ts
                    ON activity_log(timestamp);
            """)
            self._conn.commit()

    # ── Agent CRUD ────────────────────────────────────────────────────────────

    def register_agent(
        self,
        tenant_id: str,
        name: str,
        provider: str = "",
        max_per_item: float = 0.0,
        monthly_budget: float = 0.0,
        require_confirmation: bool = False,
        allowed_categories: list[str] | None = None,
        mandate_ttl_seconds: int = 300,
    ) -> dict:
        agent_id = str(uuid.uuid4())
        now      = datetime.now(UTC).isoformat()
        cats     = json.dumps(allowed_categories or [])
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agents
                    (agent_id, tenant_id, name, provider, status,
                     max_per_item, monthly_budget, require_confirmation,
                     allowed_categories, mandate_ttl_seconds, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
                """,
                (agent_id, tenant_id, name, provider,
                 max_per_item, monthly_budget, int(require_confirmation),
                 cats, mandate_ttl_seconds, now, now),
            )
            self._conn.commit()
        log.info("Agent registered: agent_id=%s tenant=%s name=%r", agent_id, tenant_id, name)
        return self.get_agent(agent_id)  # type: ignore[return-value]

    def get_agents(self, tenant_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM agents WHERE tenant_id=? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_agent(self, agent_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM agents WHERE agent_id=?", (agent_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_agent(self, agent_id: str, **fields) -> dict | None:
        allowed = {
            "name", "provider", "max_per_item", "monthly_budget",
            "require_confirmation", "allowed_categories", "mandate_ttl_seconds",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_agent(agent_id)
        if "allowed_categories" in updates:
            updates["allowed_categories"] = json.dumps(updates["allowed_categories"])
        if "require_confirmation" in updates:
            updates["require_confirmation"] = int(updates["require_confirmation"])
        updates["updated_at"] = datetime.now(UTC).isoformat()
        set_clause = ", ".join(f"{k}=?" for k in updates)
        params = list(updates.values()) + [agent_id]
        with self._lock:
            self._conn.execute(
                f"UPDATE agents SET {set_clause} WHERE agent_id=?", params
            )
            self._conn.commit()
        return self.get_agent(agent_id)

    def revoke_agent(self, agent_id: str) -> bool:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE agents SET status='revoked', updated_at=? WHERE agent_id=?",
                (now, agent_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def revoke_all(self, tenant_id: str) -> int:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE agents SET status='revoked', updated_at=?"
                " WHERE tenant_id=? AND status='active'",
                (now, tenant_id),
            )
            self._conn.commit()
        log.info("Revoked %d agent(s) for tenant=%s", cur.rowcount, tenant_id)
        return cur.rowcount

    # ── Activity log ──────────────────────────────────────────────────────────

    def log_activity(
        self,
        tenant_id: str,
        agent_id: str,
        action: str,
        sku: str,
        amount: float,
        currency: str,
        status: str,
        reason: str = "",
        transaction_id: str = "",
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO activity_log
                    (tenant_id, agent_id, action, sku, amount, currency,
                     status, reason, transaction_id, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, agent_id, action, sku, amount, currency,
                 status, reason, transaction_id, now),
            )
            self._conn.commit()

    def get_activity(
        self,
        tenant_id: str,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        if agent_id:
            rows = self._conn.execute(
                "SELECT * FROM activity_log WHERE tenant_id=? AND agent_id=?"
                " ORDER BY timestamp DESC LIMIT ?",
                (tenant_id, agent_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM activity_log WHERE tenant_id=?"
                " ORDER BY timestamp DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_monthly_spend(self, agent_id: str, year_month: str | None = None) -> float:
        if year_month is None:
            year_month = datetime.now(UTC).strftime("%Y-%m")
        row = self._conn.execute(
            """
            SELECT COALESCE(SUM(amount), 0.0) AS total
            FROM activity_log
            WHERE agent_id=? AND status='approved'
              AND substr(timestamp, 1, 7) = ?
            """,
            (agent_id, year_month),
        ).fetchone()
        return float(row["total"]) if row else 0.0

    # ── Helper ────────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        try:
            d["allowed_categories"] = json.loads(d.get("allowed_categories", "[]"))
        except (json.JSONDecodeError, TypeError):
            d["allowed_categories"] = []
        d["require_confirmation"] = bool(d.get("require_confirmation", 0))
        return d

    def close(self) -> None:
        self._conn.close()


# ── Module-level singleton ────────────────────────────────────────────────────

_instance:      AgentRegistry | None = None
_instance_lock: threading.Lock       = threading.Lock()


def get_registry() -> AgentRegistry:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = AgentRegistry()
    return _instance
