"""Secrets Inventory — SQLite-backed central registry of secret metadata."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

_DB_PATH = os.environ.get("SECRETS_DB_PATH", "/tmp/warden_secrets.db")


@contextmanager
def _conn(db_path: str = _DB_PATH):
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _init_db(db_path: str = _DB_PATH) -> None:
    with _conn(db_path) as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS secrets_vaults (
                vault_id     TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL,
                vault_type   TEXT NOT NULL,
                display_name TEXT NOT NULL,
                config_enc   TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                last_synced  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_sv_tenant ON secrets_vaults(tenant_id);

            CREATE TABLE IF NOT EXISTS secrets_inventory (
                secret_id    TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL,
                vault_id     TEXT NOT NULL,
                name         TEXT NOT NULL,
                vault_type   TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'active',
                risk_score   REAL NOT NULL DEFAULT 0.0,
                created_at   TEXT,
                last_rotated TEXT,
                expires_at   TEXT,
                tags         TEXT NOT NULL DEFAULT '{}',
                synced_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_si_tenant  ON secrets_inventory(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_si_vault   ON secrets_inventory(vault_id);
            CREATE INDEX IF NOT EXISTS idx_si_status  ON secrets_inventory(status);
        """)


_init_db()


@dataclass
class SecretRecord:
    secret_id: str
    tenant_id: str
    vault_id: str
    name: str
    vault_type: str
    status: str = "active"
    risk_score: float = 0.0
    created_at: str | None = None
    last_rotated: str | None = None
    expires_at: str | None = None
    tags: dict = field(default_factory=dict)
    synced_at: str = ""


def _row_to_record(row: sqlite3.Row) -> SecretRecord:
    d = dict(row)
    d["tags"] = json.loads(d.get("tags") or "{}")
    return SecretRecord(**d)


def _compute_risk(meta) -> float:
    score = 0.0
    now = datetime.now(UTC)
    if meta.expires_at:
        try:
            exp = datetime.fromisoformat(meta.expires_at.replace("Z", "+00:00"))
            days_left = (exp - now).days
            if days_left < 0:
                score += 0.5
            elif days_left < 14:
                score += 0.3
            elif days_left < 30:
                score += 0.1
        except ValueError:
            pass
    if not meta.last_rotated:
        score += 0.3
    elif meta.created_at:
        try:
            rot = datetime.fromisoformat(meta.last_rotated.replace("Z", "+00:00"))
            age = (now - rot).days
            if age > 90:
                score += 0.3
            elif age > 30:
                score += 0.1
        except ValueError:
            pass
    return min(score, 1.0)


class SecretsInventory:
    def __init__(self, db_path: str = _DB_PATH):
        self.db_path = db_path
        _init_db(db_path)

    # ── Vault registry ────────────────────────────────────────────────────────

    def register_vault(self, tenant_id: str, vault_type: str, display_name: str,
                       config_enc: str) -> str:
        vault_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with _conn(self.db_path) as con:
            con.execute(
                """INSERT INTO secrets_vaults
                   (vault_id, tenant_id, vault_type, display_name, config_enc, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (vault_id, tenant_id, vault_type, display_name, config_enc, now),
            )
        return vault_id

    def list_vaults(self, tenant_id: str) -> list[dict]:
        with _conn(self.db_path) as con:
            rows = con.execute(
                "SELECT vault_id, vault_type, display_name, created_at, last_synced "
                "FROM secrets_vaults WHERE tenant_id=?",
                (tenant_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_vault(self, tenant_id: str, vault_id: str) -> dict | None:
        with _conn(self.db_path) as con:
            row = con.execute(
                "SELECT * FROM secrets_vaults WHERE vault_id=? AND tenant_id=?",
                (vault_id, tenant_id),
            ).fetchone()
        return dict(row) if row else None

    def delete_vault(self, tenant_id: str, vault_id: str) -> bool:
        with _conn(self.db_path) as con:
            cur = con.execute(
                "DELETE FROM secrets_vaults WHERE vault_id=? AND tenant_id=?",
                (vault_id, tenant_id),
            )
            con.execute(
                "DELETE FROM secrets_inventory WHERE vault_id=? AND tenant_id=?",
                (vault_id, tenant_id),
            )
        return cur.rowcount > 0

    # ── Inventory sync ────────────────────────────────────────────────────────

    def upsert_secrets(self, tenant_id: str, vault_id: str,
                       metas: list) -> int:
        now = datetime.now(UTC).isoformat()
        synced_names: set[str] = set()
        with _conn(self.db_path) as con:
            for m in metas:
                risk = _compute_risk(m)
                status = _derive_status(m)
                existing = con.execute(
                    "SELECT secret_id FROM secrets_inventory "
                    "WHERE tenant_id=? AND vault_id=? AND name=?",
                    (tenant_id, vault_id, m.name),
                ).fetchone()
                if existing:
                    con.execute(
                        """UPDATE secrets_inventory
                           SET status=?, risk_score=?, last_rotated=?,
                               expires_at=?, tags=?, synced_at=?
                           WHERE secret_id=?""",
                        (status, risk, m.last_rotated,
                         m.expires_at, json.dumps(m.tags), now,
                         existing["secret_id"]),
                    )
                else:
                    con.execute(
                        """INSERT INTO secrets_inventory
                           (secret_id,tenant_id,vault_id,name,vault_type,
                            status,risk_score,created_at,last_rotated,
                            expires_at,tags,synced_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (str(uuid.uuid4()), tenant_id, vault_id, m.name,
                         m.vault_type, status, risk, m.created_at,
                         m.last_rotated, m.expires_at,
                         json.dumps(m.tags), now),
                    )
                synced_names.add(m.name)
            # Mark secrets no longer in vault as retired
            rows = con.execute(
                "SELECT secret_id, name FROM secrets_inventory "
                "WHERE tenant_id=? AND vault_id=?",
                (tenant_id, vault_id),
            ).fetchall()
            for r in rows:
                if r["name"] not in synced_names:
                    con.execute(
                        "UPDATE secrets_inventory SET status='retired' WHERE secret_id=?",
                        (r["secret_id"],),
                    )
            con.execute(
                "UPDATE secrets_vaults SET last_synced=? WHERE vault_id=?",
                (now, vault_id),
            )
        return len(metas)

    # ── Queries ───────────────────────────────────────────────────────────────

    def list_secrets(self, tenant_id: str, status: str | None = None,
                     vault_id: str | None = None) -> list[SecretRecord]:
        q = "SELECT * FROM secrets_inventory WHERE tenant_id=?"
        params: list = [tenant_id]
        if status:
            q += " AND status=?"
            params.append(status)
        if vault_id:
            q += " AND vault_id=?"
            params.append(vault_id)
        q += " ORDER BY risk_score DESC, name"
        with _conn(self.db_path) as con:
            rows = con.execute(q, params).fetchall()
        return [_row_to_record(r) for r in rows]

    def get_expiring(self, tenant_id: str, within_days: int = 30) -> list[SecretRecord]:
        cutoff = (datetime.now(UTC) + timedelta(days=within_days)).isoformat()
        now = datetime.now(UTC).isoformat()
        with _conn(self.db_path) as con:
            rows = con.execute(
                """SELECT * FROM secrets_inventory
                   WHERE tenant_id=? AND expires_at IS NOT NULL
                   AND expires_at <= ? AND expires_at >= ?
                   ORDER BY expires_at""",
                (tenant_id, cutoff, now),
            ).fetchall()
        return [_row_to_record(r) for r in rows]

    def get_stats(self, tenant_id: str) -> dict:
        with _conn(self.db_path) as con:
            total = con.execute(
                "SELECT COUNT(*) FROM secrets_inventory WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()[0]
            by_status = {
                r["status"]: r["cnt"]
                for r in con.execute(
                    "SELECT status, COUNT(*) as cnt FROM secrets_inventory "
                    "WHERE tenant_id=? GROUP BY status",
                    (tenant_id,),
                ).fetchall()
            }
            by_vault = {
                r["vault_type"]: r["cnt"]
                for r in con.execute(
                    "SELECT vault_type, COUNT(*) as cnt FROM secrets_inventory "
                    "WHERE tenant_id=? GROUP BY vault_type",
                    (tenant_id,),
                ).fetchall()
            }
            high_risk = con.execute(
                "SELECT COUNT(*) FROM secrets_inventory "
                "WHERE tenant_id=? AND risk_score >= 0.5",
                (tenant_id,),
            ).fetchone()[0]
        return {
            "total": total,
            "by_status": by_status,
            "by_vault_type": by_vault,
            "high_risk_count": high_risk,
            "vaults": len(self.list_vaults(tenant_id)),
        }

    def update_status(self, tenant_id: str, secret_id: str, status: str) -> bool:
        with _conn(self.db_path) as con:
            cur = con.execute(
                "UPDATE secrets_inventory SET status=? WHERE secret_id=? AND tenant_id=?",
                (status, secret_id, tenant_id),
            )
        return cur.rowcount > 0


def _derive_status(meta) -> str:
    now = datetime.now(UTC)
    if meta.expires_at:
        try:
            exp = datetime.fromisoformat(meta.expires_at.replace("Z", "+00:00"))
            if exp < now:
                return "expired"
            if (exp - now).days < 30:
                return "expiring_soon"
        except ValueError:
            pass
    return "active"
