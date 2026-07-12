"""
warden/marketplace/service.py
───────────────────────────────
Asset registry — tokenizes and stores marketplace assets.

All assets receive a UECIID (SEP-{11}) as their primary identifier.
The full token container (SHA-256, Ed25519 signature, IPFS hash, payload)
is stored as JSON in SQLite alongside seller metadata.

Database
────────
  Shares MARKETPLACE_DB_PATH with agent.py.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from warden.config import data_path
from warden.db.sqlite_pragmas import init_pragmas
from warden.marketplace.agent import get_agent
from warden.marketplace.tokenizer import AssetTokenizer

if TYPE_CHECKING:
    from warden.communities.keypair import CommunityKeypair

log = logging.getLogger("warden.marketplace.service")

_DB_PATH = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_db_lock = threading.RLock()

_VALID_ASSET_TYPES = {"rule", "model", "signals"}


# ── Schema ────────────────────────────────────────────────────────────────────

def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS marketplace_assets (
            asset_id        TEXT PRIMARY KEY,
            asset_type      TEXT NOT NULL,
            token_data      TEXT NOT NULL,
            ipfs_hash       TEXT NOT NULL DEFAULT '',
            seller_agent_id TEXT NOT NULL,
            community_id    TEXT NOT NULL,
            tenant_id       TEXT NOT NULL,
            created_at      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mkt_assets_agent
            ON marketplace_assets(seller_agent_id);
        CREATE INDEX IF NOT EXISTS idx_mkt_assets_type
            ON marketplace_assets(asset_type);
        CREATE INDEX IF NOT EXISTS idx_mkt_assets_community
            ON marketplace_assets(community_id);
    """)


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    init_pragmas(con)
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


# ── Registry functions ────────────────────────────────────────────────────────

def register_asset(
    tenant_id: str,
    seller_agent_id: str,
    asset_type: str,
    raw_data: dict | list,
    keypair: CommunityKeypair,
    db_path: str = _DB_PATH,
) -> str:
    """Tokenize and register an asset. Returns the UECIID (asset_id).

    Raises:
        ValueError:      Unknown asset_type.
        PermissionError: Agent lacks marketplace_sell capability.
    """
    if asset_type not in _VALID_ASSET_TYPES:
        raise ValueError(f"Unknown asset_type '{asset_type}'. Valid: {_VALID_ASSET_TYPES}")

    agent = get_agent(seller_agent_id, db_path=db_path)
    if agent is None or "marketplace_sell" not in agent.capabilities:
        raise PermissionError(
            f"Agent '{seller_agent_id}' lacks 'marketplace_sell' capability."
        )

    tokenizer = AssetTokenizer()
    community_id = agent.community_id

    if asset_type == "rule":
        rule_data = raw_data if isinstance(raw_data, dict) else {}
        container = tokenizer.tokenize_rule(rule_data, keypair, seller_agent_id, community_id)
    elif asset_type == "model":
        model_data = raw_data if isinstance(raw_data, dict) else {}
        container = tokenizer.tokenize_model(model_data, keypair, seller_agent_id, community_id)
    else:  # signals
        signals = raw_data if isinstance(raw_data, list) else [raw_data]
        container = tokenizer.tokenize_signals(signals, keypair, seller_agent_id, community_id)

    asset_id  = container["ueciid"]
    ipfs_hash = container.get("ipfs_hash", "")
    now       = datetime.now(UTC).isoformat()

    with _db_lock, _conn(db_path) as con:
        con.execute(
            """
            INSERT OR REPLACE INTO marketplace_assets
                (asset_id, asset_type, token_data, ipfs_hash,
                 seller_agent_id, community_id, tenant_id, created_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                asset_id,
                asset_type,
                json.dumps(container, ensure_ascii=False),
                ipfs_hash,
                seller_agent_id,
                community_id,
                tenant_id,
                now,
            ),
        )

    log.info("Asset registered: %s type=%s agent=%s", asset_id, asset_type, seller_agent_id)
    return asset_id


def get_asset(asset_id: str, db_path: str = _DB_PATH) -> dict | None:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT * FROM marketplace_assets WHERE asset_id=?", (asset_id,)
        ).fetchone()
    if row is None:
        return None
    return {
        "asset_id":        row["asset_id"],
        "asset_type":      row["asset_type"],
        "token_data":      json.loads(row["token_data"]),
        "ipfs_hash":       row["ipfs_hash"],
        "seller_agent_id": row["seller_agent_id"],
        "community_id":    row["community_id"],
        "tenant_id":       row["tenant_id"],
        "created_at":      row["created_at"],
    }


def list_assets_by_agent(
    agent_id: str,
    asset_type: str | None = None,
    limit: int = 50,
    db_path: str = _DB_PATH,
) -> list[dict]:
    query = "SELECT * FROM marketplace_assets WHERE seller_agent_id=?"
    params: list = [agent_id]
    if asset_type:
        query += " AND asset_type=?"
        params.append(asset_type)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with _conn(db_path) as con:
        rows = con.execute(query, params).fetchall()
    return [
        {
            "asset_id":        r["asset_id"],
            "asset_type":      r["asset_type"],
            "ipfs_hash":       r["ipfs_hash"],
            "seller_agent_id": r["seller_agent_id"],
            "community_id":    r["community_id"],
            "created_at":      r["created_at"],
        }
        for r in rows
    ]


def search_assets(
    community_id: str,
    asset_type: str | None = None,
    limit: int = 20,
    db_path: str = _DB_PATH,
) -> list[dict]:
    query = "SELECT * FROM marketplace_assets WHERE community_id=?"
    params: list = [community_id]
    if asset_type:
        query += " AND asset_type=?"
        params.append(asset_type)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with _conn(db_path) as con:
        rows = con.execute(query, params).fetchall()
    return [
        {
            "asset_id":        r["asset_id"],
            "asset_type":      r["asset_type"],
            "ipfs_hash":       r["ipfs_hash"],
            "seller_agent_id": r["seller_agent_id"],
            "created_at":      r["created_at"],
        }
        for r in rows
    ]
