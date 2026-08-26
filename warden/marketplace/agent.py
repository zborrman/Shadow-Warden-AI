"""
warden/marketplace/agent.py
────────────────────────────
Marketplace agent registry — DID-based identity layer for M2M commerce.

Each MarketplaceAgent owns a W3C-compatible DID (`did:shadow:{32 base-62 chars}`)
derived deterministically from its Ed25519 public key.  On registration an AP2
spending mandate is created automatically so the agent can immediately buy/sell
within its capability set.

Database
────────
  SQLite at MARKETPLACE_DB_PATH (default /tmp/warden_marketplace.db).
  Thread-safe via RLock + WAL mode.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.marketplace.agent")

_DB_PATH  = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_DB_PATH_AT_IMPORT = _DB_PATH   # pristine; never monkeypatched

def _db_path() -> str:
    """Resolve the DB path on every call.

    DE-6 P2: this used to be read once into a module-level ``_DB_PATH`` and then
    used as a *parameter default* (``db_path: str | None = None``). Defaults bind at
    def-time, so the first value seen by the process was frozen into ~79
    signatures — no later ``MARKETPLACE_DB_PATH`` change, and no monkeypatch,
    could move them. That is the repo's own documented trap (Track F: use
    ``= None`` and resolve dynamically), and it is why test files that set the
    env at import fought over one another's databases.

    ``_DB_PATH`` is kept for callers that still reference it directly.
    """
    # An explicit override wins. Tests across this repo use
    # `monkeypatch.setattr(module, "_DB_PATH", ...)`, and callers may assign
    # it directly; re-reading the env unconditionally would silently ignore
    # both. Only when _DB_PATH is still the pristine import-time value do we
    # resolve fresh -- which is what unfreezes the parameter defaults.
    if _DB_PATH != _DB_PATH_AT_IMPORT:
        return _DB_PATH
    return data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")

_db_lock  = threading.RLock()
_DEFAULT_MANDATE_USD = float(os.getenv("MARKETPLACE_DEFAULT_MANDATE_USD", "1000"))

VALID_CAPABILITIES = {"marketplace_buy", "marketplace_sell", "marketplace_negotiate"}


# ── DID derivation ────────────────────────────────────────────────────────────

_B62_ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _pubkey_to_did_fragment(pub_b64: str) -> str:
    """Derive a 32-char base-62 fragment from an Ed25519 public key (base64)."""
    raw = base64.b64decode(pub_b64)
    n = int.from_bytes(hashlib.sha256(raw).digest(), "big")  # 256-bit → ≥43 b62
    chars: list[str] = []
    while n:
        chars.append(_B62_ALPHA[n % 62])
        n //= 62
    fragment = "".join(reversed(chars))
    return fragment[:32].ljust(32, "0")  # SHA-256 always yields ≥43 chars; pad edge


def pubkey_to_agent_id(pub_b64: str) -> str:
    return "did:shadow:" + _pubkey_to_did_fragment(pub_b64)


# ── Schema ────────────────────────────────────────────────────────────────────

_AGENTS_DDL = """
    CREATE TABLE IF NOT EXISTS marketplace_agents (
        agent_id     TEXT PRIMARY KEY,
        community_id TEXT NOT NULL,
        tenant_id    TEXT NOT NULL,
        public_key   TEXT NOT NULL,
        capabilities TEXT NOT NULL DEFAULT '[]',
        status       TEXT NOT NULL DEFAULT 'active',
        mandate_id   TEXT NOT NULL DEFAULT '',
        created_at   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_mkt_agents_community
        ON marketplace_agents(community_id);
    CREATE INDEX IF NOT EXISTS idx_mkt_agents_tenant
        ON marketplace_agents(tenant_id);
"""
register("marketplace", "warden.marketplace.agent", _AGENTS_DDL)


def _ensure_columns(con: sqlite3.Connection) -> None:
    # ALTER ADD COLUMN is not idempotent (errors on a column that already exists),
    # so it cannot be folded into the registered DDL — stays a suppress-per-connect.
    for col, defn in [
        ("name",         "TEXT NOT NULL DEFAULT ''"),
        ("budget_limit", "REAL NOT NULL DEFAULT 1000.0"),
        # Where this agent is paid when a trade settles on-chain. Ed25519 is a
        # signing identity, not an account: no Ethereum address can be derived
        # from `public_key`, so a seller that wants settlement has to say where.
        ("payout_address", "TEXT NOT NULL DEFAULT ''"),
    ]:
        try:
            con.execute(f"ALTER TABLE marketplace_agents ADD COLUMN {col} {defn}")
            con.commit()
        except Exception:
            pass  # column already exists


@contextmanager
def _conn(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    db_path = db_path or _db_path()
    with open_db(
        "marketplace", db_path, turso_name="marketplace", module_default_path=db_path
    ) as con:
        _ensure_columns(con)
        yield con


# ── Dataclass ─────────────────────────────────────────────────────────────────

@dataclass
class MarketplaceAgent:
    agent_id:     str
    community_id: str
    tenant_id:    str
    public_key:   str          # base64-encoded Ed25519 public key
    capabilities: list[str]
    status:       str
    mandate_id:   str
    created_at:   str
    payout_address: str = ""   # EIP-55 address; empty means "cannot be paid on-chain"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["capabilities"] = self.capabilities
        return d


def _row_to_agent(row: sqlite3.Row) -> MarketplaceAgent:
    # `in row` would test sqlite3.Row's *values*, not its keys.
    keys = row.keys()
    return MarketplaceAgent(
        agent_id=row["agent_id"],
        community_id=row["community_id"],
        tenant_id=row["tenant_id"],
        public_key=row["public_key"],
        capabilities=json.loads(row["capabilities"]),
        status=row["status"],
        mandate_id=row["mandate_id"],
        created_at=row["created_at"],
        # Defensive: older rows and test fixtures predate the column.
        payout_address=(row["payout_address"] if "payout_address" in keys else ""),
    )


# ── CRUD ──────────────────────────────────────────────────────────────────────

def register_agent(
    tenant_id: str,
    community_id: str,
    public_key_b64: str,
    capabilities: list[str],
    db_path: str | None = None,
) -> MarketplaceAgent:
    """Register a marketplace agent and create its AP2 mandate.

    Raises ValueError if capabilities are invalid or the public key is malformed.
    """
    # Validate capabilities
    valid = {c for c in capabilities if c in VALID_CAPABILITIES}
    if not valid:
        raise ValueError(
            f"At least one valid capability required. Valid: {VALID_CAPABILITIES}"
        )

    # Validate public key (must be decodable base64)
    try:
        base64.b64decode(public_key_b64, validate=True)
    except Exception as exc:
        raise ValueError(f"public_key must be valid base64: {exc}") from exc

    agent_id = pubkey_to_agent_id(public_key_b64)

    # Create AP2 mandate (fail-open: if commerce module unavailable, mandate_id stays "")
    mandate_id = ""
    try:
        from warden.business_community.agentic_commerce.ap2 import AP2Processor
        mandate = AP2Processor().create_mandate(
            tenant_id=tenant_id,
            max_amount=_DEFAULT_MANDATE_USD,
            currency="USD",
            allowed_merchants=["marketplace"],
        )
        mandate_id = mandate.id
    except Exception:
        log.warning("AP2Processor unavailable; agent registered without mandate")

    now = datetime.now(UTC).isoformat()
    agent = MarketplaceAgent(
        agent_id=agent_id,
        community_id=community_id,
        tenant_id=tenant_id,
        public_key=public_key_b64,
        capabilities=sorted(valid),
        status="active",
        mandate_id=mandate_id,
        created_at=now,
    )

    with _db_lock, _conn(db_path) as con:
        con.execute(
            """
            INSERT OR REPLACE INTO marketplace_agents
                (agent_id, community_id, tenant_id, public_key,
                 capabilities, status, mandate_id, created_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                agent.agent_id,
                agent.community_id,
                agent.tenant_id,
                agent.public_key,
                json.dumps(agent.capabilities),
                agent.status,
                agent.mandate_id,
                agent.created_at,
            ),
        )
    return agent


def set_payout_address(
    agent_id: str, address: str, db_path: str | None = None
) -> bool:
    """Record where this agent is paid when a trade settles on-chain.

    Validated here rather than at send time. A malformed address is a
    configuration error, and discovering it from a failed transaction costs gas
    and tells the operator only that something reverted.

    An empty string is accepted and clears the address — an agent that no longer
    wants on-chain settlement should be able to say so without deleting itself.
    """
    address = (address or "").strip()
    if address:
        try:
            from web3 import Web3  # noqa: PLC0415
        except Exception as exc:  # pragma: no cover - web3 is a hard dependency
            raise ValueError(f"cannot validate an address without web3: {exc}") from exc
        if not Web3.is_address(address):
            raise ValueError(f"{address!r} is not an Ethereum address")
        address = Web3.to_checksum_address(address)

    with _conn(db_path) as con:
        cur = con.execute(
            "UPDATE marketplace_agents SET payout_address=? WHERE agent_id=?",
            (address, agent_id),
        )
        con.commit()
        return cur.rowcount > 0


def get_agent(agent_id: str, db_path: str | None = None) -> MarketplaceAgent | None:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT * FROM marketplace_agents WHERE agent_id=?", (agent_id,)
        ).fetchone()
    return _row_to_agent(row) if row else None


def update_capabilities(
    agent_id: str,
    tenant_id: str,
    capabilities: list[str],
    db_path: str | None = None,
) -> bool:
    valid = [c for c in capabilities if c in VALID_CAPABILITIES]
    if not valid:
        raise ValueError(f"At least one valid capability required. Valid: {VALID_CAPABILITIES}")
    with _db_lock, _conn(db_path) as con:
        cur = con.execute(
            "UPDATE marketplace_agents SET capabilities=? WHERE agent_id=? AND tenant_id=?",
            (json.dumps(sorted(valid)), agent_id, tenant_id),
        )
        return cur.rowcount > 0


def update_agent(
    agent_id: str,
    *,
    name: str | None = None,
    budget_limit: float | None = None,
    db_path: str | None = None,
) -> bool:
    """Patch name and/or budget_limit on an agent (no tenant guard — caller verifies)."""
    parts: list[str] = []
    params: list[str | float] = []
    if name is not None:
        parts.append("name=?")
        params.append(name)
    if budget_limit is not None:
        parts.append("budget_limit=?")
        params.append(budget_limit)
    if not parts:
        return False
    params.append(agent_id)
    with _db_lock, _conn(db_path) as con:
        cur = con.execute(
            f"UPDATE marketplace_agents SET {', '.join(parts)} WHERE agent_id=?",
            params,
        )
        return cur.rowcount > 0


def deactivate_agent(agent_id: str, db_path: str | None = None) -> bool:
    """Set agent status → 'inactive' (soft delete, preserves audit trail)."""
    with _db_lock, _conn(db_path) as con:
        cur = con.execute(
            "UPDATE marketplace_agents SET status='inactive' WHERE agent_id=?",
            (agent_id,),
        )
        return cur.rowcount > 0


def suspend_agent(
    agent_id: str,
    tenant_id: str,
    db_path: str | None = None,
) -> bool:
    with _db_lock, _conn(db_path) as con:
        cur = con.execute(
            "UPDATE marketplace_agents SET status='suspended' WHERE agent_id=? AND tenant_id=?",
            (agent_id, tenant_id),
        )
        return cur.rowcount > 0


def list_agents(
    tenant_id: str | None = None,
    community_id: str | None = None,
    limit: int = 50,
    db_path: str | None = None,
) -> list[MarketplaceAgent]:
    query = "SELECT * FROM marketplace_agents WHERE 1=1"
    params: list = []
    if tenant_id:
        query += " AND tenant_id=?"
        params.append(tenant_id)
    if community_id:
        query += " AND community_id=?"
        params.append(community_id)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _conn(db_path) as con:
        rows = con.execute(query, params).fetchall()
    return [_row_to_agent(r) for r in rows]


def get_agent_stats(tenant_id: str, db_path: str | None = None) -> dict:
    with _conn(db_path) as con:
        total = con.execute(
            "SELECT COUNT(*) FROM marketplace_agents WHERE tenant_id=?", (tenant_id,)
        ).fetchone()[0]
        active = con.execute(
            "SELECT COUNT(*) FROM marketplace_agents WHERE tenant_id=? AND status='active'",
            (tenant_id,),
        ).fetchone()[0]
    return {"total": total, "active": active}
