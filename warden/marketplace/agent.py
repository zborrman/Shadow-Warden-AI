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

log = logging.getLogger("warden.marketplace.agent")

_DB_PATH  = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
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

def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
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
    """)


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


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

    def to_dict(self) -> dict:
        d = asdict(self)
        d["capabilities"] = self.capabilities
        return d


def _row_to_agent(row: sqlite3.Row) -> MarketplaceAgent:
    return MarketplaceAgent(
        agent_id=row["agent_id"],
        community_id=row["community_id"],
        tenant_id=row["tenant_id"],
        public_key=row["public_key"],
        capabilities=json.loads(row["capabilities"]),
        status=row["status"],
        mandate_id=row["mandate_id"],
        created_at=row["created_at"],
    )


# ── CRUD ──────────────────────────────────────────────────────────────────────

def register_agent(
    tenant_id: str,
    community_id: str,
    public_key_b64: str,
    capabilities: list[str],
    db_path: str = _DB_PATH,
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


def get_agent(agent_id: str, db_path: str = _DB_PATH) -> MarketplaceAgent | None:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT * FROM marketplace_agents WHERE agent_id=?", (agent_id,)
        ).fetchone()
    return _row_to_agent(row) if row else None


def update_capabilities(
    agent_id: str,
    tenant_id: str,
    capabilities: list[str],
    db_path: str = _DB_PATH,
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


def suspend_agent(
    agent_id: str,
    tenant_id: str,
    db_path: str = _DB_PATH,
) -> bool:
    with _db_lock, _conn(db_path) as con:
        cur = con.execute(
            "UPDATE marketplace_agents SET status='suspended' WHERE agent_id=? AND tenant_id=?",
            (agent_id, tenant_id),
        )
        return cur.rowcount > 0
