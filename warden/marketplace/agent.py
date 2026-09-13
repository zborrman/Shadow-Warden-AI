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
        created_at   TEXT NOT NULL,
        -- Declared here so a fresh database gets them from registered DDL;
        -- `_ensure_columns` still backfills databases that predate them.
        payout_address           TEXT NOT NULL DEFAULT '',
        payout_address_signed_at TEXT NOT NULL DEFAULT ''
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
        # Timestamp of the signed envelope that set `payout_address`. A newer
        # binding must carry a strictly later timestamp, so a captured signature
        # for an address the agent has since replaced cannot roll it back.
        ("payout_address_signed_at", "TEXT NOT NULL DEFAULT ''"),
    ]:
        try:
            con.execute(f"ALTER TABLE marketplace_agents ADD COLUMN {col} {defn}")
            con.commit()
        except Exception as exc:
            # Only "that column is already there". A bare `pass` here hid every
            # error equally, which was survivable while this ran on every
            # connection — a transient failure retried on the next one. It is
            # not survivable now that it runs once per process: a swallowed
            # outage would mark the database backfilled for the life of the
            # worker. Anything else propagates, so the memo is not set.
            if "duplicate column" not in str(exc).lower():
                raise


# Databases whose ALTER-based column backfill has already run in this process.
_columns_ensured: set[str] = set()
_ensure_lock = threading.Lock()


def reset_column_memo() -> None:
    """Forget which databases have been backfilled (tests that recreate a file)."""
    with _ensure_lock:
        _columns_ensured.clear()


@contextmanager
def _conn(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    db_path = db_path or _db_path()
    with open_db(
        "marketplace", db_path, turso_name="marketplace", module_default_path=db_path
    ) as con:
        # Once per database, not once per connection. Each ALTER here is
        # expected to fail on an existing column, and on Turso — where this
        # database lives in production — a failing statement still costs a
        # full HTTPS round trip, so this ran up ~1.4 s on every
        # ``GET /marketplace/agents``. Fail-safe: the memo is only set after
        # the backfill completes, so a raising call is retried next time.
        with _ensure_lock:
            if db_path not in _columns_ensured:
                _ensure_columns(con)
                _columns_ensured.add(db_path)
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

    # First registration wins; re-registration never mutates. Registration is
    # deliberately unauthenticated (Stage 1 first contact, owner decision D-5)
    # and `GET /agents/{id}` publishes the public key, so anyone can submit an
    # existing agent's key. This used to be `INSERT OR REPLACE`, which SQLite
    # executes as delete-then-insert: a stranger's call replaced the victim's
    # row wholesale — new tenant_id, a lifted suspension, and a wiped
    # `payout_address_signed_at` that silently disabled the payout rollback
    # guard.
    #
    # The row is reserved FIRST, with no mandate, and only the registration
    # whose INSERT succeeds goes on to create one. A check-then-create-then-
    # insert order let two concurrent registrations of one key both pass the
    # check and both create an AP2 mandate, leaving the loser's orphaned. The
    # INSERT is the single arbiter: the primary key refuses the second caller
    # before it has done anything worth undoing.
    now = datetime.now(UTC).isoformat()
    agent = MarketplaceAgent(
        agent_id=agent_id,
        community_id=community_id,
        tenant_id=tenant_id,
        public_key=public_key_b64,
        capabilities=sorted(valid),
        status="active",
        mandate_id="",
        created_at=now,
    )

    with _db_lock, _conn(db_path) as con:
        try:
            con.execute(
                """
                INSERT INTO marketplace_agents
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
        except sqlite3.Error as exc:
            # Local SQLite raises IntegrityError; the Turso adapter surfaces the
            # same constraint as OperationalError, so match on the message too.
            if isinstance(exc, sqlite3.IntegrityError) or "UNIQUE constraint" in str(exc):
                raise AgentAlreadyRegisteredError(
                    f"Agent {agent_id!r} is already registered; "
                    "registration does not update an agent."
                ) from exc
            raise

    # Only the winning registration reaches here. Fail-open as before: if the
    # commerce module is unavailable the agent stays registered with no mandate,
    # which was already a valid state.
    try:
        from warden.business_community.agentic_commerce.ap2 import AP2Processor
        mandate = AP2Processor().create_mandate(
            tenant_id=tenant_id,
            max_amount=_DEFAULT_MANDATE_USD,
            currency="USD",
            allowed_merchants=["marketplace"],
        )
    except Exception:
        log.warning("AP2Processor unavailable; agent registered without mandate")
        return agent

    with _db_lock, _conn(db_path) as con:
        # `AND mandate_id=''` so this can only ever fill the slot it reserved.
        con.execute(
            "UPDATE marketplace_agents SET mandate_id=? WHERE agent_id=? AND mandate_id=''",
            (mandate.id, agent_id),
        )
        con.commit()
    agent.mandate_id = mandate.id
    return agent


class AgentAlreadyRegisteredError(ValueError):
    """Registration was refused because the agent already exists."""


class PayoutAddressError(ValueError):
    """A payout-address binding was refused. Always fail-CLOSED."""


# Domain tag for the envelope. An agent's Ed25519 key also signs offers
# (`negotiation._canonical_offer`); without a distinct purpose, a signature
# produced for one protocol message could be presented as the other.
_PAYOUT_ADDRESS_PURPOSE = "shadow-warden:payout-address:v1"


def build_payout_address_canonical(*, agent_id: str, address: str, timestamp: str) -> bytes:
    """The exact bytes an agent signs to bind a settlement address to itself.

    Exported so an agent SDK and the tests derive the envelope from the same
    code the server verifies against — a hand-rolled client copy is how
    signature schemes quietly stop matching (see ``build_offer_canonical``).

    ``address`` is the EIP-55 checksummed form, or ``""`` to clear it. The
    server normalises before verifying, so a client must sign the checksummed
    string, not whatever casing it happened to hold.
    """
    envelope = {
        "purpose":   _PAYOUT_ADDRESS_PURPOSE,
        "agent_id":  agent_id,
        "address":   address,
        "timestamp": timestamp,
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def _normalise_address(address: str) -> str:
    address = (address or "").strip()
    if not address:
        return ""
    try:
        from web3 import Web3  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover - web3 is a hard dependency
        raise PayoutAddressError(f"cannot validate an address without web3: {exc}") from exc
    if not Web3.is_address(address):
        raise PayoutAddressError(f"{address!r} is not an Ethereum address")
    return str(Web3.to_checksum_address(address))


def bind_payout_address(
    agent_id: str,
    address: str,
    *,
    signature: str,
    timestamp: str,
    db_path: str | None = None,
) -> str:
    """Bind a settlement address to an agent, proven by the agent's own key.

    Why this exists: an agent is identified by an **Ed25519** key
    (``did:shadow:{base62(sha256(pubkey))}``), but a trade settles to a
    **secp256k1** Ethereum address. Nothing can derive one from the other, so
    without a binding the reputation an agent earns and the wallet that gets
    paid are two unrelated facts — and whoever can write ``payout_address``
    decides where a seller's money goes. That is a theft primitive, not a
    configuration field.

    The binding is the agent signing ``{purpose, agent_id, address, timestamp}``
    with the key it registered. ``agent_id`` is *derived from* that key, so a
    signature that verifies against ``marketplace_agents.public_key`` is proof
    the address was chosen by the agent it is attributed to — the same
    argument ``negotiation._assert_actor`` makes for offers.

    **Always fail-CLOSED, with no enforcement flag.** Offers got a bake-in flag
    because unsigned clients existed; this route has none to break, and an
    unenforced mode would ship the theft primitive it closes. Unknown agent,
    missing key, missing or invalid signature, a timestamp outside the skew
    window, or one not newer than the current binding all refuse.

    Returns the stored (checksummed) address.
    """
    # Lazy: negotiation imports this module inside functions, so a module-level
    # import here would be the first half of a cycle.
    from warden.marketplace.negotiation import _timestamp_within_skew

    normalised = _normalise_address(address)

    if not signature:
        raise PayoutAddressError(
            "A payout address must be signed with the agent's registered Ed25519 key."
        )
    if not _timestamp_within_skew(timestamp):
        raise PayoutAddressError(
            f"Timestamp {timestamp!r} is outside the acceptance window."
        )
    ordering_key = _ordering_key(timestamp)

    agent = get_agent(agent_id, db_path=db_path)
    if agent is None:
        raise PayoutAddressError(f"Agent {agent_id!r} is not registered.")
    if not agent.public_key:
        raise PayoutAddressError(f"Agent {agent_id!r} has no registered public key.")

    canonical = build_payout_address_canonical(
        agent_id=agent_id, address=normalised, timestamp=timestamp
    )
    if not _verify_payout_signature(canonical, signature, agent.public_key):
        raise PayoutAddressError(
            "Signature does not verify against the agent's registered public key."
        )

    # The ordering check and the write are ONE statement. Read-check-write let
    # two concurrent binds both pass the check against the same stored value,
    # and whichever wrote last won — so an older binding could land after a
    # newer one, which is the rollback this guard exists to refuse.
    #
    # Ordering compares `_ordering_key` strings: fixed-width UTC, so string
    # order is chronological order in SQL. `''` sorts before every key, which
    # is what lets the first binding through.
    with _conn(db_path) as con:
        cur = con.execute(
            "UPDATE marketplace_agents SET payout_address=?, payout_address_signed_at=? "
            "WHERE agent_id=? AND payout_address_signed_at < ?",
            (normalised, ordering_key, agent_id, ordering_key),
        )
        con.commit()
        if cur.rowcount == 0:
            raise PayoutAddressError(
                "A newer payout-address binding already exists; refusing to roll back."
            )
    return normalised


def _verify_payout_signature(canonical: bytes, signature_b64: str, public_key_b64: str) -> bool:
    """Ed25519 verify over the payout envelope. False on any error.

    A named seam over the offer verifier — the primitive is identical, and one
    implementation of Ed25519 verification is what keeps the two from drifting.
    """
    from warden.marketplace.negotiation import _verify_offer_signature

    return _verify_offer_signature(canonical, signature_b64, public_key_b64)


def _ordering_key(timestamp: str) -> str:
    """Fixed-width UTC rendering of an ISO-8601 instant, so string order is time order.

    Stored in `payout_address_signed_at` and compared in SQL. The signature is
    still verified over the client's original string; only the ordering uses
    this form. Assumes `_timestamp_within_skew` has already accepted the input.
    """
    parsed = datetime.fromisoformat(timestamp)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


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
