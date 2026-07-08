"""
warden/billing/audit_chain.py — Zero-Trust Billing Audit Chain.

Every billable event (staff tool call, MCP paid call, ACP checkout) is
appended to a per-tenant SHA-256 hash chain stored in SQLite.  External
verifiers can replay the chain and confirm total spend without trusting
our database.

Chain integrity
───────────────
  entry_hash = SHA-256(canonical_json(entry_without_hash))
  canonical  = json.dumps(entry_dict, sort_keys=True, separators=(",",":"))
  Genesis:   prev_hash = "0" * 64

EVM attestation (optional)
──────────────────────────
  BILLING_AUDIT_EVM_ATTESTATION=true + BILLING_AUDIT_EVM_RPC_URL + BILLING_AUDIT_EVM_PRIVATE_KEY
  → periodically anchor the per-tenant chain tip hash to Base Sepolia via
    a zero-value ETH transaction with data = "0xbill_audit_v1:" + tip_hash.
  Fail-open: EVM errors never block billing writes.

Compliance mapping
──────────────────
  • SOC 2 CC6.1 — logical access controls (immutable audit trail)
  • SOC 2 A1.2  — availability: system capacity + cost monitoring
  • ISO 27001 A.5.33 — protection of records
  • GDPR Art. 30 — records of processing (spend × agent × tenant)
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from warden.config import settings

log = logging.getLogger("warden.billing.audit_chain")

_DB_PATH   = settings.billing_audit_db_path
_EVM_ON    = settings.billing_audit_evm_attestation
_EVM_RPC   = settings.billing_audit_evm_rpc_url
_EVM_KEY   = settings.billing_audit_evm_private_key
_EVM_EVERY = settings.billing_audit_evm_anchor_every  # anchor every N entries
_db_lock   = threading.RLock()

# Supported event types
STAFF_CALL   = "staff_tool_call"
MCP_CALL     = "mcp_tool_call"
ACP_CHECKOUT = "acp_checkout"
MANUAL       = "manual"


_DDL = """
    CREATE TABLE IF NOT EXISTS billing_audit_chain (
        id          INTEGER  PRIMARY KEY AUTOINCREMENT,
        entry_id    TEXT     NOT NULL UNIQUE,
        tenant_id   TEXT     NOT NULL,
        seq         INTEGER  NOT NULL,
        event_type  TEXT     NOT NULL,
        agent_id    TEXT     NOT NULL DEFAULT '',
        tool_name   TEXT     NOT NULL DEFAULT '',
        model       TEXT     NOT NULL DEFAULT '',
        input_tokens  INTEGER NOT NULL DEFAULT 0,
        output_tokens INTEGER NOT NULL DEFAULT 0,
        cost_usd    TEXT     NOT NULL DEFAULT '0',
        amount_usd  TEXT     NOT NULL DEFAULT '0',
        timestamp   TEXT     NOT NULL,
        prev_hash   TEXT     NOT NULL,
        entry_hash  TEXT     NOT NULL,
        evm_tx_hash TEXT     NOT NULL DEFAULT ''
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_bac_tenant_seq
        ON billing_audit_chain(tenant_id, seq);
    CREATE INDEX IF NOT EXISTS idx_bac_tenant
        ON billing_audit_chain(tenant_id, timestamp);
    CREATE TABLE IF NOT EXISTS billing_audit_evm_anchors (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id   TEXT NOT NULL,
        tip_seq     INTEGER NOT NULL,
        tip_hash    TEXT NOT NULL,
        tx_hash     TEXT NOT NULL DEFAULT '',
        anchored_at TEXT NOT NULL
    );
"""


# ── Schema ─────────────────────────────────────────────────────────────────────

@contextmanager
def _conn(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Yield a connection with schema applied.

    Priority:
      1. Explicit db_path → always use local SQLite (test isolation, explicit path)
      2. Turso env vars set → use Turso remote connection
      3. Fallback → local SQLite at _DB_PATH
    """
    if db_path is not None:
        # Explicit path → local SQLite (used by tests + explicit overrides)
        con = sqlite3.connect(db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(_DDL)
        try:
            yield con
            con.commit()
        finally:
            con.close()
        return

    try:
        from warden.db.turso import get_connection, is_turso_enabled  # noqa: PLC0415
        if is_turso_enabled("billing_audit"):
            with get_connection("billing_audit", fallback_path=_DB_PATH) as con:  # type: ignore[assignment]
                with suppress(Exception):
                    con.executescript(_DDL)
                yield con
            return
    except ImportError:
        pass

    # Local SQLite fallback
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_DDL)
    try:
        yield con
        con.commit()
    finally:
        con.close()


# ── Hash helpers ───────────────────────────────────────────────────────────────

def _canonical(d: dict[str, Any]) -> str:
    """Deterministic JSON for hashing — sort keys, no whitespace."""
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)


def _compute_hash(entry_dict: dict[str, Any]) -> str:
    """entry_hash = SHA-256 of canonical JSON (excluding entry_hash itself)."""
    d = {k: v for k, v in entry_dict.items() if k != "entry_hash"}
    return hashlib.sha256(_canonical(d).encode()).hexdigest()


# ── Chain append ───────────────────────────────────────────────────────────────

def append_billing_event(
    tenant_id: str,
    event_type: str,
    cost_usd: float | Decimal = Decimal("0"),
    amount_usd: float | Decimal = Decimal("0"),
    agent_id: str = "",
    tool_name: str = "",
    model: str = "",
    input_tokens: int = 0,
    output_tokens: int = 0,
    db_path: str | None = None,
) -> dict:
    """
    Append one billing event to the tenant's audit chain.

    Returns the entry dict including entry_hash and seq.
    Fail-open: returns {} on any exception.
    """
    db_path = db_path or _DB_PATH
    try:
        timestamp = datetime.now(UTC).isoformat()
        entry_id  = str(uuid.uuid4())

        with _db_lock, _conn(db_path) as con:
            # Get last entry for this tenant
            last = con.execute(
                "SELECT seq, entry_hash FROM billing_audit_chain "
                "WHERE tenant_id=? ORDER BY seq DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()

            seq       = (last["seq"] + 1) if last else 1
            prev_hash = last["entry_hash"] if last else "0" * 64

            entry = {
                "entry_id":     entry_id,
                "tenant_id":    tenant_id,
                "seq":          seq,
                "event_type":   event_type,
                "agent_id":     agent_id,
                "tool_name":    tool_name,
                "model":        model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd":     str(Decimal(str(cost_usd)).quantize(Decimal("0.000001"))),
                "amount_usd":   str(Decimal(str(amount_usd)).quantize(Decimal("0.000001"))),
                "timestamp":    timestamp,
                "prev_hash":    prev_hash,
            }
            entry["entry_hash"] = _compute_hash(entry)

            con.execute(
                "INSERT INTO billing_audit_chain "
                "(entry_id,tenant_id,seq,event_type,agent_id,tool_name,model,"
                "input_tokens,output_tokens,cost_usd,amount_usd,timestamp,prev_hash,entry_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (entry["entry_id"], tenant_id, seq, event_type, agent_id, tool_name, model,
                 input_tokens, output_tokens, entry["cost_usd"], entry["amount_usd"],
                 timestamp, prev_hash, entry["entry_hash"]),
            )

        log.debug(
            "billing_audit: tenant=%s seq=%d event=%s cost=%s hash=%s…",
            tenant_id, seq, event_type, entry["cost_usd"], str(entry["entry_hash"])[:12],
        )

        # Optional EVM attestation (background, fail-open)
        if _EVM_ON and seq % _EVM_EVERY == 0:
            threading.Thread(
                target=_anchor_to_evm,
                args=(tenant_id, seq, entry["entry_hash"], db_path),
                daemon=True,
            ).start()

        return entry

    except Exception as exc:  # noqa: BLE001
        log.warning("billing_audit append failed (fail-open): %s", exc)
        return {}


# ── Chain verification ─────────────────────────────────────────────────────────

def verify_chain(tenant_id: str, db_path: str | None = None) -> dict:
    """
    Re-hash every entry and confirm the chain is intact.

    Returns {"valid": bool, "entries": int, "tip_hash": str, "first_broken_seq": int | None}.
    """
    db_path = db_path or _DB_PATH
    try:
        with _db_lock, _conn(db_path) as con:
            rows = con.execute(
                "SELECT * FROM billing_audit_chain WHERE tenant_id=? ORDER BY seq ASC",
                (tenant_id,),
            ).fetchall()

        if not rows:
            return {"valid": True, "entries": 0, "tip_hash": "0" * 64, "first_broken_seq": None}

        expected_prev = "0" * 64
        for row in rows:
            d = dict(row)
            if d["prev_hash"] != expected_prev:
                return {
                    "valid": False,
                    "entries": len(rows),
                    "tip_hash": d["entry_hash"],
                    "first_broken_seq": d["seq"],
                    "reason": "prev_hash_mismatch",
                }
            expected = _compute_hash({k: v for k, v in d.items() if k not in ("id", "entry_hash", "evm_tx_hash")})
            if expected != d["entry_hash"]:
                return {
                    "valid": False,
                    "entries": len(rows),
                    "tip_hash": d["entry_hash"],
                    "first_broken_seq": d["seq"],
                    "reason": "entry_hash_mismatch",
                }
            expected_prev = d["entry_hash"]

        last = dict(rows[-1])
        return {
            "valid":            True,
            "entries":          len(rows),
            "tip_hash":         last["entry_hash"],
            "tip_seq":          last["seq"],
            "first_broken_seq": None,
        }

    except Exception as exc:  # noqa: BLE001
        log.warning("billing_audit verify failed: %s", exc)
        return {"valid": False, "entries": 0, "tip_hash": "", "first_broken_seq": None, "error": str(exc)}


# ── Chain query ────────────────────────────────────────────────────────────────

def get_chain(
    tenant_id: str,
    limit: int = 200,
    offset: int = 0,
    db_path: str | None = None,
) -> list[dict]:
    db_path = db_path or _DB_PATH
    try:
        with _db_lock, _conn(db_path) as con:
            rows = con.execute(
                "SELECT * FROM billing_audit_chain WHERE tenant_id=? "
                "ORDER BY seq DESC LIMIT ? OFFSET ?",
                (tenant_id, limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as exc:  # noqa: BLE001
        log.warning("billing_audit get_chain failed: %s", exc)
        return []


def get_summary(tenant_id: str, db_path: str | None = None) -> dict:
    """Total spend, entry count, and tip hash."""
    db_path = db_path or _DB_PATH
    try:
        with _db_lock, _conn(db_path) as con:
            row = con.execute(
                "SELECT COUNT(*) as cnt, SUM(CAST(cost_usd AS REAL)) as total_cost, "
                "SUM(CAST(amount_usd AS REAL)) as total_amount "
                "FROM billing_audit_chain WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            tip = con.execute(
                "SELECT entry_hash, seq FROM billing_audit_chain WHERE tenant_id=? ORDER BY seq DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
        return {
            "tenant_id":       tenant_id,
            "entry_count":     row["cnt"] or 0,
            "total_cost_usd":  round(row["total_cost"] or 0.0, 6),
            "total_amount_usd": round(row["total_amount"] or 0.0, 6),
            "tip_hash":        tip["entry_hash"] if tip else "0" * 64,
            "tip_seq":         tip["seq"] if tip else 0,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("billing_audit summary failed: %s", exc)
        return {"tenant_id": tenant_id, "entry_count": 0, "total_cost_usd": 0.0}


def export_jsonl(tenant_id: str, db_path: str | None = None) -> str:
    """Export full chain as JSONL — one entry per line."""
    entries = get_chain(tenant_id, limit=100_000, offset=0, db_path=db_path)
    entries.sort(key=lambda e: e.get("seq", 0))
    return "\n".join(json.dumps(e, default=str) for e in entries)


# ── EVM attestation ────────────────────────────────────────────────────────────

def _anchor_to_evm(tenant_id: str, seq: int, tip_hash: str, db_path: str) -> None:
    """
    Anchor the chain tip hash to Base Sepolia via a zero-value ETH transaction.
    data field: 0xbill_audit_v1:<tenant_id>:<seq>:<tip_hash>
    Fail-open: any exception is logged and swallowed.
    """
    if not _EVM_KEY:
        log.debug("billing_audit: EVM_PRIVATE_KEY not set — skipping attestation")
        return
    try:
        from web3 import Web3  # noqa: PLC0415
        w3    = Web3(Web3.HTTPProvider(_EVM_RPC))
        acct  = w3.eth.account.from_key(_EVM_KEY)
        nonce = w3.eth.get_transaction_count(acct.address)
        data  = f"bill_audit_v1:{tenant_id}:{seq}:{tip_hash}".encode()
        tx = acct.sign_transaction({
            "to":       acct.address,      # self-send (no USDC, just anchoring)
            "value":    0,
            "gas":      30_000,
            "gasPrice": w3.eth.gas_price,
            "nonce":    nonce,
            "chainId":  84532,             # Base Sepolia
            "data":     data,
        })
        tx_hash = w3.eth.send_raw_transaction(tx.raw_transaction).hex()

        with _db_lock, _conn(db_path) as con:
            con.execute(
                "INSERT INTO billing_audit_evm_anchors (tenant_id,tip_seq,tip_hash,tx_hash,anchored_at) "
                "VALUES (?,?,?,?,?)",
                (tenant_id, seq, tip_hash, tx_hash, datetime.now(UTC).isoformat()),
            )
            con.execute(
                "UPDATE billing_audit_chain SET evm_tx_hash=? WHERE tenant_id=? AND seq=?",
                (tx_hash, tenant_id, seq),
            )
        log.info("billing_audit: EVM anchor tenant=%s seq=%d tx=%s", tenant_id, seq, tx_hash[:16])

    except Exception as exc:  # noqa: BLE001
        log.warning("billing_audit: EVM anchor failed (fail-open): %s", exc)
