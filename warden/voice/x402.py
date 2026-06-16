"""
warden/voice/x402.py
HTTP 402 Micropayment Protocol — per-API-call USDC micro-charges via payment channels.

Flow
----
  1. Agent calls a paid resource endpoint.
  2. If balance insufficient → raise HTTP 402 with payment instructions.
  3. Agent funds payment channel / completes payment.
  4. POST /voice/x402/confirm → access granted, balance deducted.

Storage: SQLite (VOICE_X402_DB_PATH) + in-process fallback.
Network: Polygon Amoy or Base Sepolia testnets (configurable).
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass

from fastapi import HTTPException

log = logging.getLogger("warden.voice.x402")

_DB_PATH      = os.getenv("VOICE_X402_DB_PATH", "/tmp/warden_voice_x402.db")
_CHAIN_RPC    = os.getenv("VOICE_X402_RPC", "https://rpc-amoy.polygon.technology")
_PAYMENT_ADDR = os.getenv("VOICE_X402_PAYMENT_ADDRESS", "0x0000000000000000000000000000000000000000")
_db_lock      = threading.RLock()


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS x402_balances (
            agent_id    TEXT PRIMARY KEY,
            balance_usd REAL NOT NULL DEFAULT 0.0,
            updated_at  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS x402_channels (
            channel_id  TEXT PRIMARY KEY,
            agent_id    TEXT NOT NULL,
            initial_usd REAL NOT NULL,
            status      TEXT NOT NULL DEFAULT 'open',
            created_at  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS x402_transactions (
            tx_id       TEXT PRIMARY KEY,
            agent_id    TEXT NOT NULL,
            amount_usd  REAL NOT NULL,
            resource    TEXT NOT NULL,
            verified    INTEGER NOT NULL DEFAULT 0,
            ts          TEXT NOT NULL
        );
    """)


@dataclass
class PaymentRequest:
    service_id:      str
    amount_usd:      float
    payment_address: str
    payment_uri:     str
    expires_at:      str


@dataclass
class PaymentChannel:
    channel_id:     str
    agent_id:       str
    balance_usd:    float
    status:         str


class X402Protocol:
    """HTTP 402 micropayment processor."""

    # ── Payments ───────────────────────────────────────────────────────────────

    def generate_402_response(
        self, service_id: str, amount_usd: float, payment_address: str | None = None
    ) -> HTTPException:
        """Return HTTP 402 with payment instructions when balance insufficient."""
        addr    = payment_address or _PAYMENT_ADDR
        expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 300))
        detail  = {
            "error":           "payment_required",
            "service":         service_id,
            "amount_usd":      amount_usd,
            "payment_address": addr,
            "payment_uri":     f"web3:{addr}?amount={amount_usd}&currency=USDC&chain=polygon-amoy",
            "expires_at":      expires,
            "instructions":    "Send USDC to the payment_address, then POST /voice/x402/confirm",
        }
        return HTTPException(status_code=402, detail=detail)

    def verify_payment(self, tx_hash: str, expected_amount: float, expected_recipient: str) -> bool:
        """Verify on-chain payment. Falls back to stored tx_hash check when no RPC."""
        if not tx_hash:
            return False
        # Check if already verified locally
        with _db_lock:
            con = sqlite3.connect(_DB_PATH, check_same_thread=False)
            try:
                _ensure_schema(con)
                row = con.execute(
                    "SELECT verified FROM x402_transactions WHERE tx_id = ?", (tx_hash,)
                ).fetchone()
                if row and row[0]:
                    return True
            finally:
                con.close()
        # Attempt on-chain verification
        try:
            return self._verify_on_chain(tx_hash, expected_amount, expected_recipient)
        except Exception as exc:
            log.warning("x402 on-chain verify failed (fail-closed): %s", exc)
            return False

    def create_payment_channel(self, agent_id: str, initial_balance_usd: float) -> str:
        """Open a pre-funded payment channel for the agent."""
        cid = str(uuid.uuid4())
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with _db_lock:
            con = sqlite3.connect(_DB_PATH, check_same_thread=False)
            try:
                _ensure_schema(con)
                con.execute(
                    "INSERT INTO x402_channels (channel_id, agent_id, initial_usd, status, created_at) "
                    "VALUES (?, ?, ?, 'open', ?)",
                    (cid, agent_id, initial_balance_usd, now),
                )
                con.execute(
                    "INSERT INTO x402_balances (agent_id, balance_usd, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(agent_id) DO UPDATE SET balance_usd = balance_usd + excluded.balance_usd, "
                    "updated_at = excluded.updated_at",
                    (agent_id, initial_balance_usd, now),
                )
                con.commit()
            finally:
                con.close()
        return cid

    # ── Balance management ─────────────────────────────────────────────────────

    def get_balance(self, agent_id: str) -> float:
        with _db_lock:
            con = sqlite3.connect(_DB_PATH, check_same_thread=False)
            try:
                _ensure_schema(con)
                row = con.execute(
                    "SELECT balance_usd FROM x402_balances WHERE agent_id = ?", (agent_id,)
                ).fetchone()
                return float(row[0]) if row else 0.0
            finally:
                con.close()

    def deduct(self, agent_id: str, amount_usd: float, resource: str) -> bool:
        """Deduct amount from agent balance.  Returns False if insufficient."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with _db_lock:
            con = sqlite3.connect(_DB_PATH, check_same_thread=False)
            try:
                _ensure_schema(con)
                row = con.execute(
                    "SELECT balance_usd FROM x402_balances WHERE agent_id = ?", (agent_id,)
                ).fetchone()
                balance = float(row[0]) if row else 0.0
                if balance < amount_usd:
                    return False
                new_bal = balance - amount_usd
                con.execute(
                    "UPDATE x402_balances SET balance_usd = ?, updated_at = ? WHERE agent_id = ?",
                    (new_bal, now, agent_id),
                )
                con.execute(
                    "INSERT INTO x402_transactions (tx_id, agent_id, amount_usd, resource, verified, ts) "
                    "VALUES (?, ?, ?, ?, 1, ?)",
                    (str(uuid.uuid4()), agent_id, amount_usd, resource, now),
                )
                con.commit()
                return True
            finally:
                con.close()

    def confirm_payment(self, tx_hash: str, agent_id: str, amount_usd: float, resource: str) -> bool:
        """Confirm external payment and credit agent balance."""
        if not self.verify_payment(tx_hash, amount_usd, _PAYMENT_ADDR):
            return False
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with _db_lock:
            con = sqlite3.connect(_DB_PATH, check_same_thread=False)
            try:
                _ensure_schema(con)
                con.execute(
                    "INSERT INTO x402_transactions (tx_id, agent_id, amount_usd, resource, verified, ts) "
                    "VALUES (?, ?, ?, ?, 1, ?)",
                    (tx_hash, agent_id, amount_usd, resource, now),
                )
                con.execute(
                    "INSERT INTO x402_balances (agent_id, balance_usd, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(agent_id) DO UPDATE SET "
                    "balance_usd = balance_usd + excluded.balance_usd, updated_at = excluded.updated_at",
                    (agent_id, amount_usd, now),
                )
                con.commit()
                return True
            finally:
                con.close()

    def close_channel(self, channel_id: str) -> bool:
        with _db_lock:
            con = sqlite3.connect(_DB_PATH, check_same_thread=False)
            try:
                _ensure_schema(con)
                con.execute(
                    "UPDATE x402_channels SET status = 'closed' WHERE channel_id = ?", (channel_id,)
                )
                con.commit()
                return True
            finally:
                con.close()

    # ── On-chain verification (best-effort) ────────────────────────────────────

    def _verify_on_chain(self, tx_hash: str, amount_usd: float, recipient: str) -> bool:
        import httpx  # noqa: PLC0415
        payload = {"jsonrpc": "2.0", "method": "eth_getTransactionReceipt", "params": [tx_hash], "id": 1}
        resp    = httpx.post(_CHAIN_RPC, json=payload, timeout=10.0)
        resp.raise_for_status()
        data    = resp.json()
        result  = data.get("result")
        if not result:
            return False
        return result.get("status") == "0x1"
