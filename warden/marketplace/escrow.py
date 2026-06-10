"""
warden/marketplace/escrow.py
──────────────────────────────
EscrowService — manages the lifecycle of escrow contracts for M2M trades.

Design
──────
  Real Web3 (eth_tester / Ganache / Sepolia) is optional.
  When no RPC is configured the service uses a deterministic simulation:
    contract_address = keccak256(buyer|seller|listing|nonce)[:20] as hex
  This keeps all tests green without a running blockchain.

  The Solidity contract source is at:
    warden/blockchain/contracts/Escrow.sol

Lifecycle
─────────
  create_escrow()      → status: pending_deposit
  fund_escrow()        → status: funded          (buyer deposits)
  deliver_asset()      → status: delivered       (seller submits asset hash)
  confirm_receipt()    → status: confirmed        (buyer confirms → finalize_purchase())
  raise_dispute()      → status: disputed
  resolve_dispute()    → status: resolved_buyer | resolved_seller
  cancel_escrow()      → status: cancelled       (refund after 48h timeout)

Table: marketplace_escrow (shared MARKETPLACE_DB_PATH)
"""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Generator

log = logging.getLogger("warden.marketplace.escrow")

_DB_PATH   = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_db_lock   = threading.RLock()
_DELIVERY_TIMEOUT_HOURS = int(os.getenv("ESCROW_DELIVERY_TIMEOUT_HOURS", "48"))


# ── Schema ────────────────────────────────────────────────────────────────────

def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS marketplace_escrow (
            escrow_id        TEXT PRIMARY KEY,
            purchase_id      TEXT NOT NULL DEFAULT '',
            listing_id       TEXT NOT NULL,
            buyer_agent      TEXT NOT NULL,
            seller_agent     TEXT NOT NULL,
            amount_usd       REAL NOT NULL DEFAULT 0.0,
            contract_address TEXT NOT NULL DEFAULT '',
            status           TEXT NOT NULL DEFAULT 'pending_deposit',
            asset_hash       TEXT NOT NULL DEFAULT '',
            dispute_reason   TEXT NOT NULL DEFAULT '',
            created_at       TEXT NOT NULL,
            funded_at        TEXT,
            delivered_at     TEXT,
            confirmed_at     TEXT,
            expires_at       TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_esc_buyer  ON marketplace_escrow(buyer_agent);
        CREATE INDEX IF NOT EXISTS idx_esc_seller ON marketplace_escrow(seller_agent);
        CREATE INDEX IF NOT EXISTS idx_esc_listing ON marketplace_escrow(listing_id);
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
class Escrow:
    escrow_id:        str
    purchase_id:      str
    listing_id:       str
    buyer_agent:      str
    seller_agent:     str
    amount_usd:       float
    contract_address: str
    status:           str
    asset_hash:       str
    dispute_reason:   str
    created_at:       str
    funded_at:        str | None
    delivered_at:     str | None
    confirmed_at:     str | None
    expires_at:       str

    def to_dict(self) -> dict:
        return asdict(self)

    def is_expired(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.expires_at)
            return datetime.now(UTC) > exp
        except Exception:
            return False


def _row_to_escrow(row: sqlite3.Row) -> Escrow:
    return Escrow(
        escrow_id=row["escrow_id"],
        purchase_id=row["purchase_id"],
        listing_id=row["listing_id"],
        buyer_agent=row["buyer_agent"],
        seller_agent=row["seller_agent"],
        amount_usd=row["amount_usd"],
        contract_address=row["contract_address"],
        status=row["status"],
        asset_hash=row["asset_hash"],
        dispute_reason=row["dispute_reason"],
        created_at=row["created_at"],
        funded_at=row["funded_at"],
        delivered_at=row["delivered_at"],
        confirmed_at=row["confirmed_at"],
        expires_at=row["expires_at"],
    )


# ── Simulated contract address ────────────────────────────────────────────────

def _sim_contract_address(buyer: str, seller: str, listing_id: str, nonce: str) -> str:
    raw = f"{buyer}:{seller}:{listing_id}:{nonce}".encode()
    return "0x" + hashlib.sha256(raw).hexdigest()[:40]


# ── EscrowService ─────────────────────────────────────────────────────────────

class EscrowService:
    """
    Manages escrow lifecycle for marketplace purchases.

    Web3 calls are attempted via `warden.blockchain.chain_connector`; if that
    module is unavailable or no RPC is configured, the service falls back to
    a deterministic simulation that is fully testable without a blockchain.
    """

    def create_escrow(
        self,
        listing_id: str,
        buyer_agent_id: str,
        seller_agent_id: str,
        amount_usd: float,
        purchase_id: str = "",
        db_path: str = _DB_PATH,
    ) -> Escrow:
        escrow_id = f"ESC-{uuid.uuid4().hex[:12].upper()}"
        now       = datetime.now(UTC).isoformat()
        expires   = (datetime.now(UTC) + timedelta(hours=_DELIVERY_TIMEOUT_HOURS)).isoformat()
        contract  = self._deploy_contract(buyer_agent_id, seller_agent_id, listing_id, escrow_id)

        escrow = Escrow(
            escrow_id=escrow_id,
            purchase_id=purchase_id,
            listing_id=listing_id,
            buyer_agent=buyer_agent_id,
            seller_agent=seller_agent_id,
            amount_usd=amount_usd,
            contract_address=contract,
            status="pending_deposit",
            asset_hash="",
            dispute_reason="",
            created_at=now,
            funded_at=None,
            delivered_at=None,
            confirmed_at=None,
            expires_at=expires,
        )
        with _db_lock, _conn(db_path) as con:
            con.execute(
                """INSERT INTO marketplace_escrow
                   (escrow_id, purchase_id, listing_id, buyer_agent, seller_agent,
                    amount_usd, contract_address, status, asset_hash, dispute_reason,
                    created_at, funded_at, delivered_at, confirmed_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    escrow.escrow_id, escrow.purchase_id, escrow.listing_id,
                    escrow.buyer_agent, escrow.seller_agent, escrow.amount_usd,
                    escrow.contract_address, escrow.status, escrow.asset_hash,
                    escrow.dispute_reason, escrow.created_at, escrow.funded_at,
                    escrow.delivered_at, escrow.confirmed_at, escrow.expires_at,
                ),
            )
        log.info("Escrow created: %s contract=%s", escrow_id, contract)
        return escrow

    def fund_escrow(self, escrow_id: str, db_path: str = _DB_PATH) -> bool:
        """Buyer deposits — transitions to 'funded'."""
        esc = self._get(escrow_id, db_path)
        if esc is None or esc.status != "pending_deposit":
            return False
        self._call_contract(esc.contract_address, "deposit", {})
        self._update_status(escrow_id, "funded", {"funded_at": datetime.now(UTC).isoformat()}, db_path)
        return True

    def deliver_asset(
        self,
        escrow_id: str,
        asset_hash: str,
        db_path: str = _DB_PATH,
    ) -> bool:
        """Seller delivers asset hash — transitions to 'delivered'."""
        esc = self._get(escrow_id, db_path)
        if esc is None or esc.status != "funded":
            return False
        self._call_contract(esc.contract_address, "deliverAsset", {"assetHash": asset_hash})
        self._update_status(
            escrow_id, "delivered",
            {"delivered_at": datetime.now(UTC).isoformat(), "asset_hash": asset_hash},
            db_path,
        )
        return True

    def confirm_receipt(
        self,
        escrow_id: str,
        purchase_id: str = "",
        db_path: str = _DB_PATH,
    ) -> bool:
        """Buyer confirms receipt → funds released to seller + purchase finalized."""
        esc = self._get(escrow_id, db_path)
        if esc is None or esc.status != "delivered":
            return False
        self._call_contract(esc.contract_address, "confirmReceipt", {})
        now = datetime.now(UTC).isoformat()
        self._update_status(escrow_id, "confirmed", {"confirmed_at": now}, db_path)
        # Finalize the purchase record
        pid = purchase_id or esc.purchase_id
        if pid:
            try:
                from warden.marketplace.listing import finalize_purchase
                finalize_purchase(pid, escrow_id=escrow_id, db_path=db_path)
            except Exception as exc:
                log.warning("finalize_purchase failed for %s: %s", pid, exc)
        return True

    def raise_dispute(
        self,
        escrow_id: str,
        reason: str,
        db_path: str = _DB_PATH,
    ) -> bool:
        esc = self._get(escrow_id, db_path)
        if esc is None or esc.status not in ("funded", "delivered"):
            return False
        self._call_contract(esc.contract_address, "raiseDispute", {"reason": reason})
        with _db_lock, _conn(db_path) as con:
            con.execute(
                "UPDATE marketplace_escrow SET status='disputed', dispute_reason=? WHERE escrow_id=?",
                (reason, escrow_id),
            )
        return True

    def resolve_dispute(
        self,
        escrow_id: str,
        release_to_buyer: bool,
        db_path: str = _DB_PATH,
    ) -> bool:
        esc = self._get(escrow_id, db_path)
        if esc is None or esc.status != "disputed":
            return False
        verdict = "resolved_buyer" if release_to_buyer else "resolved_seller"
        self._call_contract(
            esc.contract_address, "resolveDispute", {"releaseToBuyer": release_to_buyer}
        )
        self._update_status(escrow_id, verdict, {}, db_path)
        return True

    def cancel_escrow(self, escrow_id: str, db_path: str = _DB_PATH) -> bool:
        """Cancel after delivery timeout expiry — refunds buyer."""
        esc = self._get(escrow_id, db_path)
        if esc is None:
            return False
        if esc.status not in ("pending_deposit", "funded"):
            return False
        if not esc.is_expired():
            return False
        self._call_contract(esc.contract_address, "cancelDeposit", {})
        self._update_status(escrow_id, "cancelled", {}, db_path)
        log.info("Escrow %s cancelled (timeout)", escrow_id)
        return True

    def get_escrow(self, escrow_id: str, db_path: str = _DB_PATH) -> Escrow | None:
        return self._get(escrow_id, db_path)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _deploy_contract(
        self, buyer: str, seller: str, listing_id: str, nonce: str
    ) -> str:
        try:
            from warden.blockchain.chain_connector import ChainConnector
            cc = ChainConnector()
            if cc.is_connected():
                return cc.deploy_escrow(buyer, seller)
        except Exception:
            pass
        return _sim_contract_address(buyer, seller, listing_id, nonce)

    def _call_contract(self, contract_address: str, fn_name: str, params: dict) -> None:
        try:
            from warden.blockchain.chain_connector import ChainConnector
            cc = ChainConnector()
            if cc.is_connected():
                cc.call(contract_address, fn_name, params)
        except Exception:
            pass

    def _get(self, escrow_id: str, db_path: str) -> Escrow | None:
        with _conn(db_path) as con:
            row = con.execute(
                "SELECT * FROM marketplace_escrow WHERE escrow_id=?", (escrow_id,)
            ).fetchone()
        return _row_to_escrow(row) if row else None

    def _update_status(
        self,
        escrow_id: str,
        status: str,
        extras: dict,
        db_path: str,
    ) -> None:
        sets = ["status=?"]
        vals: list = [status]
        for col, val in extras.items():
            sets.append(f"{col}=?")
            vals.append(val)
        vals.append(escrow_id)
        with _db_lock, _conn(db_path) as con:
            con.execute(
                f"UPDATE marketplace_escrow SET {', '.join(sets)} WHERE escrow_id=?",
                vals,
            )
