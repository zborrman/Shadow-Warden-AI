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

import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.marketplace.escrow")

_DB_PATH   = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")


class EscrowDeploymentError(RuntimeError):
    """Raised when the target blockchain RPC node is unreachable after retries."""
_db_lock   = threading.RLock()
_DELIVERY_TIMEOUT_HOURS = int(os.getenv("ESCROW_DELIVERY_TIMEOUT_HOURS", "48"))


# ── Schema ────────────────────────────────────────────────────────────────────

_ESCROW_DDL = """
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
        chain            TEXT NOT NULL DEFAULT 'sepolia',
        created_at       TEXT NOT NULL,
        funded_at        TEXT,
        delivered_at     TEXT,
        confirmed_at     TEXT,
        expires_at       TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_esc_buyer  ON marketplace_escrow(buyer_agent);
    CREATE INDEX IF NOT EXISTS idx_esc_seller ON marketplace_escrow(seller_agent);
    CREATE INDEX IF NOT EXISTS idx_esc_listing ON marketplace_escrow(listing_id);
    CREATE INDEX IF NOT EXISTS idx_esc_chain  ON marketplace_escrow(chain);
"""
register("marketplace", "warden.marketplace.escrow", _ESCROW_DDL)


def _migrate_chain_column(con: sqlite3.Connection) -> None:
    """Add chain column to existing escrow tables that predate cross-chain support."""
    import contextlib
    with contextlib.suppress(Exception):
        con.execute(
            "ALTER TABLE marketplace_escrow ADD COLUMN chain TEXT NOT NULL DEFAULT 'sepolia'"
        )


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    with open_db(
        "marketplace", db_path, turso_name="marketplace", module_default_path=_DB_PATH
    ) as con:
        _migrate_chain_column(con)
        yield con


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
    chain:            str
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
    keys = row.keys()
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
        chain=row["chain"] if "chain" in keys else "sepolia",
        created_at=row["created_at"],
        funded_at=row["funded_at"],
        delivered_at=row["delivered_at"],
        confirmed_at=row["confirmed_at"],
        expires_at=row["expires_at"],
    )




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
        chain: str = "sepolia",
        db_path: str = _DB_PATH,
    ) -> Escrow:
        escrow_id = f"ESC-{uuid.uuid4().hex[:12].upper()}"
        now       = datetime.now(UTC).isoformat()
        expires   = (datetime.now(UTC) + timedelta(hours=_DELIVERY_TIMEOUT_HOURS)).isoformat()
        contract  = self._deploy_contract(
            buyer_agent_id, seller_agent_id, listing_id, escrow_id, chain
        )

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
            chain=chain,
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
                    chain, created_at, funded_at, delivered_at, confirmed_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    escrow.escrow_id, escrow.purchase_id, escrow.listing_id,
                    escrow.buyer_agent, escrow.seller_agent, escrow.amount_usd,
                    escrow.contract_address, escrow.status, escrow.asset_hash,
                    escrow.dispute_reason, escrow.chain, escrow.created_at,
                    escrow.funded_at, escrow.delivered_at, escrow.confirmed_at,
                    escrow.expires_at,
                ),
            )
        log.info("Escrow created: %s contract=%s chain=%s", escrow_id, contract, chain)
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
        # When DAO is enabled, auto-create a dispute_resolution proposal.
        try:
            from warden.marketplace.governance import (  # noqa: PLC0415
                _DAO_ENABLED,
                GovernanceService,
            )
            if _DAO_ENABLED:
                GovernanceService().create_proposal(
                    community_id=esc.listing_id,
                    proposer_id=esc.buyer_agent,
                    proposal_type="dispute_resolution",
                    target_id=escrow_id,
                    title=f"Dispute: {escrow_id}",
                    description=reason[:200],
                    db_path=db_path,
                )
        except Exception as exc:
            log.warning("DAO auto-proposal failed for escrow %s: %s", escrow_id, exc)
        return True

    def resolve_dispute(
        self,
        escrow_id: str,
        release_to_buyer: bool,
        bypass_dao_check: bool = False,
        db_path: str = _DB_PATH,
    ) -> bool:
        esc = self._get(escrow_id, db_path)
        if esc is None or esc.status != "disputed":
            return False
        # Block direct resolution when an active DAO proposal exists (unless caller is the DAO).
        if not bypass_dao_check:
            try:
                from warden.marketplace.governance import (  # noqa: PLC0415
                    _DAO_ENABLED,
                    GovernanceService,
                )
                if _DAO_ENABLED:
                    prop = GovernanceService().check_active_proposal_for_escrow(escrow_id, db_path)
                    if prop is not None:
                        log.warning(
                            "resolve_dispute blocked: active DAO proposal %s exists for escrow %s",
                            prop.proposal_id, escrow_id,
                        )
                        return False
            except Exception as exc:
                log.warning("DAO check failed: %s", exc)
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

    def list_escrows(
        self,
        agent_id: str,
        role: str = "any",
        limit: int = 50,
        db_path: str = _DB_PATH,
    ) -> list[Escrow]:
        if role == "buyer":
            query = "SELECT * FROM marketplace_escrow WHERE buyer_agent=? ORDER BY created_at DESC LIMIT ?"
            params: list = [agent_id, limit]
        elif role == "seller":
            query = "SELECT * FROM marketplace_escrow WHERE seller_agent=? ORDER BY created_at DESC LIMIT ?"
            params = [agent_id, limit]
        else:
            query = "SELECT * FROM marketplace_escrow WHERE buyer_agent=? OR seller_agent=? ORDER BY created_at DESC LIMIT ?"
            params = [agent_id, agent_id, limit]
        with _conn(db_path) as con:
            rows = con.execute(query, params).fetchall()
        return [_row_to_escrow(r) for r in rows]

    def list_all_escrows(
        self,
        status: str | None = None,
        limit: int = 50,
        db_path: str = _DB_PATH,
    ) -> list[Escrow]:
        if status:
            query = "SELECT * FROM marketplace_escrow WHERE status=? ORDER BY created_at DESC LIMIT ?"
            params: list = [status, limit]
        else:
            query = "SELECT * FROM marketplace_escrow ORDER BY created_at DESC LIMIT ?"
            params = [limit]
        with _conn(db_path) as con:
            rows = con.execute(query, params).fetchall()
        return [_row_to_escrow(r) for r in rows]

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _check_rpc_with_retry(self, chain: str, max_retries: int = 3) -> bool:
        """
        Check that the RPC node for *chain* is reachable.

        Retries up to max_retries times with exponential back-off (2, 4, 8 s).
        Returns True if connected, False if no RPC URL is configured (simulation
        mode — caller should proceed without raising).
        Raises EscrowDeploymentError after all retries if RPC is configured but
        unreachable.
        """
        import time as _time  # noqa: PLC0415

        try:
            from warden.web3.chains import get_chain  # noqa: PLC0415
            cfg = get_chain(chain)
        except Exception:
            return False  # unknown chain → simulation mode

        rpc_url = cfg.get("rpc_url", "")
        if not rpc_url:
            return False  # no RPC configured → simulation mode (fail-open)

        delays = [2 ** i for i in range(max_retries)]  # 2, 4, 8 seconds
        last_error: str = ""
        for attempt, delay in enumerate(delays, start=1):
            try:
                from web3 import Web3  # noqa: PLC0415
                w3 = Web3(Web3.HTTPProvider(rpc_url))
                if w3.is_connected():
                    try:
                        from warden.metrics import ESCROW_RPC_CHECK_TOTAL
                        ESCROW_RPC_CHECK_TOTAL.labels(chain=chain, status="ok").inc()
                    except Exception:
                        pass
                    log.debug("_check_rpc_with_retry: connected to %s on attempt %d", chain, attempt)
                    return True
                last_error = "is_connected() returned False"
            except ImportError:
                return False  # web3 not installed → simulation mode
            except Exception as exc:
                last_error = str(exc)
            log.warning("RPC check for %s attempt %d/%d failed: %s — retrying in %ds",
                        chain, attempt, max_retries, last_error, delay)
            _time.sleep(delay)

        # All retries exhausted
        try:
            from warden.metrics import ESCROW_RPC_CHECK_TOTAL
            ESCROW_RPC_CHECK_TOTAL.labels(chain=chain, status="fail").inc()
        except Exception:
            pass
        raise EscrowDeploymentError(
            f"Blockchain network '{chain}' is not reachable after {max_retries} retries. "
            f"Last error: {last_error}"
        )

    def _deploy_contract(
        self, buyer: str, seller: str, listing_id: str, nonce: str, chain: str = "sepolia"
    ) -> str:
        # Validate RPC connectivity before attempting deployment.
        # Returns False when no RPC is configured (simulation mode) — proceed.
        # Raises EscrowDeploymentError when RPC is configured but unreachable.
        self._check_rpc_with_retry(chain)

        try:
            from warden.web3.smart_contract import deploy_escrow  # noqa: PLC0415
            return deploy_escrow(buyer, seller, listing_id, nonce, chain)
        except EscrowDeploymentError:
            raise
        except Exception as exc:
            log.debug("deploy_escrow failed, using legacy sim: %s", exc)
        # Legacy fallback — ChainConnector without chain awareness
        try:
            from typing import Any  # noqa: PLC0415

            from warden.blockchain.chain_connector import ChainConnector  # noqa: PLC0415
            cc: Any = ChainConnector()
            if cc.is_connected():
                return cc.deploy_escrow(buyer, seller)
        except Exception:
            pass
        import hashlib  # noqa: PLC0415
        raw = f"{buyer}:{seller}:{listing_id}:{nonce}:{chain}".encode()
        return "0x" + hashlib.sha256(raw).hexdigest()[:40] + f":{chain}"

    def _call_contract(self, contract_address: str, fn_name: str, params: dict) -> None:
        try:
            from warden.web3.smart_contract import call_escrow, strip_chain_suffix  # noqa: PLC0415
            addr, chain = strip_chain_suffix(contract_address)
            call_escrow(addr, fn_name, params, chain)
            return
        except Exception as exc:
            log.debug("call_escrow (web3) failed: %s", exc)
        try:
            from typing import Any  # noqa: PLC0415

            from warden.blockchain.chain_connector import ChainConnector  # noqa: PLC0415
            cc: Any = ChainConnector()
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
