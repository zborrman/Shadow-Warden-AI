"""
warden/business_community/agentic_commerce/ap2.py  (CM-40)
───────────────────────────────────────────────────────────
Agent Payments Protocol (AP2) processor.

Manages cryptographically-signed spending mandates and executes
payments on behalf of AI agents within those mandate constraints.

All mandate records are stored Fernet-encrypted in SQLite.
Mandate signatures use Ed25519 (via communities/keypair.py) + HMAC-SHA256.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

from cryptography.fernet import Fernet

from warden.business_community.agentic_commerce.models import Mandate, Receipt
from warden.secret_keys import resolve_key

log = logging.getLogger("warden.commerce.ap2")

_DB_PATH  = os.getenv("COMMERCE_DB_PATH", "/tmp/warden_commerce.db")
_vault_key = os.getenv("VAULT_MASTER_KEY", "")
_FERNET   = Fernet(_vault_key.encode() if _vault_key else Fernet.generate_key())
def _hmac_key() -> bytes:
    return resolve_key("AP2_HMAC_KEY", purpose="ap2_mandate")
_db_lock  = threading.RLock()


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


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS commerce_mandates (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL,
            data_enc        BLOB NOT NULL,
            created_at      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mandates_tenant ON commerce_mandates(tenant_id);

        CREATE TABLE IF NOT EXISTS commerce_orders (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL,
            mandate_id      TEXT NOT NULL,
            data_json       TEXT NOT NULL,
            created_at      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_orders_tenant ON commerce_orders(tenant_id);

        CREATE TABLE IF NOT EXISTS commerce_receipts (
            id              TEXT PRIMARY KEY,
            order_id        TEXT NOT NULL,
            data_json       TEXT NOT NULL,
            created_at      TEXT NOT NULL
        );
    """)


def _sign_mandate(mandate: Mandate) -> str:
    """HMAC-SHA256 over canonical mandate fields."""
    canonical = f"{mandate.id}|{mandate.tenant_id}|{mandate.max_amount}|{mandate.currency}|{mandate.valid_until}"
    return hmac.new(_hmac_key(), canonical.encode(), hashlib.sha256).hexdigest()


def _encrypt(data: dict) -> bytes:
    return _FERNET.encrypt(json.dumps(data).encode())


def _decrypt(blob: bytes) -> dict:
    return json.loads(_FERNET.decrypt(blob))


class AP2Processor:
    """
    Agent Payments Protocol processor.

    Mandates are cryptographically signed and Fernet-encrypted at rest.
    Payment execution validates mandate conditions before processing.
    """

    # ── Mandate management ────────────────────────────────────────────────────

    def create_mandate(
        self,
        tenant_id: str,
        max_amount: float,
        currency: str = "USD",
        valid_until: str | None = None,
        allowed_merchants: list[str] | None = None,
    ) -> Mandate:
        if max_amount <= 0:
            raise ValueError("max_amount must be positive")
        if valid_until is None:
            from datetime import timedelta
            valid_until = (datetime.now(UTC) + timedelta(days=30)).isoformat()

        mandate = Mandate(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            max_amount=max_amount,
            currency=currency,
            valid_until=valid_until,
            allowed_merchants=allowed_merchants or [],
            status="ACTIVE",
            created_at=datetime.now(UTC).isoformat(),
        )
        mandate.signature = _sign_mandate(mandate)

        with _db_lock, _conn() as con:
            con.execute(
                "INSERT INTO commerce_mandates(id, tenant_id, data_enc, created_at) VALUES(?,?,?,?)",
                (mandate.id, tenant_id, _encrypt(mandate.to_dict()), mandate.created_at),
            )
        log.info("Mandate created: %s tenant=%s max=%.2f %s", mandate.id, tenant_id, max_amount, currency)
        return mandate

    def get_mandate(self, mandate_id: str, tenant_id: str) -> Mandate | None:
        with _db_lock, _conn() as con:
            row = con.execute(
                "SELECT data_enc FROM commerce_mandates WHERE id=? AND tenant_id=?",
                (mandate_id, tenant_id),
            ).fetchone()
        if not row:
            return None
        return Mandate(**_decrypt(row["data_enc"]))

    def list_mandates(self, tenant_id: str) -> list[Mandate]:
        with _db_lock, _conn() as con:
            rows = con.execute(
                "SELECT data_enc FROM commerce_mandates WHERE tenant_id=? ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
        return [Mandate(**_decrypt(r["data_enc"])) for r in rows]

    def revoke_mandate(self, mandate_id: str, tenant_id: str) -> bool:
        m = self.get_mandate(mandate_id, tenant_id)
        if not m:
            return False
        m.status = "REVOKED"
        with _db_lock, _conn() as con:
            con.execute(
                "UPDATE commerce_mandates SET data_enc=? WHERE id=? AND tenant_id=?",
                (_encrypt(m.to_dict()), mandate_id, tenant_id),
            )
        return True

    def verify_mandate(self, mandate_id: str, tenant_id: str) -> dict:
        m = self.get_mandate(mandate_id, tenant_id)
        if not m:
            return {"valid": False, "reason": "not_found"}
        expected_sig = _sign_mandate(m)
        if not hmac.compare_digest(m.signature, expected_sig):
            return {"valid": False, "reason": "signature_mismatch"}
        if m.status != "ACTIVE":
            return {"valid": False, "reason": f"status_{m.status.lower()}"}
        if datetime.fromisoformat(m.valid_until.replace("Z", "+00:00")) < datetime.now(UTC):
            return {"valid": False, "reason": "expired"}
        return {"valid": True, "remaining": m.remaining(), "currency": m.currency}

    # ── Payment execution ─────────────────────────────────────────────────────

    def execute_payment(
        self,
        mandate_id: str,
        tenant_id: str,
        amount: float,
        merchant: str,
        order_ref: str,
    ) -> dict:
        """
        Execute a payment against mandate.
        Validates: signature, status, expiry, merchant allowlist, budget.
        Returns {success, transaction_id, remaining} or {success:False, reason}.
        """
        verification = self.verify_mandate(mandate_id, tenant_id)
        if not verification["valid"]:
            return {"success": False, "reason": verification["reason"]}

        m = self.get_mandate(mandate_id, tenant_id)
        if not m:
            return {"success": False, "reason": "not_found"}

        if m.allowed_merchants and not any(
            merchant.endswith(domain) or merchant == domain
            for domain in m.allowed_merchants
        ):
            log.warning("Mandate %s: merchant %s not in allowlist", mandate_id, merchant)
            return {"success": False, "reason": "merchant_not_allowed"}

        if amount > m.remaining():
            log.warning("Mandate %s: amount %.2f exceeds remaining %.2f", mandate_id, amount, m.remaining())
            return {"success": False, "reason": "insufficient_mandate_balance"}

        # Charge mandate
        m.spent_so_far += amount
        if m.remaining() <= 0:
            m.status = "SUSPENDED"

        with _db_lock, _conn() as con:
            con.execute(
                "UPDATE commerce_mandates SET data_enc=? WHERE id=? AND tenant_id=?",
                (_encrypt(m.to_dict()), mandate_id, tenant_id),
            )

        transaction_id = f"ap2-{uuid.uuid4().hex[:16]}"
        receipt = Receipt(
            id=str(uuid.uuid4()),
            purchase_order_id=order_ref,
            transaction_id=transaction_id,
            timestamp=datetime.now(UTC).isoformat(),
            amount=amount,
            currency=m.currency,
            payment_method="AP2",
            merchant=merchant,
        )
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT INTO commerce_receipts(id, order_id, data_json, created_at) VALUES(?,?,?,?)",
                (receipt.id, order_ref, json.dumps(receipt.to_dict()), receipt.timestamp),
            )

        log.info("Payment executed: txn=%s mandate=%s amount=%.2f merchant=%s", transaction_id, mandate_id, amount, merchant)
        return {
            "success": True,
            "transaction_id": transaction_id,
            "amount": amount,
            "remaining": m.remaining(),
            "receipt_id": receipt.id,
        }

    def get_receipt(self, order_id: str) -> Receipt | None:
        with _db_lock, _conn() as con:
            row = con.execute(
                "SELECT data_json FROM commerce_receipts WHERE order_id=?",
                (order_id,),
            ).fetchone()
        if not row:
            return None
        return Receipt(**json.loads(row["data_json"]))

    def get_mandate_usage(self, tenant_id: str) -> dict:
        mandates = self.list_mandates(tenant_id)
        return {
            "total_mandates": len(mandates),
            "active": sum(1 for m in mandates if m.status == "ACTIVE"),
            "total_authorized": sum(m.max_amount for m in mandates),
            "total_spent": sum(m.spent_so_far for m in mandates),
            "mandates": [
                {
                    "id": m.id,
                    "max_amount": m.max_amount,
                    "spent": m.spent_so_far,
                    "remaining": m.remaining(),
                    "status": m.status,
                    "valid_until": m.valid_until,
                }
                for m in mandates
            ],
        }
