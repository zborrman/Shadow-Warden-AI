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

import base64
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
from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register
from warden.secret_keys import resolve_key

log = logging.getLogger("warden.commerce.ap2")

_DB_PATH  = data_path("warden_commerce.db", "COMMERCE_DB_PATH")


def _hmac_key() -> bytes:
    return resolve_key("AP2_HMAC_KEY", purpose="ap2_mandate")


def _fernet() -> Fernet:
    """Resolve the mandate-vault Fernet cipher per call, fail-CLOSED.

    VAULT_MASTER_KEY is the boot-validated Fernet key (CLAUDE.md #1); production
    always has it, so mandates encrypted before this change stay decryptable.
    There is deliberately NO random fallback: the previous module-level
    ``Fernet(... else Fernet.generate_key())`` was evaluated at import (before the
    env was populated) and silently rotated the key on every restart, rendering
    every stored mandate permanently undecryptable. With no master key, dev/test
    derive a deterministic key via ``resolve_key``; production raises
    ``InsecureKeyError`` rather than encrypt under an ephemeral key.
    """
    key = os.getenv("VAULT_MASTER_KEY", "")
    if key:
        return Fernet(key.encode())
    derived = resolve_key("AP2_VAULT_KEY", purpose="ap2_vault")  # dev key, or raises in prod
    return Fernet(base64.urlsafe_b64encode(derived[:32]))


_db_lock  = threading.RLock()

# Single source of truth for commerce_orders — service.py imports this rather
# than carrying its own copy (FT-6 order-model consolidation, slice 1: kill
# the literal duplicate DDL before the bigger cross-domain schema migration).
COMMERCE_ORDERS_DDL = """
    CREATE TABLE IF NOT EXISTS commerce_orders (
        id              TEXT PRIMARY KEY,
        tenant_id       TEXT NOT NULL,
        mandate_id      TEXT NOT NULL,
        data_json       TEXT NOT NULL,
        created_at      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_orders_tenant ON commerce_orders(tenant_id);
"""

_AP2_DDL = f"""
    CREATE TABLE IF NOT EXISTS commerce_mandates (
        id              TEXT PRIMARY KEY,
        tenant_id       TEXT NOT NULL,
        data_enc        BLOB NOT NULL,
        created_at      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_mandates_tenant ON commerce_mandates(tenant_id);

    {COMMERCE_ORDERS_DDL}

    CREATE TABLE IF NOT EXISTS commerce_receipts (
        id              TEXT PRIMARY KEY,
        order_id        TEXT NOT NULL,
        data_json       TEXT NOT NULL,
        created_at      TEXT NOT NULL
    );
"""

# Shares warden_commerce.db with service.py and orchestrator.py — same db_key,
# distinct module name.
register("commerce", "ap2", _AP2_DDL)


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    with open_db("commerce", db_path, module_default_path=_DB_PATH) as con:
        yield con


def _sign_mandate(mandate: Mandate) -> str:
    """HMAC-SHA256 over canonical mandate fields."""
    canonical = f"{mandate.id}|{mandate.tenant_id}|{mandate.max_amount}|{mandate.currency}|{mandate.valid_until}"
    return hmac.new(_hmac_key(), canonical.encode(), hashlib.sha256).hexdigest()


def _encrypt(data: dict) -> bytes:
    return _fernet().encrypt(json.dumps(data).encode())


def _decrypt(blob: bytes) -> dict:
    return json.loads(_fernet().decrypt(blob))


class AP2Processor:
    """
    Agent Payments Protocol processor.

    Mandates are cryptographically signed and Fernet-encrypted at rest.
    Payment execution validates mandate conditions before processing.
    """

    def __init__(self, db_path: str | None = None) -> None:
        # Resolved at instantiation, not at module import — so tests that swap
        # COMMERCE_DB_PATH per-test (e.g. via a tmp_path fixture) get isolated
        # storage. A frozen module-level default would silently keep pointing
        # at whichever path was current the first time this module was ever
        # imported in the process.
        self._db_path = db_path or data_path("warden_commerce.db", "COMMERCE_DB_PATH")

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

        with _db_lock, _conn(self._db_path) as con:
            con.execute(
                "INSERT INTO commerce_mandates(id, tenant_id, data_enc, created_at) VALUES(?,?,?,?)",
                (mandate.id, tenant_id, _encrypt(mandate.to_dict()), mandate.created_at),
            )
        log.info("Mandate created: %s tenant=%s max=%.2f %s", mandate.id, tenant_id, max_amount, currency)
        return mandate

    def get_mandate(self, mandate_id: str, tenant_id: str) -> Mandate | None:
        with _db_lock, _conn(self._db_path) as con:
            row = con.execute(
                "SELECT data_enc FROM commerce_mandates WHERE id=? AND tenant_id=?",
                (mandate_id, tenant_id),
            ).fetchone()
        if not row:
            return None
        return Mandate(**_decrypt(row["data_enc"]))

    def list_mandates(self, tenant_id: str) -> list[Mandate]:
        with _db_lock, _conn(self._db_path) as con:
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
        with _db_lock, _conn(self._db_path) as con:
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

        with _db_lock, _conn(self._db_path) as con:
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
        with _db_lock, _conn(self._db_path) as con:
            con.execute(
                "INSERT INTO commerce_receipts(id, order_id, data_json, created_at) VALUES(?,?,?,?)",
                (receipt.id, order_ref, json.dumps(receipt.to_dict()), receipt.timestamp),
            )
        try:
            from warden.marketplace.listing import upsert_mirrored_order
            upsert_mirrored_order(
                "agentic_commerce", order_ref,
                status="PAID", receipt_json=json.dumps(receipt.to_dict()),
            )
        except Exception as exc:
            log.debug("commerce_receipts -> marketplace_purchases mirror unavailable: %s", exc)

        log.info("Payment executed: txn=%s mandate=%s amount=%.2f merchant=%s", transaction_id, mandate_id, amount, merchant)
        return {
            "success": True,
            "transaction_id": transaction_id,
            "amount": amount,
            "remaining": m.remaining(),
            "receipt_id": receipt.id,
        }

    def get_receipt(self, order_id: str) -> Receipt | None:
        with _db_lock, _conn(self._db_path) as con:
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
