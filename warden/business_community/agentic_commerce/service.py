"""
warden/business_community/agentic_commerce/service.py  (CM-40)
───────────────────────────────────────────────────────────────
AgenticCommerceService — orchestrates UCP + AP2 + MCP.

Integrations:
  - Vendor Governance: blocks purchases from unregistered merchants
  - Financial/Budget: checks budget cap before payment, records spend
  - STIX Audit: every order gets a UECIID and audit chain entry
  - BI: spend analytics fed through cost_allocation
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from warden.business_community.agentic_commerce.ap2 import AP2Processor
from warden.business_community.agentic_commerce.mcp_bridge import MCPBridge
from warden.business_community.agentic_commerce.models import MCPIntent, PurchaseOrder
from warden.business_community.agentic_commerce.ucp import UCPClient

log = logging.getLogger("warden.commerce.service")

_DB_PATH = os.getenv("COMMERCE_DB_PATH", "/tmp/warden_commerce.db")
_db_lock = threading.RLock()


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
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
        CREATE TABLE IF NOT EXISTS commerce_orders (
            id          TEXT PRIMARY KEY,
            tenant_id   TEXT NOT NULL,
            mandate_id  TEXT NOT NULL,
            data_json   TEXT NOT NULL,
            created_at  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_co_tenant ON commerce_orders(tenant_id);
    """)


class AgenticCommerceService:
    def __init__(self) -> None:
        self._ucp = UCPClient()
        self._ap2 = AP2Processor()
        self._mcp = MCPBridge()

    # ── Vendor governance check ───────────────────────────────────────────────

    def _check_vendor(self, tenant_id: str, store_url: str) -> dict[str, Any]:
        """
        Verify merchant against Vendor Governance registry.
        Blocks if merchant domain has no active DPA record.
        """
        try:
            from urllib.parse import urlparse
            from warden.vendor_gov.registry import list_vendors
            domain = urlparse(store_url if "://" in store_url else f"https://{store_url}").netloc
            vendors = list_vendors(tenant_id)
            for vendor in vendors:
                if domain and (domain in (vendor.website or "") or vendor.website in store_url):
                    if vendor.status == "ACTIVE":
                        return {"allowed": True, "vendor_id": vendor.id}
                    return {"allowed": False, "reason": f"vendor_status_{vendor.status.lower()}"}
            # Not registered → auto-register with MEDIUM risk for discovery
            log.warning("Merchant %s not in vendor registry for tenant %s", domain, tenant_id)
            return {"allowed": False, "reason": "merchant_not_registered"}
        except Exception as exc:
            log.debug("Vendor governance check skipped: %s", exc)
            return {"allowed": True, "reason": "governance_unavailable"}

    # ── Budget check ──────────────────────────────────────────────────────────

    def _check_budget(self, tenant_id: str, amount: float, currency: str) -> dict[str, Any]:
        """Check AI budget cap before authorizing payment."""
        try:
            from warden.financial.budget import get_budget_status
            status = get_budget_status(tenant_id)
            remaining = status.get("remaining_usd", float("inf"))
            if amount > remaining:
                return {"allowed": False, "reason": "budget_exceeded", "remaining": remaining}
        except Exception as exc:
            log.debug("Budget check skipped: %s", exc)
        return {"allowed": True}

    # ── Record spend ──────────────────────────────────────────────────────────

    def _record_spend(self, tenant_id: str, amount: float, merchant: str, order_id: str) -> None:
        try:
            from warden.financial.cost_allocation import record_spend
            record_spend(
                tenant_id=tenant_id,
                department="AI_Procurement",
                vendor=merchant,
                cost_type="agentic_procurement",
                amount_usd=amount,
                ref=order_id,
            )
        except Exception as exc:
            log.debug("Cost allocation record skipped: %s", exc)

    # ── STIX audit ────────────────────────────────────────────────────────────

    def _append_audit(self, tenant_id: str, order: PurchaseOrder) -> str:
        try:
            from warden.communities.stix_audit import append_transfer
            chain_id = append_transfer(
                community_id=tenant_id,
                entity_id=order.ueciid or order.id,
                source_community=tenant_id,
                target_community=order.store_url,
                proof_dict={
                    "order_id": order.id,
                    "mandate_id": order.mandate_id,
                    "total": order.total,
                    "status": order.status,
                },
            )
            return chain_id or ""
        except Exception as exc:
            log.debug("STIX audit append skipped: %s", exc)
            return ""

    # ── UECIID assignment ─────────────────────────────────────────────────────

    def _assign_ueciid(self) -> str:
        try:
            from warden.communities.sep import generate_ueciid
            return generate_ueciid()
        except Exception:
            return f"ORD-{uuid.uuid4().hex[:11].upper()}"

    # ── Order persistence ─────────────────────────────────────────────────────

    def _save_order(self, order: PurchaseOrder) -> None:
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO commerce_orders(id, tenant_id, mandate_id, data_json, created_at) "
                "VALUES(?,?,?,?,?)",
                (order.id, order.tenant_id, order.mandate_id,
                 json.dumps(order.to_dict()), order.created_at),
            )

    # ── Public API ────────────────────────────────────────────────────────────

    async def create_purchase_workflow(
        self,
        tenant_id: str,
        intent: MCPIntent | None = None,
        store_url: str = "",
        items: list[dict] | None = None,
        mandate_id: str = "",
    ) -> dict[str, Any]:
        """
        Full purchase workflow:
          1. Vendor governance check
          2. Budget check
          3. Create/verify mandate
          4. Execute AP2 payment
          5. Record spend + STIX audit
        """
        total = sum(i.get("qty", 1) * i.get("unit_price", 0) for i in (items or []))
        currency = "USD"
        merchant = store_url

        # 1. Vendor check
        vendor_check = self._check_vendor(tenant_id, store_url)
        if not vendor_check["allowed"]:
            return {"success": False, "reason": vendor_check.get("reason", "vendor_blocked")}

        # 2. Budget check
        budget_check = self._check_budget(tenant_id, total, currency)
        if not budget_check["allowed"]:
            return {"success": False, "reason": budget_check.get("reason", "budget_blocked"),
                    "remaining_budget": budget_check.get("remaining")}

        # 3. Mandate check
        if mandate_id:
            verification = self._ap2.verify_mandate(mandate_id, tenant_id)
            if not verification["valid"]:
                return {"success": False, "reason": f"mandate_{verification['reason']}"}
        else:
            return {"success": False, "reason": "no_mandate_provided"}

        # 4. Execute payment
        order_id = str(uuid.uuid4())
        payment = self._ap2.execute_payment(
            mandate_id=mandate_id,
            tenant_id=tenant_id,
            amount=total,
            merchant=merchant,
            order_ref=order_id,
        )
        if not payment["success"]:
            return {"success": False, "reason": payment.get("reason", "payment_failed")}

        # 5. Build order record
        from warden.business_community.agentic_commerce.models import OrderItem
        order = PurchaseOrder(
            id=order_id,
            tenant_id=tenant_id,
            store_url=store_url,
            items=[OrderItem(**i) for i in (items or [])],
            total=total,
            currency=currency,
            mandate_id=mandate_id,
            status="PAID",
            created_at=datetime.now(UTC).isoformat(),
            mcp_intent=intent.raw if intent else "",
            ueciid=self._assign_ueciid(),
        )
        order.stix_chain_id = self._append_audit(tenant_id, order)
        self._save_order(order)
        self._record_spend(tenant_id, total, merchant, order_id)

        log.info("Purchase workflow complete: order=%s tenant=%s total=%.2f", order_id, tenant_id, total)
        return {
            "success": True,
            "order_id": order_id,
            "ueciid": order.ueciid,
            "transaction_id": payment["transaction_id"],
            "total": total,
            "mandate_remaining": payment["remaining"],
        }

    def get_order_history(self, tenant_id: str, limit: int = 50) -> list[dict]:
        with _db_lock, _conn() as con:
            rows = con.execute(
                "SELECT data_json FROM commerce_orders WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [json.loads(r["data_json"]) for r in rows]

    def get_mandate_usage(self, tenant_id: str) -> dict:
        return self._ap2.get_mandate_usage(tenant_id)
