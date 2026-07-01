"""
ACP Refund engine — draft-only pattern (PENDING_REVIEW).

Agents propose refunds; humans (or the compliance officer) approve them.
No money moves without explicit human approval — analogous to SAR filing.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

from warden.protocols.acp.models import RefundRequest

log = logging.getLogger("warden.acp.refund")

_DB_PATH = os.getenv("ACP_DB_PATH", "/tmp/warden_acp.db")
_db_lock = threading.RLock()


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS acp_refunds (
            refund_id    TEXT PRIMARY KEY,
            order_id     TEXT NOT NULL,
            merchant_id  TEXT NOT NULL,
            agent_id     TEXT NOT NULL,
            tenant_id    TEXT NOT NULL,
            amount       REAL NOT NULL,
            currency     TEXT NOT NULL DEFAULT 'USD',
            reason       TEXT,
            status       TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
            stix_chain_id TEXT DEFAULT '',
            created_at   TEXT NOT NULL
        )
    """)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def request_refund(
    order_id: str,
    merchant_id: str,
    agent_id: str,
    tenant_id: str,
    amount: float,
    currency: str = "USD",
    reason: str = "",
) -> RefundRequest:
    """
    Create a refund request in PENDING_REVIEW status.
    Agents never self-approve refunds (draft-only pattern).
    """
    refund_id  = f"acp-refund-{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(UTC).isoformat()

    # STIX audit
    stix_chain_id = ""
    try:
        from warden.communities.stix_audit import append_transfer  # noqa: PLC0415
        entry = append_transfer(
            community_id=tenant_id,
            entity_id=refund_id,
            from_tenant=merchant_id,
            to_tenant=agent_id,
            data_class="FINANCIAL",
            metadata={"acp_refund_request": True, "order_id": order_id, "amount": amount},
        )
        stix_chain_id = str(entry.get("id", ""))
    except Exception:
        pass

    with _db_lock, _conn() as con:
        con.execute(
            "INSERT INTO acp_refunds (refund_id,order_id,merchant_id,agent_id,tenant_id,"
            "amount,currency,reason,status,stix_chain_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (refund_id, order_id, merchant_id, agent_id, tenant_id,
             amount, currency, reason, "PENDING_REVIEW", stix_chain_id, created_at),
        )

    log.info("ACP: refund requested refund=%s order=%s agent=%s amount=%.2f status=PENDING_REVIEW",
             refund_id, order_id, agent_id, amount)

    return RefundRequest(
        refund_id=refund_id,
        order_id=order_id,
        merchant_id=merchant_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        amount=amount,
        currency=currency,
        reason=reason,
        status="PENDING_REVIEW",
        stix_chain_id=stix_chain_id,
        created_at=created_at,
    )


def get_refund(refund_id: str) -> RefundRequest | None:
    with _db_lock, _conn() as con:
        row = con.execute(
            "SELECT * FROM acp_refunds WHERE refund_id=?", (refund_id,)
        ).fetchone()
    if not row:
        return None
    return RefundRequest(**dict(row))


def list_refunds(tenant_id: str, status: str | None = None) -> list[RefundRequest]:
    with _db_lock, _conn() as con:
        if status:
            rows = con.execute(
                "SELECT * FROM acp_refunds WHERE tenant_id=? AND status=? ORDER BY created_at DESC",
                (tenant_id, status),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM acp_refunds WHERE tenant_id=? ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
    return [RefundRequest(**dict(r)) for r in rows]


def resolve_refund(refund_id: str, action: str) -> bool:
    """Human-only: approve or reject a refund. action must be 'approve' or 'reject'."""
    if action not in ("approve", "reject"):
        raise ValueError("action must be 'approve' or 'reject'")
    new_status = "APPROVED" if action == "approve" else "REJECTED"
    with _db_lock, _conn() as con:
        cur = con.execute(
            "UPDATE acp_refunds SET status=? WHERE refund_id=? AND status='PENDING_REVIEW'",
            (new_status, refund_id),
        )
    return cur.rowcount > 0
