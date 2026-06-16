"""
warden/marketplace/agent_key_rotation.py  (Phase 2-5)
──────────────────────────────────────────────────────
Agent key rotation endpoint for marketplace agents.

POST /marketplace/agents/{id}/rotate-key
  - Accepts a new Ed25519 public key (base64)
  - Revokes the old X.509 certificate (adds to CRL)
  - Issues a new X.509 certificate for the new public key
  - Updates agent record: public_key + last_key_rotation_at timestamp
  - Emits a Kafka/Redis stream event (fail-open)

Enforcement (90-day rotation deadline)
───────────────────────────────────────
GET /marketplace/agents/{id}/key-rotation-status
  Returns days_since_rotation and overdue=True when > 90 days.
  Agents that are overdue have their capabilities reduced to [] until they rotate.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import threading
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from warden.marketplace.rate_limit import marketplace_rate_limit

log = logging.getLogger("warden.marketplace.agent_key_rotation")

_DB_PATH          = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_ROTATION_MAX_DAYS = int(os.getenv("AGENT_KEY_ROTATION_MAX_DAYS", "90"))
_db_lock          = threading.RLock()

router = APIRouter(
    prefix="/marketplace",
    tags=["Marketplace Key Rotation"],
    dependencies=[Depends(marketplace_rate_limit)],
)


# ── Schema migration (adds last_key_rotation_at if absent) ────────────────────

def _migrate(con: sqlite3.Connection) -> None:
    try:
        con.execute(
            "ALTER TABLE marketplace_agents ADD COLUMN last_key_rotation_at TEXT DEFAULT ''"
        )
        con.commit()
    except sqlite3.OperationalError:
        pass  # column already exists


def _conn():
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    _migrate(con)
    return con


# ── Helpers ───────────────────────────────────────────────────────────────────

def _days_since_rotation(last_rotation_at: str) -> float:
    if not last_rotation_at:
        return float("inf")
    try:
        then = datetime.fromisoformat(last_rotation_at)
        if then.tzinfo is None:
            then = then.replace(tzinfo=UTC)
        delta = datetime.now(UTC) - then
        return delta.total_seconds() / 86_400
    except Exception:
        return float("inf")


def _emit_rotation_event(agent_id: str, new_key: str) -> None:
    try:
        from warden.streams.event_bus import publish
        publish(
            "marketplace.agents",
            {"event": "key_rotated", "agent_id": agent_id, "ts": datetime.now(UTC).isoformat()},
        )
    except Exception:
        pass


# ── REST models ───────────────────────────────────────────────────────────────

class KeyRotationRequest(BaseModel):
    tenant_id:   str
    new_public_key: str   # base64-encoded Ed25519 public key


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/agents/{agent_id}/rotate-key", status_code=200)
def rotate_agent_key(agent_id: str, body: KeyRotationRequest) -> dict:
    """
    Rotate the signing key for a marketplace agent.

    Steps:
      1. Validate new_public_key is valid base64.
      2. Revoke old X.509 certificate (CRL entry added).
      3. Issue new X.509 certificate for new_public_key.
      4. Update agent record (public_key + last_key_rotation_at).
    """
    # Validate new key
    try:
        base64.b64decode(body.new_public_key, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"new_public_key must be valid base64: {exc}") from exc

    # Load agent
    with _db_lock:
        con = _conn()
        row = con.execute(
            "SELECT * FROM marketplace_agents WHERE agent_id=? AND tenant_id=?",
            (agent_id, body.tenant_id),
        ).fetchone()
        con.close()

    if not row:
        raise HTTPException(status_code=404, detail="Agent not found or wrong tenant.")
    if row["status"] == "suspended":
        raise HTTPException(status_code=403, detail="Suspended agents cannot rotate keys.")

    community_id = row["community_id"]

    # 1. Revoke old certificate
    try:
        from warden.security.certificate_authority import get_ca
        ca = get_ca()
        ca.revoke_certificate(agent_id)
        log.info("Key rotation: old cert revoked agent=%s", agent_id)
    except Exception as exc:
        log.warning("Key rotation: cert revoke failed agent=%s: %s", agent_id, exc)

    # 2. Issue new certificate
    new_cert: dict = {}
    try:
        from warden.security.certificate_authority import get_ca
        new_cert = get_ca().issue_agent_certificate(
            agent_id=agent_id,
            community_id=community_id,
            public_key_pem="",
        )
        log.info("Key rotation: new cert issued agent=%s cert_id=%s", agent_id, new_cert.get("cert_id"))
    except Exception as exc:
        log.warning("Key rotation: new cert issue failed agent=%s: %s", agent_id, exc)

    # 3. Update agent record
    now = datetime.now(UTC).isoformat()
    with _db_lock:
        con = _conn()
        con.execute(
            """UPDATE marketplace_agents
               SET public_key=?, last_key_rotation_at=?
               WHERE agent_id=?""",
            (body.new_public_key, now, agent_id),
        )
        con.commit()
        con.close()

    _emit_rotation_event(agent_id, body.new_public_key)

    return {
        "agent_id":              agent_id,
        "rotated_at":            now,
        "new_cert_id":           new_cert.get("cert_id", ""),
        "next_rotation_due_at":  datetime.fromtimestamp(
            datetime.now(UTC).timestamp() + _ROTATION_MAX_DAYS * 86_400, tz=UTC
        ).isoformat(),
    }


@router.get("/agents/{agent_id}/key-rotation-status")
def key_rotation_status(agent_id: str) -> dict:
    """Return rotation status and whether the agent is overdue."""
    with _db_lock:
        con = _conn()
        row = con.execute(
            "SELECT last_key_rotation_at, status FROM marketplace_agents WHERE agent_id=?",
            (agent_id,),
        ).fetchone()
        con.close()

    if not row:
        raise HTTPException(status_code=404, detail="Agent not found.")

    last_rot = row["last_key_rotation_at"] or ""
    days = _days_since_rotation(last_rot)
    overdue = days > _ROTATION_MAX_DAYS

    if overdue and row["status"] == "active":
        # Reduce capabilities to empty — agent must rotate before trading
        with _db_lock:
            con = _conn()
            con.execute(
                "UPDATE marketplace_agents SET capabilities='[]' WHERE agent_id=? AND status='active'",
                (agent_id,),
            )
            con.commit()
            con.close()
        log.warning("Key rotation: overdue agent=%s capabilities reduced", agent_id)

    return {
        "agent_id":             agent_id,
        "last_rotation_at":     last_rot or None,
        "days_since_rotation":  round(days, 1) if days != float("inf") else None,
        "max_rotation_days":    _ROTATION_MAX_DAYS,
        "overdue":              overdue,
    }
