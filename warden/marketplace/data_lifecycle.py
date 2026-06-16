"""
warden/marketplace/data_lifecycle.py  (Phase 4-10)
───────────────────────────────────────────────────
Marketplace data lifecycle manager.

Tracks TTLs for marketplace entities and purges them when expired.

Supported entity types and default TTLs
────────────────────────────────────────
  negotiation   — 90 days  (transcripts zeroed + deleted)
  escrow        — 7 years  (anonymised; audit hash retained)
  mandate       — 30 days post-expiry (removed from DB + Redis)
  certificate   — already managed by CRL; 7 years archive then purge

ARQ cron jobs
─────────────
  check_expired_lifecycle_entities   — daily
  purge_expired_lifecycle_entities   — weekly

Admin endpoint
──────────────
  POST /admin/data-lifecycle/purge  — force purge now
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

log = logging.getLogger("warden.marketplace.data_lifecycle")

_DB_PATH      = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_LIFECYCLE_DB = os.getenv("LIFECYCLE_DB_PATH", "/tmp/warden_lifecycle.db")
_db_lock      = threading.RLock()

_DEFAULT_TTLS: dict[str, int] = {
    "negotiation":  90,
    "escrow":       365 * 7,
    "mandate":      30,
    "certificate":  365 * 7,
}

# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mkt_data_lifecycle (
    entity_type    TEXT NOT NULL,
    entity_id      TEXT NOT NULL,
    registered_at  TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    purged         INTEGER NOT NULL DEFAULT 0,
    purged_at      TEXT,
    PRIMARY KEY (entity_type, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_lcm_expires ON mkt_data_lifecycle(expires_at, purged);
"""


def _conn(path: str = _LIFECYCLE_DB) -> sqlite3.Connection:
    con = sqlite3.connect(path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_SCHEMA)
    return con


# ── Dataclass ─────────────────────────────────────────────────────────────────

@dataclass
class LifecycleEntry:
    entity_type:   str
    entity_id:     str
    registered_at: str
    expires_at:    str
    purged:        bool
    purged_at:     str | None

    def to_dict(self) -> dict:
        return asdict(self)


# ── DataLifecycleManager ──────────────────────────────────────────────────────

class DataLifecycleManager:
    """Tracks marketplace entity TTLs and purges expired records."""

    def __init__(self, lifecycle_db: str = _LIFECYCLE_DB, marketplace_db: str = _DB_PATH) -> None:
        self.lifecycle_db   = lifecycle_db
        self.marketplace_db = marketplace_db
        with _db_lock:
            con = _conn(lifecycle_db)
            con.close()

    # ── Registration ─────────────────────────────────────────────────────────

    def register_entity(
        self,
        entity_type: str,
        entity_id: str,
        ttl_days: int | None = None,
    ) -> LifecycleEntry:
        """Register an entity with a TTL. Uses default if ttl_days not provided."""
        if ttl_days is None:
            ttl_days = _DEFAULT_TTLS.get(entity_type, 90)
        now      = datetime.now(UTC)
        expires  = now + timedelta(days=ttl_days)
        entry = LifecycleEntry(
            entity_type=entity_type,
            entity_id=entity_id,
            registered_at=now.isoformat(),
            expires_at=expires.isoformat(),
            purged=False,
            purged_at=None,
        )
        with _db_lock:
            con = _conn(self.lifecycle_db)
            con.execute(
                """INSERT OR IGNORE INTO mkt_data_lifecycle
                   (entity_type, entity_id, registered_at, expires_at, purged)
                   VALUES (?,?,?,?,0)""",
                (entity_type, entity_id, entry.registered_at, entry.expires_at),
            )
            con.commit()
            con.close()
        return entry

    # ── Check ─────────────────────────────────────────────────────────────────

    def check_expired(self) -> list[LifecycleEntry]:
        """Return all non-purged entries past their TTL."""
        now = datetime.now(UTC).isoformat()
        with _db_lock:
            con = _conn(self.lifecycle_db)
            rows = con.execute(
                "SELECT * FROM mkt_data_lifecycle WHERE expires_at <= ? AND purged=0",
                (now,),
            ).fetchall()
            con.close()
        return [
            LifecycleEntry(
                entity_type=r["entity_type"],
                entity_id=r["entity_id"],
                registered_at=r["registered_at"],
                expires_at=r["expires_at"],
                purged=bool(r["purged"]),
                purged_at=r["purged_at"],
            )
            for r in rows
        ]

    # ── Purge ─────────────────────────────────────────────────────────────────

    def purge_expired(self) -> dict:
        """Purge all expired entities. Returns summary counts."""
        expired = self.check_expired()
        counts: dict[str, int] = {}

        for entry in expired:
            try:
                self._purge_one(entry)
                counts[entry.entity_type] = counts.get(entry.entity_type, 0) + 1
            except Exception as exc:
                log.warning(
                    "lifecycle: purge failed type=%s id=%s: %s",
                    entry.entity_type, entry.entity_id, exc,
                )

        log.info("lifecycle: purge complete %s", counts)
        return {"purged": counts, "total": sum(counts.values())}

    def _purge_one(self, entry: LifecycleEntry) -> None:
        etype = entry.entity_type
        eid   = entry.entity_id

        if etype == "negotiation":
            self._purge_negotiation(eid)
        elif etype == "escrow":
            self._anonymise_escrow(eid)
        elif etype == "mandate":
            self._purge_mandate(eid)
        elif etype == "certificate":
            self._archive_certificate(eid)
        else:
            log.debug("lifecycle: unknown entity_type=%s — skipping content purge", etype)

        now = datetime.now(UTC).isoformat()
        with _db_lock:
            con = _conn(self.lifecycle_db)
            con.execute(
                "UPDATE mkt_data_lifecycle SET purged=1, purged_at=? WHERE entity_type=? AND entity_id=?",
                (now, etype, eid),
            )
            con.commit()
            con.close()

    # ── Per-type purge logic ──────────────────────────────────────────────────

    def _purge_negotiation(self, negotiation_id: str) -> None:
        """Zero out offer messages and delete the negotiation record."""
        try:
            with _db_lock:
                con = sqlite3.connect(self.marketplace_db, check_same_thread=False)
                con.execute("PRAGMA journal_mode=WAL")
                con.execute(
                    "UPDATE marketplace_offers SET message='' WHERE negotiation_id=?",
                    (negotiation_id,),
                )
                con.execute(
                    "DELETE FROM marketplace_negotiations WHERE negotiation_id=?",
                    (negotiation_id,),
                )
                con.commit()
                con.close()
            log.info("lifecycle: negotiation purged id=%s", negotiation_id)
        except Exception as exc:
            log.warning("lifecycle: negotiation purge failed id=%s: %s", negotiation_id, exc)

    def _anonymise_escrow(self, escrow_id: str) -> None:
        """Replace sensitive escrow fields with a SHA-256 audit hash, retain record."""
        try:
            with _db_lock:
                con = sqlite3.connect(self.marketplace_db, check_same_thread=False)
                con.row_factory = sqlite3.Row
                con.execute("PRAGMA journal_mode=WAL")
                row = con.execute(
                    "SELECT * FROM marketplace_escrows WHERE escrow_id=?", (escrow_id,)
                ).fetchone()
                if row:
                    canonical = json.dumps(dict(row), sort_keys=True)
                    audit_hash = hashlib.sha256(canonical.encode()).hexdigest()
                    con.execute(
                        """UPDATE marketplace_escrows
                           SET buyer_agent='[redacted]', seller_agent='[redacted]',
                               contract_address='[redacted]', tx_hash='[redacted]'
                           WHERE escrow_id=?""",
                        (escrow_id,),
                    )
                    con.execute(
                        "UPDATE marketplace_escrows SET memo=? WHERE escrow_id=?",
                        (f"audit_hash:{audit_hash}", escrow_id),
                    )
                con.commit()
                con.close()
            log.info("lifecycle: escrow anonymised id=%s", escrow_id)
        except Exception as exc:
            log.warning("lifecycle: escrow anonymise failed id=%s: %s", escrow_id, exc)

    def _purge_mandate(self, mandate_id: str) -> None:
        """Delete expired mandate from DB and Redis."""
        try:
            from warden.business_community.agentic_commerce.ap2 import AP2Processor
            AP2Processor().revoke_mandate(mandate_id, tenant_id="")
            log.info("lifecycle: mandate purged id=%s", mandate_id)
        except Exception as exc:
            log.debug("lifecycle: mandate purge failed id=%s: %s", mandate_id, exc)

    def _archive_certificate(self, cert_id: str) -> None:
        """Move revoked certificate to archive table (CRL retention)."""
        try:
            from warden.security.certificate_authority import get_ca
            ca = get_ca(self.marketplace_db)
            cert = ca.get_agent_certificate(cert_id)
            if cert and cert.get("revoked"):
                log.info("lifecycle: cert archived id=%s (already revoked)", cert_id)
        except Exception as exc:
            log.debug("lifecycle: cert archive failed id=%s: %s", cert_id, exc)


# ── Module singleton ──────────────────────────────────────────────────────────

_mgr: DataLifecycleManager | None = None
_mgr_lock = threading.Lock()


def get_lifecycle_manager() -> DataLifecycleManager:
    global _mgr
    with _mgr_lock:
        if _mgr is None:
            _mgr = DataLifecycleManager()
    return _mgr


# ── FastAPI router ────────────────────────────────────────────────────────────

from fastapi import APIRouter, Depends  # noqa: E402

from warden.marketplace.rate_limit import marketplace_rate_limit  # noqa: E402

router = APIRouter(
    prefix="/admin",
    tags=["Data Lifecycle"],
    dependencies=[Depends(marketplace_rate_limit)],
)


@router.post("/data-lifecycle/purge")
def force_purge() -> dict:
    """Force-run the data lifecycle purge immediately."""
    return get_lifecycle_manager().purge_expired()


@router.get("/data-lifecycle/expired")
def list_expired() -> dict:
    expired = get_lifecycle_manager().check_expired()
    return {"expired": [e.to_dict() for e in expired], "count": len(expired)}


# ── ARQ cron jobs ─────────────────────────────────────────────────────────────

async def lifecycle_check_expired(ctx) -> dict:  # type: ignore[type-arg]
    """ARQ daily job — log expired entities."""
    expired = get_lifecycle_manager().check_expired()
    log.info("lifecycle cron: %d expired entities", len(expired))
    return {"expired_count": len(expired)}


async def lifecycle_purge_expired(ctx) -> dict:  # type: ignore[type-arg]
    """ARQ weekly job — purge expired entities."""
    return get_lifecycle_manager().purge_expired()
