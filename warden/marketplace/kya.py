"""
warden/marketplace/kya.py
─────────────────────────
Know Your Agent (KYA) framework — regulatory compliance layer for M2M agents.

KYA is the agent-identity equivalent of KYC. Every agent registered in the
marketplace gets a KYA record linking its DID to an owner tenant, a risk score,
and a compliance status badge used by search and clearing.

Risk scoring v1 uses ERS Redis scores + registration velocity.
External Persona/Crossmint integration is planned for v2.

Env vars
────────
  KYA_VERIFIED_ONLY                true/false (default false) — reject unverified agents in search
  KYA_AUTO_VERIFY_SCORE_THRESHOLD  float 0.0–1.0 (default 0.3) — auto-VERIFIED if risk ≤ this
  MARKETPLACE_DB_PATH              SQLite path (shared with listing.py)
  REDIS_URL                        Redis URL (kya records cached 1h)
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field

from warden.config import data_path
from warden.db.sqlite_pragmas import init_pragmas

log = logging.getLogger("warden.marketplace.kya")

_DB_PATH    = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_db_lock    = threading.RLock()
_REDIS_TTL  = 3600   # 1 hour

_KYA_VERIFIED_ONLY    = os.getenv("KYA_VERIFIED_ONLY", "false").lower() == "true"
_AUTO_VERIFY_THRESHOLD = float(os.getenv("KYA_AUTO_VERIFY_SCORE_THRESHOLD", "0.3"))


# ── Dataclass ─────────────────────────────────────────────────────────────────

@dataclass
class KYARecord:
    agent_id:        str
    owner_tenant_id: str
    kya_status:      str         # PENDING | VERIFIED | FLAGGED | REVOKED
    risk_score:      float       # 0.0–1.0
    screened_at:     str         # ISO timestamp
    flags:           list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ── Schema ────────────────────────────────────────────────────────────────────

def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS marketplace_kya_records (
            agent_id        TEXT PRIMARY KEY,
            owner_tenant_id TEXT NOT NULL DEFAULT '',
            kya_status      TEXT NOT NULL DEFAULT 'PENDING',
            risk_score      REAL NOT NULL DEFAULT 0.5,
            screened_at     TEXT NOT NULL,
            flags           TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_kya_status ON marketplace_kya_records(kya_status);
        CREATE INDEX IF NOT EXISTS idx_kya_owner  ON marketplace_kya_records(owner_tenant_id);
    """)


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    init_pragmas(con)
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True, socket_connect_timeout=5, socket_timeout=3)
    except Exception:
        return None


def _cache_set(agent_id: str, status: str) -> None:
    try:
        r = _redis()
        if r:
            r.setex(f"marketplace:kya:{agent_id}", _REDIS_TTL, status)
    except Exception as exc:
        log.debug("kya redis set error: %s", exc)


def _cache_get(agent_id: str) -> str | None:
    try:
        r = _redis()
        if r:
            return r.get(f"marketplace:kya:{agent_id}")
    except Exception as exc:
        log.debug("kya redis get error: %s", exc)
    return None


def _cache_del(agent_id: str) -> None:
    try:
        r = _redis()
        if r:
            r.delete(f"marketplace:kya:{agent_id}")
    except Exception as exc:
        log.debug("kya redis del error: %s", exc)


# ── Risk scoring ──────────────────────────────────────────────────────────────

def _compute_risk_score(agent_id: str) -> tuple[float, list[str]]:
    """Compute risk score 0.0–1.0 for agent. Returns (score, flags).

    v1: checks ERS Redis score as a proxy for suspicious activity.
    Agents with no ERS history get a low-risk default.
    v2: will call Persona/Crossmint identity verification API.
    """
    flags: list[str] = []
    risk = 0.1   # base low risk for newly registered agents

    try:
        r = _redis()
        if r:
            # ERS stores sliding window score at ers:{agent_id} or by session/tenant
            ers_key = f"ers:{agent_id}"
            raw = r.get(ers_key)
            if raw is not None:
                ers_score = float(raw)
                if ers_score >= 0.75:
                    risk = max(risk, ers_score)
                    flags.append("HIGH_VELOCITY")
                    log.debug("kya: agent=%s ERS score=%.2f → HIGH_VELOCITY", agent_id[:32], ers_score)
                elif ers_score >= 0.5:
                    risk = max(risk, ers_score * 0.8)
                    flags.append("ELEVATED_RISK")
    except Exception as exc:
        log.debug("kya risk scorer redis error: %s", exc)

    # Check registration velocity — many agents registered by same owner in short window
    # (stubbed for v1; v2 will query owner registration history)

    risk = min(1.0, max(0.0, risk))
    return risk, flags


# ── Public API ────────────────────────────────────────────────────────────────

def register_agent(agent_id: str, owner_tenant_id: str) -> KYARecord:
    """Create a PENDING KYA record for a newly registered agent."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    record = KYARecord(
        agent_id=agent_id,
        owner_tenant_id=owner_tenant_id,
        kya_status="PENDING",
        risk_score=0.5,
        screened_at=now,
        flags=[],
    )
    with _db_lock, _conn() as con:
        con.execute(
            """INSERT OR REPLACE INTO marketplace_kya_records
               (agent_id, owner_tenant_id, kya_status, risk_score, screened_at, flags)
               VALUES (?,?,?,?,?,?)""",
            (agent_id, owner_tenant_id, "PENDING", 0.5, now, "[]"),
        )
    _cache_set(agent_id, "PENDING")
    log.info("kya: registered agent=%s owner=%s", agent_id[:32], owner_tenant_id)
    return record


def _require_kyb_behind_kya(owner_tenant_id: str, agent_id: str, flags: list[str]) -> None:
    """FT-5: a FLAGGED agent escalates KYB on its owning tenant.

    Guarded (lazy import + broad except) so a KYB failure can never break KYA
    screening — the same posture as the ledger dual-write mirrors.
    """
    if not owner_tenant_id:
        return
    try:
        from warden.marketplace import kyb
        kyb.require_kyb(owner_tenant_id, reason=f"kya_flagged:{','.join(flags) or 'unspecified'}:{agent_id[:16]}")
    except Exception as exc:
        log.warning("kya: kyb escalation failed for tenant=%s: %s", owner_tenant_id, exc)


def screen_agent(agent_id: str) -> KYARecord:
    """Run risk screening and update kya_status.

    Auto-VERIFIED when risk_score ≤ KYA_AUTO_VERIFY_SCORE_THRESHOLD.
    FLAGGED when risk_score > threshold — this also escalates a KYB
    requirement onto the agent's owning tenant (FT-5, "KYB behind KYA").
    Fail-open: screening errors leave status as PENDING.
    """
    try:
        risk, flags = _compute_risk_score(agent_id)
        status = "VERIFIED" if risk <= _AUTO_VERIFY_THRESHOLD else "FLAGGED"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        flags_json = json.dumps(flags)

        with _db_lock, _conn() as con:
            con.execute(
                """INSERT INTO marketplace_kya_records
                   (agent_id, owner_tenant_id, kya_status, risk_score, screened_at, flags)
                   VALUES (?,
                     COALESCE((SELECT owner_tenant_id FROM marketplace_kya_records WHERE agent_id=?), ''),
                     ?,?,?,?)
                   ON CONFLICT(agent_id) DO UPDATE SET
                     kya_status=excluded.kya_status,
                     risk_score=excluded.risk_score,
                     screened_at=excluded.screened_at,
                     flags=excluded.flags""",
                (agent_id, agent_id, status, risk, now, flags_json),
            )
            row = con.execute(
                "SELECT * FROM marketplace_kya_records WHERE agent_id=?", (agent_id,)
            ).fetchone()

        _cache_set(agent_id, status)
        log.info("kya: screened agent=%s status=%s risk=%.2f flags=%s",
                 agent_id[:32], status, risk, flags)
        record = _row_to_record(row)
        if status == "FLAGGED":
            _require_kyb_behind_kya(record.owner_tenant_id, agent_id, flags)
        return record

    except Exception as exc:
        log.warning("kya: screen_agent fail-open for %s: %s", agent_id[:32], exc)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return KYARecord(agent_id=agent_id, owner_tenant_id="", kya_status="PENDING",
                         risk_score=0.5, screened_at=now, flags=[])


def get_kya_status(agent_id: str) -> str:
    """Return kya_status string. Redis fast-path, SQLite fallback. Returns 'PENDING' if unknown."""
    cached = _cache_get(agent_id)
    if cached:
        return cached
    try:
        with _conn() as con:
            row = con.execute(
                "SELECT kya_status FROM marketplace_kya_records WHERE agent_id=?", (agent_id,)
            ).fetchone()
        if row:
            status = row["kya_status"]
            _cache_set(agent_id, status)
            return status
    except Exception as exc:
        log.debug("kya: get_kya_status error: %s", exc)
    return "PENDING"


def get_kya_record(agent_id: str) -> KYARecord | None:
    """Return full KYARecord from SQLite, or None if not found."""
    try:
        with _conn() as con:
            row = con.execute(
                "SELECT * FROM marketplace_kya_records WHERE agent_id=?", (agent_id,)
            ).fetchone()
        return _row_to_record(row) if row else None
    except Exception as exc:
        log.warning("kya: get_kya_record error: %s", exc)
        return None


def revoke_agent(agent_id: str, reason: str = "admin_revoke") -> None:
    """Set kya_status to REVOKED and flush Redis cache."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _db_lock, _conn() as con:
        con.execute(
            """UPDATE marketplace_kya_records
               SET kya_status='REVOKED', screened_at=?,
                   flags=json_insert(COALESCE(flags,'[]'), '$[#]', ?)
               WHERE agent_id=?""",
            (now, f"REVOKED:{reason}", agent_id),
        )
    _cache_del(agent_id)
    _cache_set(agent_id, "REVOKED")
    log.info("kya: revoked agent=%s reason=%s", agent_id[:32], reason)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _row_to_record(row: sqlite3.Row) -> KYARecord:
    try:
        flags = json.loads(row["flags"] or "[]")
    except Exception:
        flags = []
    return KYARecord(
        agent_id=row["agent_id"],
        owner_tenant_id=row["owner_tenant_id"],
        kya_status=row["kya_status"],
        risk_score=float(row["risk_score"]),
        screened_at=row["screened_at"],
        flags=flags,
    )
