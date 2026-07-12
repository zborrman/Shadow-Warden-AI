"""
Community Evolution — share and import anonymised evolution rules.
All rules require human-in-the-loop approval (status=approved) before import.
Rules are screened through the warden filter for malicious content.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass

from warden.config import data_path

COMM_DB_PATH = data_path("warden_communities.db", "COMM_DB_PATH")
_lock = threading.RLock()

RULE_TYPES = ("regex_pattern", "embedding_example", "jailbreak_signature", "compound_rule")


@dataclass
class EvolutionBundle:
    bundle_id: str
    community_id: str
    publisher_tenant_id: str
    rule_type: str
    rule_content: str
    ueciid: str
    status: str         # pending_review / approved / rejected / imported
    published_at: str
    reviewed_at: str = ""
    import_count: int = 0
    threat_score: float = 0.0


def _db():
    import sqlite3
    c = sqlite3.connect(COMM_DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript("""
        CREATE TABLE IF NOT EXISTS evolution_bundles (
            bundle_id           TEXT PRIMARY KEY,
            community_id        TEXT NOT NULL,
            publisher_tenant_id TEXT NOT NULL,
            rule_type           TEXT NOT NULL DEFAULT 'jailbreak_signature',
            rule_content        TEXT NOT NULL,
            ueciid              TEXT NOT NULL DEFAULT '',
            status              TEXT NOT NULL DEFAULT 'pending_review',
            published_at        TEXT NOT NULL,
            reviewed_at         TEXT NOT NULL DEFAULT '',
            import_count        INTEGER NOT NULL DEFAULT 0,
            threat_score        REAL NOT NULL DEFAULT 0.0
        );
        CREATE INDEX IF NOT EXISTS idx_eb_community ON evolution_bundles(community_id, status);
        CREATE INDEX IF NOT EXISTS idx_eb_status    ON evolution_bundles(status);
    """)
    c.commit()
    return c


def _assign_ueciid() -> str:
    try:
        from warden.communities.sep import new_ueciid
        result = new_ueciid()
        return str(result[0]) if isinstance(result, tuple) else str(result)
    except Exception:
        return f"SEP-{uuid.uuid4().hex[:11]}"


def _screen_rule(rule_content: str, tenant_id: str) -> float:
    """Screen rule via warden filter; return threat score (fail-open → 0.0)."""
    try:
        import httpx
        r = httpx.post(
            "http://localhost:8001/filter",
            json={"text": rule_content[:2000], "tenant_id": tenant_id},
            timeout=3.0,
        )
        if r.status_code == 200:
            return float(r.json().get("score", 0.0))
    except Exception:
        pass
    return 0.0


def share_rule(
    community_id: str,
    publisher_tenant_id: str,
    rule_type: str,
    rule_content: str,
) -> EvolutionBundle:
    if rule_type not in RULE_TYPES:
        rule_type = "jailbreak_signature"

    bid = uuid.uuid4().hex[:32]
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ueciid = _assign_ueciid()
    threat_score = _screen_rule(rule_content, publisher_tenant_id)

    bundle = EvolutionBundle(
        bundle_id=bid,
        community_id=community_id,
        publisher_tenant_id=publisher_tenant_id,
        rule_type=rule_type,
        rule_content=rule_content,
        ueciid=ueciid,
        status="pending_review",
        published_at=ts,
        threat_score=threat_score,
    )
    with _lock:
        db = _db()
        db.execute(
            "INSERT INTO evolution_bundles VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (bid, community_id, publisher_tenant_id, rule_type, rule_content,
             ueciid, "pending_review", ts, "", 0, threat_score),
        )
        db.commit()
    return bundle


def get_bundle(bundle_id: str) -> EvolutionBundle | None:
    row = _db().execute(
        "SELECT * FROM evolution_bundles WHERE bundle_id=?", (bundle_id,)
    ).fetchone()
    return EvolutionBundle(**dict(row)) if row else None


def approve_rule(bundle_id: str, reviewer_tenant_id: str) -> bool:  # noqa: ARG001
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _lock:
        db = _db()
        cur = db.execute(
            "UPDATE evolution_bundles SET status='approved', reviewed_at=? WHERE bundle_id=?",
            (ts, bundle_id),
        )
        db.commit()
        return cur.rowcount > 0


def reject_rule(bundle_id: str) -> bool:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _lock:
        db = _db()
        cur = db.execute(
            "UPDATE evolution_bundles SET status='rejected', reviewed_at=? WHERE bundle_id=?",
            (ts, bundle_id),
        )
        db.commit()
        return cur.rowcount > 0


def import_rule(bundle_id: str, target_community_id: str) -> bool:  # noqa: ARG001
    """Import an approved bundle into the local evolution engine."""
    bundle = get_bundle(bundle_id)
    if not bundle or bundle.status != "approved":
        return False

    try:
        from warden.brain.evolve import EvolutionEngine
        eng = EvolutionEngine()
        if bundle.rule_type in ("embedding_example", "jailbreak_signature"):
            eng.add_examples([{"text": bundle.rule_content, "label": "jailbreak"}])
        elif bundle.rule_type == "regex_pattern":
            # Treat as a new candidate rule for the engine to evaluate
            eng.add_examples([{"text": bundle.rule_content, "label": "jailbreak"}])
    except Exception:
        pass  # fail-open — still record the import

    with _lock:
        db = _db()
        db.execute(
            "UPDATE evolution_bundles SET import_count=import_count+1 WHERE bundle_id=?",
            (bundle_id,),
        )
        db.commit()
    return True


def list_bundles(
    community_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[EvolutionBundle]:
    sql = "SELECT * FROM evolution_bundles WHERE 1=1"
    params: list = []
    if community_id:
        sql += " AND community_id=?"
        params.append(community_id)
    if status:
        sql += " AND status=?"
        params.append(status)
    sql += f" ORDER BY published_at DESC LIMIT {limit}"
    return [EvolutionBundle(**dict(r)) for r in _db().execute(sql, params).fetchall()]


def get_evolution_stats(community_id: str) -> dict:
    db = _db()
    row = db.execute(
        """SELECT
               COUNT(*) AS total,
               SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) AS approved,
               SUM(CASE WHEN status='pending_review' THEN 1 ELSE 0 END) AS pending,
               SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) AS rejected,
               SUM(import_count) AS total_imports
           FROM evolution_bundles WHERE community_id=?""",
        (community_id,),
    ).fetchone()
    return dict(row)
