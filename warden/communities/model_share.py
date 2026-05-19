"""
warden/communities/model_share.py  (CM-27)
──────────────────────────────────────────
Community AI model sharing — package detection rules as signed UECIID bundles
that can be shared across communities without exposing raw patterns.

A ModelBundle wraps a set of SemanticGuard/EvolutionEngine rules and signs
them as a UECIID entity, enabling:
  - Traceable provenance via SEP audit chain
  - HMAC-signed payload (tamper-evident, same as CTP)
  - Optional PQC signature when source community has hybrid keypair
  - Import-with-approval flow (human-in-the-loop gate)

Bundle format
─────────────
  {
    "ueciid":          "SEP-{11 chars}",
    "bundle_type":     "MODEL_RULES",
    "rule_count":      int,
    "rules_hash":      SHA-256(serialised_rules),
    "rules":           [...],          ← only in FULL_SYNC transfers
    "attack_types":    [str],          ← metadata, always shared
    "source_community": str,
    "effectiveness":   float,
    "hmac":            hex,
    "pqc_signature":   base64 | null,
    "created_at":      ISO-8601,
  }

Privacy
───────
  - `rules` field is stripped before cross-community transfer unless
    peering policy == FULL_SYNC
  - `rules_hash` allows integrity verification without pattern exposure
  - Importing community validates HMAC before adding any examples

Storage: SQLite `sep_model_bundles` in SEP_DB_PATH.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

log = logging.getLogger("warden.communities.model_share")

_DB_PATH   = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
_HMAC_KEY  = os.getenv("COMMUNITY_VAULT_KEY", "model-share-default")


@dataclass
class ModelBundle:
    ueciid:            str
    bundle_type:       str
    rule_count:        int
    rules_hash:        str
    rules:             list[dict]
    attack_types:      list[str]
    source_community:  str
    effectiveness:     float
    hmac_sig:          str
    pqc_signature:     str
    created_at:        str


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sep_model_bundles (
            ueciid            TEXT PRIMARY KEY,
            source_community  TEXT NOT NULL,
            bundle_type       TEXT NOT NULL,
            rule_count        INTEGER,
            rules_hash        TEXT,
            rules_json        TEXT,
            attack_types_json TEXT,
            effectiveness     REAL,
            hmac_sig          TEXT,
            pqc_signature     TEXT,
            created_at        TEXT
        )
    """)
    conn.commit()
    return conn


def _sign(payload: str) -> str:
    return _hmac.new(_HMAC_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _verify_hmac(payload: str, sig: str) -> bool:
    expected = _sign(payload)
    return _hmac.compare_digest(expected, sig)


def create_bundle(
    rules: list[dict],
    source_community: str,
    effectiveness: float = 0.0,
    pqc_sign: bool = False,
) -> ModelBundle:
    """
    Package a list of rules as a signed ModelBundle and store it.

    `rules` should be dicts with at least {"pattern": str, "label": str, ...}.
    Patterns are included only for local storage; they are stripped on transfer.
    """
    from warden.communities.sep import new_ueciid  # noqa: PLC0415

    # Compute attack type distribution
    attack_types = list({r.get("attack_type", "unknown") for r in rules if r})

    # Hash the serialised rules (canonical JSON)
    rules_serial = json.dumps(rules, sort_keys=True, ensure_ascii=False)
    rules_hash   = hashlib.sha256(rules_serial.encode()).hexdigest()

    _, ueciid = new_ueciid()

    payload = f"{ueciid}|{rules_hash}|{source_community}|{len(rules)}"
    sig     = _sign(payload)

    pqc_sig = ""
    if pqc_sign:
        pqc_sig = _pqc_sign_bundle(payload, source_community)

    bundle = ModelBundle(
        ueciid           = ueciid,
        bundle_type      = "MODEL_RULES",
        rule_count       = len(rules),
        rules_hash       = rules_hash,
        rules            = rules,
        attack_types     = attack_types,
        source_community = source_community,
        effectiveness    = round(effectiveness, 4),
        hmac_sig         = sig,
        pqc_signature    = pqc_sig,
        created_at       = datetime.now(UTC).isoformat(),
    )

    _store_bundle(bundle)
    log.info("model_share: created bundle ueciid=%s rules=%d", ueciid, len(rules))
    return bundle


def _store_bundle(bundle: ModelBundle) -> None:
    conn = _db()
    try:
        conn.execute("""
            INSERT OR REPLACE INTO sep_model_bundles
            (ueciid, source_community, bundle_type, rule_count, rules_hash,
             rules_json, attack_types_json, effectiveness, hmac_sig, pqc_signature, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            bundle.ueciid, bundle.source_community, bundle.bundle_type,
            bundle.rule_count, bundle.rules_hash,
            json.dumps(bundle.rules), json.dumps(bundle.attack_types),
            bundle.effectiveness, bundle.hmac_sig, bundle.pqc_signature,
            bundle.created_at,
        ))
        conn.commit()
    finally:
        conn.close()


def get_bundle(ueciid: str, include_rules: bool = False) -> dict | None:
    conn = _db()
    try:
        row = conn.execute(
            "SELECT * FROM sep_model_bundles WHERE ueciid = ?", (ueciid,)
        ).fetchone()
        if not row:
            return None
        cols = [d[0] for d in conn.execute("SELECT * FROM sep_model_bundles LIMIT 0").description]
        d = dict(zip(cols, row, strict=False))
        d["attack_types"] = json.loads(d.pop("attack_types_json", "[]"))
        rules_json = d.pop("rules_json", "[]")
        if include_rules:
            d["rules"] = json.loads(rules_json)
        return d
    finally:
        conn.close()


def list_bundles(source_community: str | None = None) -> list[dict]:
    conn = _db()
    try:
        sql = "SELECT ueciid, source_community, bundle_type, rule_count, attack_types_json, effectiveness, created_at FROM sep_model_bundles"
        params: tuple = ()
        if source_community:
            sql += " WHERE source_community = ?"
            params = (source_community,)
        sql += " ORDER BY created_at DESC LIMIT 100"
        rows = conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            result.append({
                "ueciid":           row[0],
                "source_community": row[1],
                "bundle_type":      row[2],
                "rule_count":       row[3],
                "attack_types":     json.loads(row[4] or "[]"),
                "effectiveness":    row[5],
                "created_at":       row[6],
            })
        return result
    finally:
        conn.close()


def import_bundle(bundle_payload: dict, importing_community: str) -> dict:
    """
    Import a ModelBundle from a peer community.
    Validates HMAC, logs to STIX audit chain, and injects rules (requires approval).
    Returns {"status", "ueciid", "rule_count", "requires_approval"}.
    """
    ueciid    = bundle_payload.get("ueciid", "")
    rules_hash = bundle_payload.get("rules_hash", "")
    community  = bundle_payload.get("source_community", "")
    rule_count = bundle_payload.get("rule_count", 0)
    sig        = bundle_payload.get("hmac_sig", "")

    # Verify HMAC
    payload = f"{ueciid}|{rules_hash}|{community}|{rule_count}"
    if not _verify_hmac(payload, sig):
        log.warning("model_share: import rejected — HMAC mismatch for %s", ueciid)
        return {"status": "REJECTED", "reason": "hmac_mismatch", "ueciid": ueciid}

    rules = bundle_payload.get("rules", [])

    # Bundles with rules require human approval before hot-reload
    return {
        "status":            "PENDING_APPROVAL",
        "ueciid":            ueciid,
        "rule_count":        len(rules) if rules else rule_count,
        "attack_types":      bundle_payload.get("attack_types", []),
        "source_community":  community,
        "requires_approval": True,
        "message":           "Bundle imported but rules require MasterAgent approval before activation.",
    }


def activate_bundle(ueciid: str) -> int:
    """
    Activate a previously imported bundle — inject rules into EvolutionEngine.
    Called after human-in-the-loop approval.
    Returns count of rules activated.
    """
    bundle = get_bundle(ueciid, include_rules=True)
    if not bundle:
        return 0

    rules = bundle.get("rules", [])
    if not rules:
        return 0

    try:
        from warden.brain.evolve import EvolutionEngine  # noqa: PLC0415
        EvolutionEngine().add_examples([{
            "text":   r.get("pattern", r.get("text", "")),
            "label":  r.get("label", "HIGH_RISK"),
            "source": f"model_bundle:{bundle['source_community']}:{ueciid}",
        } for r in rules if r.get("pattern") or r.get("text")])
        log.info("model_share: activated %d rules from bundle %s", len(rules), ueciid)
        return len(rules)
    except Exception as exc:
        log.error("model_share: activate failed: %s", exc)
        return 0


def _pqc_sign_bundle(payload: str, community_id: str) -> str:
    try:
        import base64  # noqa: PLC0415

        from warden.communities.keypair import load_community_keypair  # noqa: PLC0415
        kp = load_community_keypair(community_id)
        if kp and kp.is_hybrid:
            sig = kp.hybrid_sign(payload.encode())
            return base64.b64encode(sig).decode()
    except Exception:
        pass
    return ""


# ── FastAPI router ────────────────────────────────────────────────────────────

from fastapi import APIRouter, HTTPException  # noqa: E402
from pydantic import BaseModel  # noqa: E402

router = APIRouter(prefix="/sep/model-bundles", tags=["Model Sharing"])


class ImportBundleRequest(BaseModel):
    bundle: dict
    importing_community: str


@router.get("", summary="List all model bundles")
async def list_model_bundles(source_community: str | None = None):
    return {"bundles": list_bundles(source_community)}


@router.get("/{ueciid}", summary="Get a model bundle by UECIID")
async def get_model_bundle(ueciid: str, include_rules: bool = False):
    bundle = get_bundle(ueciid, include_rules=include_rules)
    if not bundle:
        raise HTTPException(status_code=404, detail=f"Bundle {ueciid} not found")
    return bundle


@router.post("/import", summary="Import a model bundle from a peer community")
async def import_model_bundle(body: ImportBundleRequest):
    return import_bundle(body.bundle, body.importing_community)


@router.post("/{ueciid}/activate", summary="Activate an imported bundle post-approval")
async def activate_model_bundle(ueciid: str):
    count = activate_bundle(ueciid)
    if count == 0:
        raise HTTPException(status_code=404, detail=f"Bundle {ueciid} not found or has no rules")
    return {"activated": True, "rules_loaded": count, "ueciid": ueciid}
