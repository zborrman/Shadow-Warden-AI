"""
warden/sovereign/attestation.py
─────────────────────────────────
Sovereignty Attestation — cryptographic proof that an AI request was processed
within a specific jurisdiction without crossing restricted borders.

Attestation fields:
  attest_id        UUID-based attestation ID
  request_id       Shadow Warden filter request_id (links to audit trail)
  tenant_id        Tenant that made the request
  jurisdiction     Jurisdiction where the request was processed
  tunnel_id        MASQUE tunnel used (null for DIRECT)
  data_class       Data classification of the payload
  compliant        Whether the routing satisfied the tenant's policy
  frameworks       Compliance frameworks satisfied (["GDPR", "EU_AI_ACT", ...])
  issued_at        ISO timestamp
  data_path        ["origin_jurisdiction", "tunnel_jurisdiction", "ai_provider_region"]
  signature        HMAC-SHA256 over canonical fields (SOVEREIGN_ATTEST_KEY env var)

The signature allows auditors to verify that the attestation was issued by
Shadow Warden and has not been tampered with.  SOVEREIGN_ATTEST_KEY must be
a 32+ byte secret; falls back to VAULT_MASTER_KEY if not set.

Storage: Redis `sovereign:attest:{attest_id}` (TTL = 7 years / 220,752,000 s).
         Redis set `sovereign:attests:{tenant_id}` (index for listing).
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.sovereign.attestation")

_ATTEST_TTL  = 220_752_000        # 7 years in seconds (SOC 2 audit retention)
_ATTEST_CAP  = 10_000             # max attestations stored per tenant


def _attest_key() -> bytes:
    raw = (
        os.getenv("SOVEREIGN_ATTEST_KEY")
        or os.getenv("VAULT_MASTER_KEY")
        or os.getenv("COMMUNITY_VAULT_KEY")
        or "dev-sovereign-attest-key-insecure"
    )
    return raw.encode() if isinstance(raw, str) else raw


def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


_MEMORY_ATTESTS: dict[str, dict] = {}


# ── Dataclass ─────────────────────────────────────────────────────────────────

@dataclass
class SovereigntyAttestation:
    attest_id:   str
    request_id:  str
    tenant_id:   str
    jurisdiction: str
    tunnel_id:   str | None
    region:      str
    data_class:  str
    compliant:   bool
    action:      str           # "TUNNEL" | "DIRECT" | "BLOCK"
    frameworks:  list[str]
    data_path:   list[str]     # [origin_jcode, tunnel_jcode, provider_region]
    issued_at:   str
    signature:   str           # HMAC-SHA256 hex


# ── Canonical signing payload ─────────────────────────────────────────────────

def _canonical(a: SovereigntyAttestation) -> bytes:
    """Deterministic UTF-8 bytes over the fields that must not change."""
    return (
        f"{a.attest_id}|{a.request_id}|{a.tenant_id}|"
        f"{a.jurisdiction}|{a.tunnel_id or ''}|{a.data_class}|"
        f"{int(a.compliant)}|{a.issued_at}"
    ).encode()


def _sign(canonical: bytes) -> str:
    return hmac.new(_attest_key(), canonical, hashlib.sha256).hexdigest()


def _verify_signature(a: SovereigntyAttestation) -> bool:
    expected = _sign(_canonical(a))
    return hmac.compare_digest(expected, a.signature)


# ── Issue ─────────────────────────────────────────────────────────────────────

def issue_attestation(
    request_id:   str,
    tenant_id:    str,
    route:        Any,           # RouteDecision from router.py
    data_class:   str  = "GENERAL",
    origin_jcode: str  = "EU",
) -> SovereigntyAttestation:
    """
    Issue a signed sovereignty attestation for a completed route decision.

    Call this after the AI API response is received to close the circuit.
    """
    from warden.sovereign.tunnel import get_tunnel

    tunnel   = get_tunnel(route.tunnel_id) if route.tunnel_id else None
    region   = tunnel.region if tunnel else "unknown"
    now      = datetime.now(UTC).isoformat()

    data_path = [
        origin_jcode,
        route.jurisdiction,
        region,
    ]

    a = SovereigntyAttestation(
        attest_id   = f"sa-{uuid.uuid4().hex}",
        request_id  = request_id,
        tenant_id   = tenant_id,
        jurisdiction= route.jurisdiction,
        tunnel_id   = route.tunnel_id,
        region      = region,
        data_class  = data_class,
        compliant   = route.compliant,
        action      = route.action,
        frameworks  = route.frameworks,
        data_path   = data_path,
        issued_at   = now,
        signature   = "",   # filled below
    )
    a.signature = _sign(_canonical(a))

    # Persist
    _store_attestation(a, tenant_id)
    log.info(
        "Attestation issued %s req=%s tenant=%s jurisdiction=%s compliant=%s",
        a.attest_id, request_id, tenant_id, route.jurisdiction, route.compliant,
    )
    return a


def _store_attestation(a: SovereigntyAttestation, tenant_id: str) -> None:
    d = asdict(a)
    d["frameworks"] = json.dumps(d["frameworks"])
    d["data_path"]  = json.dumps(d["data_path"])

    _MEMORY_ATTESTS[a.attest_id] = asdict(a)

    r = _redis()
    if not r:
        return
    try:
        r.setex(f"sovereign:attest:{a.attest_id}", _ATTEST_TTL, json.dumps(asdict(a)))
        r.lpush(f"sovereign:attests:{tenant_id}", a.attest_id)
        r.ltrim(f"sovereign:attests:{tenant_id}", 0, _ATTEST_CAP - 1)
    except Exception as exc:
        log.debug("_store_attestation redis error: %s", exc)


# ── Retrieve ──────────────────────────────────────────────────────────────────

def get_attestation(attest_id: str) -> SovereigntyAttestation | None:
    r = _redis()
    if r:
        try:
            raw = r.get(f"sovereign:attest:{attest_id}")
            if raw:
                d = json.loads(raw)
                return _dict_to_attest(d)
        except Exception as exc:
            log.debug("get_attestation redis error: %s", exc)
    d = _MEMORY_ATTESTS.get(attest_id)
    return _dict_to_attest(d) if d else None


def get_attestations_for_request(request_id: str, tenant_id: str) -> list[SovereigntyAttestation]:
    """Return all attestations linked to *request_id* for *tenant_id*."""
    all_a = list_attestations(tenant_id, limit=200)
    return [a for a in all_a if a.request_id == request_id]


def list_attestations(tenant_id: str, limit: int = 100) -> list[SovereigntyAttestation]:
    r = _redis()
    ids: list[str] = []
    if r:
        with contextlib.suppress(Exception):
            ids = r.lrange(f"sovereign:attests:{tenant_id}", 0, limit - 1)
    if not ids:
        # In-memory fallback — filter by tenant
        ids = [
            a["attest_id"]
            for a in _MEMORY_ATTESTS.values()
            if a.get("tenant_id") == tenant_id
        ][:limit]

    result: list[SovereigntyAttestation] = []
    for aid in ids:
        a = get_attestation(aid)
        if a:
            result.append(a)
    return result


def verify_attestation(attest_id: str) -> dict:
    """
    Cryptographically verify an attestation's HMAC signature.
    Returns {"valid": bool, "attest_id": str, "reason": str}.
    """
    a = get_attestation(attest_id)
    if not a:
        return {"valid": False, "attest_id": attest_id, "reason": "Attestation not found."}
    valid = _verify_signature(a)
    return {
        "valid":      valid,
        "attest_id":  attest_id,
        "tenant_id":  a.tenant_id,
        "issued_at":  a.issued_at,
        "compliant":  a.compliant,
        "reason":     "Signature valid." if valid else "Signature mismatch — attestation may have been tampered.",
    }


def _dict_to_attest(d: dict) -> SovereigntyAttestation:
    frameworks = d.get("frameworks", [])
    data_path  = d.get("data_path", [])
    if isinstance(frameworks, str):
        try:
            frameworks = json.loads(frameworks)
        except Exception:
            frameworks = []
    if isinstance(data_path, str):
        try:
            data_path = json.loads(data_path)
        except Exception:
            data_path = []
    return SovereigntyAttestation(
        attest_id    = d["attest_id"],
        request_id   = d["request_id"],
        tenant_id    = d["tenant_id"],
        jurisdiction = d["jurisdiction"],
        tunnel_id    = d.get("tunnel_id"),
        region       = d.get("region", "unknown"),
        data_class   = d.get("data_class", "GENERAL"),
        compliant    = bool(d.get("compliant", False)),
        action       = d.get("action", "DIRECT"),
        frameworks   = frameworks,
        data_path    = data_path,
        issued_at    = d.get("issued_at", ""),
        signature    = d.get("signature", ""),
    )
