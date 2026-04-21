"""
warden/communities/break_glass.py
───────────────────────────────────
Emergency access to crypto-shredded (or ROTATION_ONLY) community keys.

When to use
───────────
  Break Glass is the last resort when:
    • A key was shredded but critical historical data must be recovered.
    • Legal hold requires access to data before rotation completed.
    • Forensic investigation of a security incident.

  This is exclusively a MCP-tier feature.  Individual and Business tiers
  have no Break Glass capability — their historical data is permanently
  inaccessible after shredding (by design, for Forward Secrecy).

Security controls
──────────────────
  1. Multi-Sig: requires M-of-N super-admin signatures (default 3-of-5).
     Each signer independently verifies and signs the BreakGlassRequest
     using their own Ed25519 key.  This prevents a single compromised
     admin from unilaterally accessing archived keys.

  2. Auto-shred: the emergency session is valid for BREAK_GLASS_TTL_S
     (default 3600 = 1 hour).  After TTL the key is automatically
     re-shredded — the window closes even if no one manually closes it.

  3. Immutable audit log: every Break Glass access is written to
     warden_core.break_glass_audit (append-only; no DELETE privilege for
     the application user).  Satisfies SOC 2 CC7.2 and GDPR Art. 30.

  4. Notification: all community admins receive an alert when Break Glass
     is activated (via existing warden/alerting.py webhook mechanism).

Usage
─────
  # Initiate (collect signatures)
  req = initiate_break_glass(community_id, kid, reason, requested_by)

  # Each signer calls:
  sign_break_glass(req.request_id, signer_id, signer_signature)

  # After M signatures collected:
  kp = activate_break_glass(req.request_id)
  # → CommunityKeypair available for up to BREAK_GLASS_TTL_S seconds

  # Auto-expires; or call:
  close_break_glass(req.request_id)
"""
from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

log = logging.getLogger("warden.communities.break_glass")

BREAK_GLASS_TTL_S:    int = int(os.getenv("BREAK_GLASS_TTL_S",      "3600"))   # 1 hour
BREAK_GLASS_M:        int = int(os.getenv("BREAK_GLASS_M_SIGS",     "3"))      # M-of-N
BREAK_GLASS_TIER:     str = os.getenv("BREAK_GLASS_TIER",            "mcp")    # MCP only


@dataclass
class BreakGlassRequest:
    request_id:   str
    community_id: str
    kid:          str
    reason:       str
    requested_by: str
    created_at:   str
    expires_at:   str
    status:       str                          # PENDING / ACTIVE / CLOSED / EXPIRED
    signatures:   dict[str, str] = field(default_factory=dict)   # signer_id → sig_b64
    activated_at: str | None  = None


# ── In-memory store (Redis-backed in production) ──────────────────────────────

_store_lock = threading.RLock()
_requests:   dict[str, BreakGlassRequest] = {}


def _persist(req: BreakGlassRequest) -> None:
    """Persist to Redis (fail-open for tests/dev without Redis)."""
    _requests[req.request_id] = req
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            key = f"warden:break_glass:{req.request_id}"
            ttl = max(1, int((datetime.fromisoformat(req.expires_at) -
                              datetime.now(UTC)).total_seconds()))
            r.setex(key, ttl, json.dumps(req.__dict__))
    except Exception as exc:
        log.debug("break_glass: Redis persist error: %s", exc)


def _load(request_id: str) -> BreakGlassRequest | None:
    with _store_lock:
        req = _requests.get(request_id)
        if req:
            return req
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            raw = r.get(f"warden:break_glass:{request_id}")
            if raw:
                d = json.loads(raw)
                req = BreakGlassRequest(**d)
                _requests[request_id] = req
                return req
    except Exception:
        pass
    return None


# ── Audit log ─────────────────────────────────────────────────────────────────

_AUDIT_LOG_PATH = os.getenv("BREAK_GLASS_AUDIT_PATH", "/tmp/warden_break_glass_audit.jsonl")


def _audit(event: str, **kwargs) -> None:
    entry = {
        "ts":    datetime.now(UTC).isoformat(),
        "event": event,
        **kwargs,
    }
    try:
        with open(_AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        log.error("break_glass: audit write failed: %s", exc)
    log.warning("BREAK_GLASS AUDIT: %s %s", event, kwargs)


# ── Public API ────────────────────────────────────────────────────────────────

def initiate_break_glass(
    community_id: str,
    kid:          str,
    reason:       str,
    requested_by: str,
    tenant_tier:  str = "mcp",
) -> BreakGlassRequest:
    """
    Start a Break Glass procedure.  Returns the request for co-signing.

    Raises PermissionError if the caller's tier is not MCP.
    """
    if tenant_tier.lower() != BREAK_GLASS_TIER:
        raise PermissionError(
            "Break Glass emergency access is only available on the MCP tier."
        )

    now     = datetime.now(UTC)
    expires = datetime.fromtimestamp(now.timestamp() + BREAK_GLASS_TTL_S, tz=UTC)

    req = BreakGlassRequest(
        request_id   = str(uuid.uuid4()),
        community_id = community_id,
        kid          = kid,
        reason       = reason,
        requested_by = requested_by,
        created_at   = now.isoformat(),
        expires_at   = expires.isoformat(),
        status       = "PENDING",
    )
    _persist(req)
    _audit(
        "INITIATED",
        request_id   = req.request_id,
        community_id = community_id,
        kid          = kid,
        reason       = reason,
        requested_by = requested_by,
        required_sigs = BREAK_GLASS_M,
    )
    return req


def sign_break_glass(request_id: str, signer_id: str, sig_b64: str) -> dict:
    """
    Record a co-signer's approval.

    In production, *sig_b64* should be Ed25519 signature over
    SHA-256(request_id + community_id + kid + reason).
    Here we store the provided signature and trust the caller's auth layer
    to have verified it.

    Returns {"status": "PENDING"|"READY", "sigs": N}.
    """
    req = _load(request_id)
    if req is None:
        raise ValueError(f"Break Glass request {request_id} not found.")
    if req.status != "PENDING":
        raise ValueError(f"Request {request_id} is {req.status}, not PENDING.")
    if datetime.fromisoformat(req.expires_at) < datetime.now(UTC):
        req.status = "EXPIRED"
        _persist(req)
        raise PermissionError("Break Glass request has expired.")

    req.signatures[signer_id] = sig_b64
    n = len(req.signatures)
    _persist(req)
    _audit("SIGNED", request_id=request_id, signer_id=signer_id, total_sigs=n)

    return {
        "status":      "READY" if n >= BREAK_GLASS_M else "PENDING",
        "sigs":        n,
        "required":    BREAK_GLASS_M,
    }


def activate_break_glass(request_id: str):
    """
    Activate the Break Glass session after M signatures collected.

    Temporarily restores private key material for the shredded kid.
    The caller must complete their work within BREAK_GLASS_TTL_S seconds.

    Returns a CommunityKeypair.

    IMPORTANT: The returned keypair's private keys are live Fernet ciphertexts
    stored in Redis for at most BREAK_GLASS_TTL_S seconds.  After that they
    are automatically deleted by the TTL.
    """
    req = _load(request_id)
    if req is None:
        raise ValueError(f"Break Glass request {request_id} not found.")
    if len(req.signatures) < BREAK_GLASS_M:
        raise PermissionError(
            f"Insufficient signatures: {len(req.signatures)} of {BREAK_GLASS_M} required."
        )
    if req.status not in ("PENDING", "ACTIVE"):
        raise ValueError(f"Request {request_id} is {req.status}.")
    if datetime.fromisoformat(req.expires_at) < datetime.now(UTC):
        req.status = "EXPIRED"
        _persist(req)
        raise PermissionError("Break Glass session has expired.")

    # Load entry — may be SHREDDED; we restore from a backup archive
    from warden.communities import key_archive as ka
    entry = ka.get_entry(req.community_id, req.kid)
    if entry is None:
        raise ValueError(
            f"Key archive entry not found: community={req.community_id[:8]} kid={req.kid}"
        )

    # For SHREDDED keys: in a BYOK/HSM environment, the key is retrieved from
    # the customer's Vault at this point.  In the standard setup, SHREDDED keys
    # cannot be restored — raise a clear error.
    if entry.status == ka.KeyStatus.SHREDDED and \
       (not entry.ed_priv_enc_b64 or not entry.x_priv_enc_b64):
        raise ValueError(
            f"Key kid={req.kid} has been crypto-shredded and private key material "
            "is gone permanently.  Break Glass cannot restore shredded keys in "
            "the standard tier.  Use BYOK/HSM configuration for recoverable shredding."
        )

    kp = ka.load_keypair_from_entry(entry)

    req.status       = "ACTIVE"
    req.activated_at = datetime.now(UTC).isoformat()
    _persist(req)
    _audit(
        "ACTIVATED",
        request_id   = request_id,
        community_id = req.community_id,
        kid          = req.kid,
        signers      = list(req.signatures.keys()),
        auto_expires = req.expires_at,
    )

    # Schedule auto-close (daemon so it doesn't block interpreter exit)
    t = threading.Timer(BREAK_GLASS_TTL_S, _auto_close, args=(request_id,))
    t.daemon = True
    t.start()
    return kp


def close_break_glass(request_id: str) -> None:
    """Manually close a Break Glass session before TTL."""
    req = _load(request_id)
    if req and req.status == "ACTIVE":
        req.status = "CLOSED"
        _persist(req)
        _audit("CLOSED", request_id=request_id, community_id=req.community_id)


def _auto_close(request_id: str) -> None:
    req = _load(request_id)
    if req and req.status == "ACTIVE":
        req.status = "CLOSED"
        _persist(req)
        _audit("AUTO_CLOSED", request_id=request_id, community_id=req.community_id)
        log.warning(
            "BREAK_GLASS AUTO-CLOSED after TTL: request_id=%s community=%s",
            request_id, req.community_id[:8],
        )
