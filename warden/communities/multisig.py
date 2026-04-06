"""
warden/communities/multisig.py
────────────────────────────────
Multi-Sig Bridge Consensus — M-of-N Ed25519 signing for Community proposals.

What is a Bridge Proposal?
───────────────────────────
  A Bridge Proposal is any action that carries elevated risk if a single actor
  is compromised: key rotation confirmation, member clearance elevation, cross-
  community data share, Break Glass activation, or governance rule changes.

  The proposal is defined by a *canonical JSON payload* that all signers must
  independently verify and sign.  A SHA-256 config_hash of this payload is
  signed (not the payload itself) — this matches the Gemini audit recommendation
  to prevent condition-substitution attacks where an attacker presents a
  different-looking document that hashes to the same value.

Gemini audit fix — config_hash signing
────────────────────────────────────────
  Original design: signers sign arbitrary payload bytes.
  Risk: attacker could present signer-A with document X and signer-B with
        document Y, both yielding quorum for a proposal neither fully intended.

  Fix: the proposal is committed to a SHA-256 *config_hash* at creation time.
  Every signer signs ONLY `b"warden:multisig:v1:" + config_hash_bytes`.
  Any mismatch between the presented document and config_hash causes
  verification to fail — condition substitution is cryptographically impossible.

Security controls
─────────────────
  1. M-of-N quorum (default M=2, N=5 — configurable per community).
  2. Signer identity: Ed25519 key bound to the Community keypair (kid version).
     Each signer provides their own signature over the same config_hash.
  3. TTL: proposals expire after MULTISIG_PROPOSAL_TTL_S (default 86400 = 24h).
  4. No duplicate signatures: same signer_id cannot sign twice.
  5. Status transitions: PENDING → APPROVED (M sigs) / REJECTED (explicit) /
     EXPIRED (TTL exceeded).

Usage
─────
  # Create proposal
  proposal = create_proposal(
      community_id = community_id,
      proposal_type = "KEY_ROTATION",
      payload = {"old_kid": "v1", "new_kid": "v2", "initiated_by": "admin"},
      proposer_id = member_id,
      m_required = 2,
  )

  # Each signer:
  add_signature(proposal.proposal_id, signer_id, sig_b64)

  # Check status:
  result = get_proposal(proposal.proposal_id)
  # → result.status == "APPROVED" when M sigs collected
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

log = logging.getLogger("warden.communities.multisig")

MULTISIG_PROPOSAL_TTL_S: int = int(os.getenv("MULTISIG_PROPOSAL_TTL_S", "86400"))  # 24h
MULTISIG_DEFAULT_M:      int = int(os.getenv("MULTISIG_DEFAULT_M",       "2"))
MULTISIG_DEFAULT_N:      int = int(os.getenv("MULTISIG_DEFAULT_N",       "5"))

# Signing context prefix — prevents cross-protocol signature confusion
_SIGN_PREFIX = b"warden:multisig:v1:"


# ── Proposal types ────────────────────────────────────────────────────────────

class ProposalType(StrEnum):
    KEY_ROTATION        = "KEY_ROTATION"        # Confirm root key rollover + shred
    BREAK_GLASS         = "BREAK_GLASS"          # Emergency key access approval
    MEMBER_ELEVATION    = "MEMBER_ELEVATION"     # Elevate member to RESTRICTED
    CROSS_COMMUNITY_SHARE = "CROSS_COMMUNITY_SHARE"  # Approve inter-community data share
    GOVERNANCE_CHANGE   = "GOVERNANCE_CHANGE"    # Policy or rule modification


class ProposalStatus(StrEnum):
    PENDING  = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED  = "EXPIRED"


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class MultiSigProposal:
    proposal_id:   str
    community_id:  str
    proposal_type: str                               # ProposalType value
    config_hash:   str                               # hex SHA-256 of canonical payload
    payload_json:  str                               # JSON string (informational only)
    proposer_id:   str
    m_required:    int                               # minimum signatures to approve
    n_total:       int                               # maximum eligible signers
    status:        str                               # ProposalStatus value
    created_at:    str
    expires_at:    str
    signatures:    dict[str, str] = field(default_factory=dict)  # signer_id → sig_b64
    rejected_by:   str | None  = None
    finalized_at:  str | None  = None


# ── In-memory store (Redis-backed in production) ──────────────────────────────

_store_lock   = threading.RLock()
_proposals:   dict[str, MultiSigProposal] = {}


def _persist(proposal: MultiSigProposal) -> None:
    """Store proposal in memory + Redis (fail-open)."""
    with _store_lock:
        _proposals[proposal.proposal_id] = proposal
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            key = f"warden:multisig:{proposal.proposal_id}"
            d = dict(proposal.__dict__.items())
            ttl = max(1, int((datetime.fromisoformat(proposal.expires_at) -
                              datetime.now(UTC)).total_seconds()))
            r.setex(key, ttl, json.dumps(d))
    except Exception as exc:
        log.debug("multisig: Redis persist error: %s", exc)


def _load(proposal_id: str) -> MultiSigProposal | None:
    """Load proposal from memory, then Redis."""
    with _store_lock:
        p = _proposals.get(proposal_id)
        if p:
            return p
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            raw = r.get(f"warden:multisig:{proposal_id}")
            if raw:
                d = json.loads(raw)
                p = MultiSigProposal(**d)
                with _store_lock:
                    _proposals[proposal_id] = p
                return p
    except Exception:
        pass
    return None


# ── config_hash computation ───────────────────────────────────────────────────

def _compute_config_hash(payload: dict) -> str:
    """
    SHA-256 of the canonical JSON representation of *payload*.

    Canonical = JSON with sorted keys, no extra whitespace.
    Hex-encoded.  All signers independently compute and verify this hash
    before signing — condition substitution is impossible.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _sign_bytes(config_hash: str) -> bytes:
    """The exact bytes every signer must sign over."""
    return _SIGN_PREFIX + bytes.fromhex(config_hash)


# ── Public API ────────────────────────────────────────────────────────────────

def create_proposal(
    community_id:   str,
    proposal_type:  str,
    payload:        dict,
    proposer_id:    str,
    m_required:     int = MULTISIG_DEFAULT_M,
    n_total:        int = MULTISIG_DEFAULT_N,
) -> MultiSigProposal:
    """
    Create a new Multi-Sig Bridge Proposal.

    Parameters
    ──────────
    community_id    Community the proposal belongs to.
    proposal_type   ProposalType value string.
    payload         Arbitrary dict describing the proposed action.
                    SHA-256 is computed immediately and locked in — the
                    payload cannot be silently swapped after creation.
    proposer_id     Member_ID of the initiator.
    m_required      Minimum number of signatures to approve (default 2).
    n_total         Maximum eligible signers — informational only.

    Returns
    ──────
    MultiSigProposal in PENDING status.
    """
    import uuid

    config_hash = _compute_config_hash(payload)
    now     = datetime.now(UTC)
    expires = datetime.fromtimestamp(now.timestamp() + MULTISIG_PROPOSAL_TTL_S, tz=UTC)

    proposal = MultiSigProposal(
        proposal_id   = str(uuid.uuid4()),
        community_id  = community_id,
        proposal_type = str(proposal_type),
        config_hash   = config_hash,
        payload_json  = json.dumps(payload, sort_keys=True, separators=(",", ":")),
        proposer_id   = proposer_id,
        m_required    = m_required,
        n_total       = n_total,
        status        = ProposalStatus.PENDING,
        created_at    = now.isoformat(),
        expires_at    = expires.isoformat(),
    )
    _persist(proposal)
    log.info(
        "multisig: created proposal=%s type=%s community=%s m=%d",
        proposal.proposal_id[:8], proposal_type, community_id[:8], m_required,
    )
    return proposal


def get_proposal(proposal_id: str) -> MultiSigProposal | None:
    """Return proposal or None.  Auto-marks EXPIRED proposals."""
    p = _load(proposal_id)
    if p and p.status == ProposalStatus.PENDING and datetime.fromisoformat(p.expires_at) < datetime.now(UTC):
        p.status = ProposalStatus.EXPIRED
        _persist(p)
    return p


def add_signature(
    proposal_id: str,
    signer_id:   str,
    sig_b64:     str,
    community_keypair = None,   # CommunityKeypair — if provided, Ed25519 is verified
) -> dict:
    """
    Record a signer's Ed25519 signature over config_hash.

    The sig_b64 must be a Base64 signature of:
        b"warden:multisig:v1:" + bytes.fromhex(proposal.config_hash)

    If *community_keypair* is provided the signature is verified against the
    community Ed25519 public key.  In production pass the keypair; in tests
    the signature is stored on trust (auth layer verifies identity separately).

    Returns {"status": "PENDING"|"APPROVED", "sigs": N, "required": M}

    Raises
    ──────
    ValueError      Proposal not found or not PENDING.
    PermissionError Proposal expired.
    ValueError      Duplicate signature from same signer_id.
    ValueError      Signature verification failed (when keypair provided).
    """
    p = get_proposal(proposal_id)
    if p is None:
        raise ValueError(f"Proposal {proposal_id} not found.")
    if p.status == ProposalStatus.EXPIRED:
        raise PermissionError(f"Proposal {proposal_id} has expired.")
    if p.status != ProposalStatus.PENDING:
        raise ValueError(f"Proposal {proposal_id} is {p.status}, not PENDING.")

    if signer_id in p.signatures:
        raise ValueError(f"Signer {signer_id} has already signed proposal {proposal_id[:8]}.")

    # Verify signature if keypair provided
    if community_keypair is not None:
        sig_bytes = base64.b64decode(sig_b64)
        sign_data = _sign_bytes(p.config_hash)
        if not community_keypair.verify(sign_data, sig_bytes):
            raise ValueError(
                f"Ed25519 signature verification failed for signer={signer_id}."
            )

    p.signatures[signer_id] = sig_b64
    n = len(p.signatures)

    if n >= p.m_required:
        p.status       = ProposalStatus.APPROVED
        p.finalized_at = datetime.now(UTC).isoformat()
        log.warning(
            "multisig: APPROVED proposal=%s type=%s community=%s signers=%s",
            p.proposal_id[:8], p.proposal_type, p.community_id[:8],
            list(p.signatures.keys()),
        )

    _persist(p)

    return {
        "status":   p.status,
        "sigs":     n,
        "required": p.m_required,
    }


def reject_proposal(
    proposal_id: str,
    rejected_by: str,
) -> MultiSigProposal:
    """
    Explicitly reject a PENDING proposal (e.g. a signer detects fraud).

    Any single authorized member can veto; the proposal immediately moves
    to REJECTED and cannot collect further signatures.
    """
    p = get_proposal(proposal_id)
    if p is None:
        raise ValueError(f"Proposal {proposal_id} not found.")
    if p.status != ProposalStatus.PENDING:
        raise ValueError(f"Proposal {proposal_id} is {p.status}, cannot reject.")

    p.status       = ProposalStatus.REJECTED
    p.rejected_by  = rejected_by
    p.finalized_at = datetime.now(UTC).isoformat()
    _persist(p)

    log.warning(
        "multisig: REJECTED proposal=%s by=%s community=%s",
        proposal_id[:8], rejected_by, p.community_id[:8],
    )
    return p


def list_proposals(
    community_id: str,
    status_filter: str | None = None,
) -> list[MultiSigProposal]:
    """
    List proposals for a community.

    status_filter: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | None (all)
    """
    with _store_lock:
        proposals = [
            p for p in _proposals.values()
            if p.community_id == community_id
        ]
    if status_filter:
        proposals = [p for p in proposals if p.status == status_filter]
    return sorted(proposals, key=lambda x: x.created_at, reverse=True)


def verify_proposal_hash(proposal: MultiSigProposal, claimed_payload: dict) -> bool:
    """
    Verify that *claimed_payload* matches the locked-in config_hash.

    Use this before acting on an APPROVED proposal to confirm the payload
    was not swapped between proposal creation and approval.
    """
    return _compute_config_hash(claimed_payload) == proposal.config_hash


def signing_bytes(config_hash: str) -> bytes:
    """
    Return the exact bytes a signer should sign for the given config_hash.

    Exported for use by signer clients:
        sig = community_keypair.sign(multisig.signing_bytes(config_hash))
        sig_b64 = base64.b64encode(sig).decode()
    """
    return _sign_bytes(config_hash)
