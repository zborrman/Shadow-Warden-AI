"""
warden/communities/clearance.py
────────────────────────────────
Security Clearance Levels — cryptographic access tier enforcement.

Levels (ascending privilege)
─────────────────────────────
  PUBLIC        General-purpose content. All members can read/write.
  INTERNAL      Operational content. Members with INTERNAL+ clearance.
  CONFIDENTIAL  Sensitive business data. CONFIDENTIAL+ clearance required.
  RESTRICTED    Board/executive only. Explicit RESTRICTED grant required.

How it works
────────────
  Each level has its own 32-byte AES-256-GCM key derived from the community
  X25519 private key + kid + level label via HKDF-SHA256.

  Content Encryption Key (CEK) model:
    1. Sender randomly generates a 32-byte CEK for the entity.
    2. CEK is wrapped (encrypted) with the Clearance Level Key for the entity's level.
    3. Encrypted payload = AES-256-GCM(CEK, plaintext).
    4. Stored: {kid, clearance, cek_wrapped_b64, payload_b64, nonce_b64, sig_b64}

  On read:
    1. Unwrap CEK using Clearance Level Key of the entity's level.
    2. Decrypt payload using CEK.
    3. Verify Ed25519 signature (Non-repudiation — Rule 1).

  Member downgrade (Gemini audit recommendation):
    When a member is downgraded (e.g. RESTRICTED → INTERNAL), the community's
    CONFIDENTIAL and RESTRICTED Clearance Level Keys must be rotated
    (new kid generated) to prevent the demoted member from using cached keys
    to decrypt future messages.  force_rotation_on_downgrade() triggers
    the Root Key Rollover flow from key_archive + rotation modules.

Envelope format
───────────────
  {
    "entity_id":      "<Snowflake int as str>",
    "community_id":   "<UUIDv7>",
    "kid":            "v1",
    "clearance":      "CONFIDENTIAL",
    "cek_wrapped_b64":"<base64 AES-256-GCM(CEK, level_key)>",
    "nonce_b64":      "<base64 12-byte GCM nonce for CEK wrap>",
    "payload_b64":    "<base64 AES-256-GCM(plaintext, CEK)>",
    "pay_nonce_b64":  "<base64 12-byte GCM nonce for payload>",
    "sender_mid":     "<Member_ID>",
    "sig_b64":        "<base64 Ed25519 sig over canonical payload>",
  }
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("warden.communities.clearance")


# ── Level enum ────────────────────────────────────────────────────────────────

class ClearanceLevel(IntEnum):
    PUBLIC       = 0
    INTERNAL     = 1
    CONFIDENTIAL = 2
    RESTRICTED   = 3

    @classmethod
    def from_str(cls, s: str) -> "ClearanceLevel":
        return cls[s.upper()]

    def can_access(self, required: "ClearanceLevel") -> bool:
        """True if this level satisfies *required* (higher int = higher privilege)."""
        return self >= required


# ── CEK operations ────────────────────────────────────────────────────────────

def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def wrap_cek(cek: bytes, level_key: bytes) -> tuple[bytes, bytes]:
    """
    Wrap (encrypt) a 32-byte CEK using *level_key* (AES-256-GCM).

    Returns (nonce, ciphertext).  Both must be stored in the entity envelope.
    """
    nonce = _random_bytes(12)
    ct    = AESGCM(level_key).encrypt(nonce, cek, None)
    return nonce, ct


def unwrap_cek(cek_ct: bytes, nonce: bytes, level_key: bytes) -> bytes:
    """
    Unwrap (decrypt) a CEK using *level_key*.

    Raises cryptography.exceptions.InvalidTag if the key is wrong or data tampered.
    """
    return AESGCM(level_key).decrypt(nonce, cek_ct, None)


def encrypt_payload(plaintext: bytes, cek: bytes) -> tuple[bytes, bytes]:
    """Encrypt *plaintext* under *cek* (AES-256-GCM). Returns (nonce, ciphertext)."""
    nonce = _random_bytes(12)
    ct    = AESGCM(cek).encrypt(nonce, plaintext, None)
    return nonce, ct


def decrypt_payload(ciphertext: bytes, nonce: bytes, cek: bytes) -> bytes:
    """Decrypt *ciphertext* under *cek* (AES-256-GCM)."""
    return AESGCM(cek).decrypt(nonce, ciphertext, None)


# ── Envelope builder / parser ─────────────────────────────────────────────────

@dataclass
class ClearanceEnvelope:
    entity_id:       str
    community_id:    str
    kid:             str
    clearance:       str                   # ClearanceLevel name
    cek_wrapped_b64: str
    nonce_b64:       str                   # CEK wrap nonce
    payload_b64:     str
    pay_nonce_b64:   str                   # payload nonce
    sender_mid:      str
    sig_b64:         str

    def to_json(self) -> str:
        return json.dumps(self.__dict__, separators=(",", ":"))

    @classmethod
    def from_json(cls, s: str) -> "ClearanceEnvelope":
        return cls(**json.loads(s))

    def canonical_bytes(self) -> bytes:
        """
        Canonical byte representation that is signed/verified.
        Excludes sig_b64 itself — everything else is covered.
        """
        d = {k: v for k, v in self.__dict__.items() if k != "sig_b64"}
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def create_envelope(
    entity_id:    str,
    community_id: str,
    plaintext:    bytes,
    clearance:    ClearanceLevel,
    keypair,                       # CommunityKeypair
    sender_mid:   str,
) -> ClearanceEnvelope:
    """
    Encrypt *plaintext* at *clearance* level and sign with *keypair*.

    Steps:
      1. Derive Clearance Level Key from keypair.
      2. Generate random CEK.
      3. Wrap CEK with level key.
      4. Encrypt plaintext with CEK.
      5. Sign canonical envelope bytes with Ed25519.
    """
    level_key       = keypair.derive_clearance_key(clearance.name)
    cek             = _random_bytes(32)
    wrap_nonce, cek_ct = wrap_cek(cek, level_key)
    pay_nonce, payload = encrypt_payload(plaintext, cek)

    env = ClearanceEnvelope(
        entity_id       = entity_id,
        community_id    = community_id,
        kid             = keypair.kid,
        clearance       = clearance.name,
        cek_wrapped_b64 = base64.b64encode(cek_ct).decode(),
        nonce_b64       = base64.b64encode(wrap_nonce).decode(),
        payload_b64     = base64.b64encode(payload).decode(),
        pay_nonce_b64   = base64.b64encode(pay_nonce).decode(),
        sender_mid      = sender_mid,
        sig_b64         = "",
    )
    sig = keypair.sign(env.canonical_bytes())
    env.sig_b64 = base64.b64encode(sig).decode()
    return env


def open_envelope(
    envelope: ClearanceEnvelope,
    keypair,                        # CommunityKeypair (must match kid)
    member_clearance: ClearanceLevel,
) -> bytes:
    """
    Decrypt and verify an envelope.

    Raises
    ──────
    PermissionError   member_clearance is below envelope.clearance
    ValueError        signature invalid or decryption failed
    """
    required = ClearanceLevel.from_str(envelope.clearance)
    if not member_clearance.can_access(required):
        raise PermissionError(
            f"Member clearance {member_clearance.name} cannot access "
            f"{envelope.clearance} content."
        )

    # Verify signature (Non-repudiation)
    sig = base64.b64decode(envelope.sig_b64)
    if not keypair.verify(envelope.canonical_bytes(), sig):
        raise ValueError("Envelope signature verification failed — possible tampering.")

    # Unwrap CEK
    level_key   = keypair.derive_clearance_key(envelope.clearance)
    cek_ct      = base64.b64decode(envelope.cek_wrapped_b64)
    wrap_nonce  = base64.b64decode(envelope.nonce_b64)
    try:
        cek = unwrap_cek(cek_ct, wrap_nonce, level_key)
    except Exception as exc:
        raise ValueError(f"CEK unwrap failed — wrong key or corrupted envelope: {exc}") from exc

    # Decrypt payload
    payload    = base64.b64decode(envelope.payload_b64)
    pay_nonce  = base64.b64decode(envelope.pay_nonce_b64)
    try:
        return decrypt_payload(payload, pay_nonce, cek)
    except Exception as exc:
        raise ValueError(f"Payload decryption failed: {exc}") from exc


# ── Re-wrap CEK for Root Key Rollover ─────────────────────────────────────────

def rewrap_envelope_cek(
    envelope:    ClearanceEnvelope,
    old_keypair,                    # CommunityKeypair with old kid (ROTATION_ONLY)
    new_keypair,                    # CommunityKeypair with new kid (ACTIVE)
) -> ClearanceEnvelope:
    """
    Re-wrap the CEK from old_keypair's level key → new_keypair's level key.

    The payload bytes are NOT touched — only cek_wrapped_b64, nonce_b64, and kid
    are updated.  The envelope signature is re-issued under new_keypair.

    This is the atomic unit of work performed by the ARQ rotation worker.
    """
    # Unwrap CEK using old key
    old_level_key  = old_keypair.derive_clearance_key(envelope.clearance)
    cek_ct         = base64.b64decode(envelope.cek_wrapped_b64)
    wrap_nonce     = base64.b64decode(envelope.nonce_b64)
    cek            = unwrap_cek(cek_ct, wrap_nonce, old_level_key)

    # Re-wrap with new key
    new_level_key              = new_keypair.derive_clearance_key(envelope.clearance)
    new_wrap_nonce, new_cek_ct = wrap_cek(cek, new_level_key)

    updated = ClearanceEnvelope(
        entity_id       = envelope.entity_id,
        community_id    = envelope.community_id,
        kid             = new_keypair.kid,
        clearance       = envelope.clearance,
        cek_wrapped_b64 = base64.b64encode(new_cek_ct).decode(),
        nonce_b64       = base64.b64encode(new_wrap_nonce).decode(),
        payload_b64     = envelope.payload_b64,      # unchanged
        pay_nonce_b64   = envelope.pay_nonce_b64,    # unchanged
        sender_mid      = envelope.sender_mid,
        sig_b64         = "",
    )
    sig = new_keypair.sign(updated.canonical_bytes())
    updated.sig_b64 = base64.b64encode(sig).decode()
    return updated


# ── Member downgrade — force rotation check ───────────────────────────────────

def check_downgrade_requires_rotation(
    old_clearance: ClearanceLevel,
    new_clearance: ClearanceLevel,
) -> bool:
    """
    Return True if downgrading from *old_clearance* to *new_clearance*
    requires a Root Key Rollover.

    Rationale (Gemini audit recommendation):
      A downgraded member holds cached Clearance Level Keys for their old level.
      Since those keys are derived from the community Root Key, they remain valid
      until the Root Key is rotated (new kid generated).  We require rotation
      whenever a member loses access to CONFIDENTIAL or RESTRICTED level.
    """
    sensitive_levels = {ClearanceLevel.CONFIDENTIAL, ClearanceLevel.RESTRICTED}
    lost_levels = {l for l in sensitive_levels if old_clearance >= l > new_clearance}
    return bool(lost_levels)
