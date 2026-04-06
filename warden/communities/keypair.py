"""
warden/communities/keypair.py
──────────────────────────────
Community cryptographic identity: per-community Ed25519 + X25519 key pair
with kid (key ID) versioning for Root Key Rollover.

Key purposes
────────────
  Ed25519  Signing key — signs community manifests, member certificates,
                          and Bridge proposals (Non-repudiation, Rule 1).
           Public key is the community's public identity (shared with peers).

  X25519   Encryption key — derives Clearance Level Keys via HKDF.
           Private key never transmitted; only public key shared in handshake.

  kid      Version string: "v1", "v2", … — incremented on each Root Key Rollover.
           Stored in every encrypted Entity envelope so the correct archive
           key can be selected during CEK re-wrapping.

Storage
───────
  Private keys are Fernet-encrypted under COMMUNITY_VAULT_KEY (env var,
  falls back to VAULT_MASTER_KEY used by the masking engine).  The ciphertext
  is what gets stored in the community_key_archive Postgres table.

  Public keys are stored in plain Base64 — they are meant to be shared.

BYOK (MCP tier)
───────────────
  When BYOK_MODE=true the private key is never held by Warden at all.
  wrap_cek() / unwrap_cek() delegate to an external Vault Transit API.
  See key_archive.py for BYOK interface.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger("warden.communities.keypair")

# ── Vault key for wrapping community private keys ─────────────────────────────

def _get_vault_fernet() -> Fernet:
    """
    Return a Fernet instance for wrapping community private keys.

    Resolution order:
      1. COMMUNITY_VAULT_KEY  (base64url-encoded 32-byte key)
      2. VAULT_MASTER_KEY     (same format, shared with masking engine)
      3. Auto-generate ephemeral key (dev/test only — keys lost on restart)
    """
    raw = os.getenv("COMMUNITY_VAULT_KEY") or os.getenv("VAULT_MASTER_KEY")
    if raw:
        key = raw.encode() if isinstance(raw, str) else raw
    else:
        log.warning(
            "COMMUNITY_VAULT_KEY not set — generating ephemeral key. "
            "Community private keys will be lost on restart. "
            "Set COMMUNITY_VAULT_KEY in production."
        )
        key = Fernet.generate_key()
    return Fernet(key)


# ── CommunityKeypair dataclass ────────────────────────────────────────────────

class CommunityKeypair:
    """
    Holds one versioned key pair for a community.

    Attributes
    ──────────
    kid               Key ID: "v1", "v2", …
    ed25519_pub_b64   Base64url public signing key (sharable)
    x25519_pub_b64    Base64url public encryption key (sharable)
    _ed_priv_enc      Fernet ciphertext of Ed25519 private key (store in DB)
    _x_priv_enc       Fernet ciphertext of X25519 private key (store in DB)
    """

    __slots__ = (
        "kid",
        "community_id",
        "ed25519_pub_b64",
        "x25519_pub_b64",
        "_ed_priv_enc",
        "_x_priv_enc",
    )

    def __init__(
        self,
        kid:            str,
        community_id:   str,
        ed25519_pub_b64: str,
        x25519_pub_b64:  str,
        ed_priv_enc:    bytes,
        x_priv_enc:     bytes,
    ) -> None:
        self.kid             = kid
        self.community_id    = community_id
        self.ed25519_pub_b64 = ed25519_pub_b64
        self.x25519_pub_b64  = x25519_pub_b64
        self._ed_priv_enc    = ed_priv_enc
        self._x_priv_enc     = x_priv_enc

    # ── Serialization for DB storage ──────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "kid":             self.kid,
            "community_id":    self.community_id,
            "ed25519_pub_b64": self.ed25519_pub_b64,
            "x25519_pub_b64":  self.x25519_pub_b64,
            "ed_priv_enc":     base64.b64encode(self._ed_priv_enc).decode(),
            "x_priv_enc":      base64.b64encode(self._x_priv_enc).decode(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> CommunityKeypair:
        return cls(
            kid             = d["kid"],
            community_id    = d["community_id"],
            ed25519_pub_b64 = d["ed25519_pub_b64"],
            x25519_pub_b64  = d["x25519_pub_b64"],
            ed_priv_enc     = base64.b64decode(d["ed_priv_enc"]),
            x_priv_enc      = base64.b64decode(d["x_priv_enc"]),
        )

    # ── Private key accessors (decrypt on demand) ─────────────────────────────

    def ed25519_private_key(self) -> Ed25519PrivateKey:
        """Decrypt and return the Ed25519 private key (never cache the result)."""
        raw = _get_vault_fernet().decrypt(self._ed_priv_enc)
        return Ed25519PrivateKey.from_private_bytes(raw)

    def x25519_private_key(self) -> X25519PrivateKey:
        """Decrypt and return the X25519 private key (never cache the result)."""
        raw = _get_vault_fernet().decrypt(self._x_priv_enc)
        return X25519PrivateKey.from_private_bytes(raw)

    # ── Signing ───────────────────────────────────────────────────────────────

    def sign(self, data: bytes) -> bytes:
        """Sign *data* with the community Ed25519 private key. Returns 64-byte signature."""
        return self.ed25519_private_key().sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify *signature* over *data* using the community Ed25519 public key."""
        try:
            pub = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(self.ed25519_pub_b64)
            )
            pub.verify(signature, data)
            return True
        except Exception:
            return False

    # ── Clearance Level Key derivation ────────────────────────────────────────

    def derive_clearance_key(self, level: str) -> bytes:
        """
        Derive a 32-byte AES key for *level* (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED)
        using HKDF-SHA256 keyed from the X25519 private key bytes.

        The `info` tag includes community_id + kid + level so the same private key
        bytes can never produce the same derived key across different communities,
        key versions, or clearance levels (Key Separation).

        Crucially: higher-clearance members hold the private key and CAN derive
        lower-level keys (downward derivation), but lower-clearance members
        cannot derive upward — they simply are never given the private key bytes.
        """
        x_priv_raw = _get_vault_fernet().decrypt(self._x_priv_enc)
        info = f"warden:community:{self.community_id}:{self.kid}:clearance:{level}".encode()
        hkdf = HKDF(
            algorithm = SHA256(),
            length    = 32,
            salt      = None,
            info      = info,
        )
        return hkdf.derive(x_priv_raw)

    # ── Safety number (for out-of-band verification) ──────────────────────────

    def safety_number(self) -> str:
        """
        First 20 hex chars of SHA-256(ed25519_pub | x25519_pub).
        Displayed in Hub UI for admins to verify community identity out-of-band.
        """
        combined = base64.b64decode(self.ed25519_pub_b64) + \
                   base64.b64decode(self.x25519_pub_b64)
        return hashlib.sha256(combined).hexdigest()[:20]


# ── Factory ───────────────────────────────────────────────────────────────────

def generate_community_keypair(community_id: str, kid: str = "v1") -> CommunityKeypair:
    """
    Generate a fresh Ed25519 + X25519 keypair for *community_id*.

    Both private keys are immediately encrypted with the vault Fernet key.
    The raw private key bytes exist in memory only for the duration of this call.
    """
    f = _get_vault_fernet()

    # Ed25519 signing key
    ed_priv  = Ed25519PrivateKey.generate()
    ed_pub   = ed_priv.public_key()
    ed_priv_raw = ed_priv.private_bytes(
        encoding = serialization.Encoding.Raw,
        format   = serialization.PrivateFormat.Raw,
        encryption_algorithm = serialization.NoEncryption(),
    )
    ed_pub_raw = ed_pub.public_bytes(
        encoding = serialization.Encoding.Raw,
        format   = serialization.PublicFormat.Raw,
    )

    # X25519 encryption key
    x_priv  = X25519PrivateKey.generate()
    x_pub   = x_priv.public_key()
    x_priv_raw = x_priv.private_bytes(
        encoding = serialization.Encoding.Raw,
        format   = serialization.PrivateFormat.Raw,
        encryption_algorithm = serialization.NoEncryption(),
    )
    x_pub_raw = x_pub.public_bytes(
        encoding = serialization.Encoding.Raw,
        format   = serialization.PublicFormat.Raw,
    )

    return CommunityKeypair(
        kid             = kid,
        community_id    = community_id,
        ed25519_pub_b64 = base64.b64encode(ed_pub_raw).decode(),
        x25519_pub_b64  = base64.b64encode(x_pub_raw).decode(),
        ed_priv_enc     = f.encrypt(ed_priv_raw),
        x_priv_enc      = f.encrypt(x_priv_raw),
    )
