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
           Hybrid PQC keys use suffix "-hybrid" (e.g. "v2-hybrid").
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

Post-Quantum (Enterprise tier, v4.1+)
──────────────────────────────────────
  When pqc=True, generate_community_keypair() adds ML-DSA-65 (FIPS 204)
  alongside Ed25519 and ML-KEM-768 (FIPS 203) alongside X25519.
  kid is set to "<base>-hybrid" (e.g. "v2-hybrid").
  Requires liboqs-python; raises PQCUnavailableError if not installed.
  Use upgrade_to_hybrid() to promote an existing v1 keypair.
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

from warden.crypto.pqc import (
    HybridKEM,
    HybridKEMKeypair,
    HybridKeypair,
    HybridSigner,
    PQCUnavailableError,
    hybrid_safety_number,
    is_pqc_available,
)

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
    kid               Key ID: "v1", "v2", … or "v2-hybrid" for PQC
    ed25519_pub_b64   Base64 public signing key (sharable)
    x25519_pub_b64    Base64 public encryption key (sharable)
    _ed_priv_enc      Fernet ciphertext of Ed25519 private key (store in DB)
    _x_priv_enc       Fernet ciphertext of X25519 private key (store in DB)
    mldsa_pub_b64     Base64 ML-DSA-65 public key (hybrid only, else None)
    mlkem_pub_b64     Base64 ML-KEM-768 public key (hybrid only, else None)
    _mldsa_priv_enc   Fernet ciphertext of ML-DSA-65 private key (hybrid only)
    _mlkem_priv_enc   Fernet ciphertext of ML-KEM-768 private key (hybrid only)
    """

    __slots__ = (
        "kid",
        "community_id",
        "ed25519_pub_b64",
        "x25519_pub_b64",
        "_ed_priv_enc",
        "_x_priv_enc",
        "mldsa_pub_b64",
        "mlkem_pub_b64",
        "_mldsa_priv_enc",
        "_mlkem_priv_enc",
    )

    def __init__(
        self,
        kid:              str,
        community_id:     str,
        ed25519_pub_b64:  str,
        x25519_pub_b64:   str,
        ed_priv_enc:      bytes,
        x_priv_enc:       bytes,
        mldsa_pub_b64:    str | None = None,
        mlkem_pub_b64:    str | None = None,
        mldsa_priv_enc:   bytes | None = None,
        mlkem_priv_enc:   bytes | None = None,
    ) -> None:
        self.kid              = kid
        self.community_id     = community_id
        self.ed25519_pub_b64  = ed25519_pub_b64
        self.x25519_pub_b64   = x25519_pub_b64
        self._ed_priv_enc     = ed_priv_enc
        self._x_priv_enc      = x_priv_enc
        self.mldsa_pub_b64    = mldsa_pub_b64
        self.mlkem_pub_b64    = mlkem_pub_b64
        self._mldsa_priv_enc  = mldsa_priv_enc
        self._mlkem_priv_enc  = mlkem_priv_enc

    @property
    def is_hybrid(self) -> bool:
        """True when this keypair carries PQC keys (kid ends with '-hybrid')."""
        return self.kid.endswith("-hybrid") and self.mldsa_pub_b64 is not None

    # ── Serialization for DB storage ──────────────────────────────────────────

    def to_dict(self) -> dict:
        d: dict = {
            "kid":             self.kid,
            "community_id":    self.community_id,
            "ed25519_pub_b64": self.ed25519_pub_b64,
            "x25519_pub_b64":  self.x25519_pub_b64,
            "ed_priv_enc":     base64.b64encode(self._ed_priv_enc).decode(),
            "x_priv_enc":      base64.b64encode(self._x_priv_enc).decode(),
        }
        if self.is_hybrid:
            d["mldsa_pub_b64"]   = self.mldsa_pub_b64
            d["mlkem_pub_b64"]   = self.mlkem_pub_b64
            d["mldsa_priv_enc"]  = base64.b64encode(self._mldsa_priv_enc).decode()  # type: ignore[arg-type]
            d["mlkem_priv_enc"]  = base64.b64encode(self._mlkem_priv_enc).decode()  # type: ignore[arg-type]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> CommunityKeypair:
        return cls(
            kid             = d["kid"],
            community_id    = d["community_id"],
            ed25519_pub_b64 = d["ed25519_pub_b64"],
            x25519_pub_b64  = d["x25519_pub_b64"],
            ed_priv_enc     = base64.b64decode(d["ed_priv_enc"]),
            x_priv_enc      = base64.b64decode(d["x_priv_enc"]),
            mldsa_pub_b64   = d.get("mldsa_pub_b64"),
            mlkem_pub_b64   = d.get("mlkem_pub_b64"),
            mldsa_priv_enc  = base64.b64decode(d["mldsa_priv_enc"]) if "mldsa_priv_enc" in d else None,
            mlkem_priv_enc  = base64.b64decode(d["mlkem_priv_enc"]) if "mlkem_priv_enc" in d else None,
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

    # ── Hybrid PQC signing (Enterprise tier) ─────────────────────────────────

    def hybrid_sign(self, data: bytes) -> bytes:
        """
        Produce a hybrid Ed25519+ML-DSA-65 signature over *data*.

        Returns packed HybridSignature bytes (64 + 3309 = 3373 bytes).
        Raises PQCUnavailableError when liboqs is not installed.
        Raises RuntimeError when called on a non-hybrid keypair.
        """
        if not self.is_hybrid:
            raise RuntimeError("hybrid_sign() requires a '-hybrid' keypair. Use upgrade_to_hybrid() first.")
        f = _get_vault_fernet()
        ed_priv_raw    = f.decrypt(self._ed_priv_enc)
        mldsa_priv_raw = f.decrypt(self._mldsa_priv_enc)  # type: ignore[arg-type]
        kp = HybridKeypair(
            ed25519_priv_raw = ed_priv_raw,
            ed25519_pub_raw  = base64.b64decode(self.ed25519_pub_b64),
            mldsa_priv_raw   = mldsa_priv_raw,
            mldsa_pub_raw    = base64.b64decode(self.mldsa_pub_b64),  # type: ignore[arg-type]
        )
        sig = HybridSigner.sign(data, kp)
        return sig.pack()

    def hybrid_verify(self, data: bytes, sig_blob: bytes) -> bool:
        """
        Verify a hybrid Ed25519+ML-DSA-65 signature.

        Returns True only when BOTH classical and PQC signatures are valid.
        Falls back to Ed25519-only verification when liboqs is unavailable.
        Returns False (not raises) on any verification failure.
        """
        if not self.is_hybrid:
            return self.verify(data, sig_blob[:64])
        try:
            from warden.crypto.pqc import HybridSignature
            hs = HybridSignature.unpack(sig_blob)
            return HybridSigner.verify(
                data,
                hs,
                base64.b64decode(self.ed25519_pub_b64),
                base64.b64decode(self.mldsa_pub_b64),  # type: ignore[arg-type]
            )
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
        First 20 hex chars of SHA-256 over all public keys.
        Classical-only: SHA-256(ed25519_pub | x25519_pub).
        Hybrid: delegates to hybrid_safety_number() which covers all 4 keys.
        Displayed in Hub UI for admins to verify community identity out-of-band.
        """
        if self.is_hybrid:
            return hybrid_safety_number(
                base64.b64decode(self.ed25519_pub_b64),
                base64.b64decode(self.x25519_pub_b64),
                base64.b64decode(self.mldsa_pub_b64),   # type: ignore[arg-type]
                base64.b64decode(self.mlkem_pub_b64),   # type: ignore[arg-type]
            )
        combined = base64.b64decode(self.ed25519_pub_b64) + \
                   base64.b64decode(self.x25519_pub_b64)
        return hashlib.sha256(combined).hexdigest()[:20]


# ── Factory ───────────────────────────────────────────────────────────────────

def generate_community_keypair(
    community_id: str,
    kid:          str  = "v1",
    pqc:          bool = False,
) -> CommunityKeypair:
    """
    Generate a fresh Ed25519 + X25519 keypair for *community_id*.

    When *pqc=True*, also generates ML-DSA-65 + ML-KEM-768 keys and
    appends "-hybrid" to *kid* (e.g. "v1" → "v1-hybrid").
    Raises PQCUnavailableError if liboqs is not installed and pqc=True.

    All private keys are immediately encrypted with the vault Fernet key.
    Raw private key bytes exist in memory only for the duration of this call.
    """
    if pqc and not is_pqc_available():
        raise PQCUnavailableError(
            "liboqs-python is not installed. Cannot generate hybrid PQC keypair."
        )

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

    if not pqc:
        return CommunityKeypair(
            kid             = kid,
            community_id    = community_id,
            ed25519_pub_b64 = base64.b64encode(ed_pub_raw).decode(),
            x25519_pub_b64  = base64.b64encode(x_pub_raw).decode(),
            ed_priv_enc     = f.encrypt(ed_priv_raw),
            x_priv_enc      = f.encrypt(x_priv_raw),
        )

    # PQC hybrid: generate ML-DSA-65 + ML-KEM-768
    hybrid_kid    = kid if kid.endswith("-hybrid") else f"{kid}-hybrid"
    sig_kp: HybridKeypair    = HybridSigner.generate()
    kem_kp: HybridKEMKeypair = HybridKEM.generate()

    return CommunityKeypair(
        kid             = hybrid_kid,
        community_id    = community_id,
        ed25519_pub_b64 = base64.b64encode(ed_pub_raw).decode(),
        x25519_pub_b64  = base64.b64encode(x_pub_raw).decode(),
        ed_priv_enc     = f.encrypt(ed_priv_raw),
        x_priv_enc      = f.encrypt(x_priv_raw),
        mldsa_pub_b64   = base64.b64encode(sig_kp.mldsa_pub_raw).decode(),
        mlkem_pub_b64   = base64.b64encode(kem_kp.mlkem_pub_raw).decode(),
        mldsa_priv_enc  = f.encrypt(sig_kp.mldsa_priv_raw),
        mlkem_priv_enc  = f.encrypt(kem_kp.mlkem_priv_raw),
    )


def upgrade_to_hybrid(kp: CommunityKeypair) -> CommunityKeypair:
    """
    Promote an existing classical keypair to hybrid PQC.

    Generates fresh ML-DSA-65 + ML-KEM-768 keys and returns a new
    CommunityKeypair with the same Ed25519/X25519 keys but the PQC keys
    added and kid updated to "<kid>-hybrid".

    Raises PQCUnavailableError if liboqs is not installed.
    Raises RuntimeError if *kp* is already a hybrid keypair.
    """
    if kp.is_hybrid:
        raise RuntimeError(f"Keypair {kp.kid!r} is already hybrid.")
    if not is_pqc_available():
        raise PQCUnavailableError(
            "liboqs-python is not installed. Cannot upgrade keypair to hybrid PQC."
        )

    f         = _get_vault_fernet()
    sig_kp    = HybridSigner.generate()
    kem_kp    = HybridKEM.generate()
    hybrid_kid = f"{kp.kid}-hybrid"

    return CommunityKeypair(
        kid             = hybrid_kid,
        community_id    = kp.community_id,
        ed25519_pub_b64 = kp.ed25519_pub_b64,
        x25519_pub_b64  = kp.x25519_pub_b64,
        ed_priv_enc     = kp._ed_priv_enc,
        x_priv_enc      = kp._x_priv_enc,
        mldsa_pub_b64   = base64.b64encode(sig_kp.mldsa_pub_raw).decode(),
        mlkem_pub_b64   = base64.b64encode(kem_kp.mlkem_pub_raw).decode(),
        mldsa_priv_enc  = f.encrypt(sig_kp.mldsa_priv_raw),
        mlkem_priv_enc  = f.encrypt(kem_kp.mlkem_priv_raw),
    )
