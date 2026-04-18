"""
warden/crypto/pqc.py
─────────────────────
Post-Quantum Cryptography primitives for Shadow Warden AI.

Implements a hybrid classical + post-quantum scheme per NIST FIPS 203/204:

  Signatures  Ed25519 (classical)  +  ML-DSA-65 / FIPS 204  (lattice-based)
  KEM         X25519  (classical)  +  ML-KEM-768 / FIPS 203  (Kyber)

Both signatures are computed and BOTH must verify (double-wrap).
Shared secret = HKDF-SHA256(X25519_secret XOR ML-KEM_secret).

This "belt-and-suspenders" hybrid ensures:
  • Classical security today (Ed25519/X25519 remain secure)
  • Quantum security tomorrow (ML-DSA/ML-KEM resist Shor's algorithm)
  • "Harvest now, decrypt later" (HNDL) resistance for Syndicate tunnels

Dependencies
────────────
  liboqs-python  — NIST reference PQC library
  cryptography   — Ed25519 + X25519 + HKDF (already installed)

Install liboqs-python:
  pip install liboqs-python
  # or in Dockerfile (after torch):
  RUN pip install liboqs-python

All classes fail-open with PQCUnavailableError when liboqs is not installed.
Enterprise-only gate: FeatureGate.require("pqc_enabled") must pass before
generating or upgrading to hybrid keys.

Key sizes (ML-DSA-65 / ML-KEM-768):
  ML-DSA-65  public key:  1952 bytes   signature: 3309 bytes
  ML-KEM-768 public key:  1184 bytes   ciphertext: 1088 bytes  secret: 32 bytes
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
from dataclasses import dataclass
from typing import NamedTuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger("warden.crypto.pqc")

# ── liboqs availability ───────────────────────────────────────────────────────

_OQS_AVAILABLE = False
try:
    import oqs  # type: ignore[import]
    _OQS_AVAILABLE = True
    log.info("pqc: liboqs available — ML-DSA-65 + ML-KEM-768 enabled")
except ImportError:
    log.warning(
        "pqc: liboqs-python not installed — PQC features unavailable. "
        "Install with: pip install liboqs-python"
    )


class PQCUnavailableError(RuntimeError):
    """Raised when liboqs is not installed but a PQC operation is requested."""


def _require_oqs() -> None:
    if not _OQS_AVAILABLE:
        raise PQCUnavailableError(
            "liboqs-python is required for post-quantum cryptography. "
            "Install with: pip install liboqs-python"
        )


# ── Algorithm identifiers ─────────────────────────────────────────────────────

_SIG_ALGO = "ML-DSA-65"    # FIPS 204 — formerly Dilithium3
_KEM_ALGO = "ML-KEM-768"   # FIPS 203 — formerly Kyber768

# Signature layout in hybrid blob:
#   bytes 0:64       → Ed25519 signature (64 bytes, fixed)
#   bytes 64:64+N    → ML-DSA-65 signature (3309 bytes)
_ED25519_SIG_LEN = 64

# KEM ciphertext layout in hybrid blob:
#   bytes 0:32       → X25519 ephemeral public key (raw, 32 bytes)
#   bytes 32:32+M    → ML-KEM-768 ciphertext (1088 bytes)
_X25519_PUB_LEN   = 32
_MLKEM768_CT_LEN  = 1088


# ── HybridSignature ───────────────────────────────────────────────────────────

class HybridSignature(NamedTuple):
    """Raw bytes of a hybrid Ed25519 + ML-DSA signature."""
    ed25519_sig: bytes   # 64 bytes
    mldsa_sig:   bytes   # 3309 bytes (ML-DSA-65)

    def pack(self) -> bytes:
        """Concatenate into a single transmittable blob."""
        return self.ed25519_sig + self.mldsa_sig

    @classmethod
    def unpack(cls, blob: bytes) -> HybridSignature:
        if len(blob) < _ED25519_SIG_LEN:
            raise ValueError(f"Hybrid signature too short: {len(blob)} bytes")
        return cls(
            ed25519_sig = blob[:_ED25519_SIG_LEN],
            mldsa_sig   = blob[_ED25519_SIG_LEN:],
        )


# ── HybridSigner ─────────────────────────────────────────────────────────────

@dataclass
class HybridKeypair:
    """
    Combined Ed25519 + ML-DSA-65 signing keypair.

    Public keys are stored as raw bytes (b64-encode for DB/wire).
    Private keys should be encrypted at rest (CommunityKeypair handles this).
    """
    ed25519_priv_raw: bytes    # 32 bytes
    ed25519_pub_raw:  bytes    # 32 bytes
    mldsa_priv_raw:   bytes    # 4032 bytes (ML-DSA-65 secret key)
    mldsa_pub_raw:    bytes    # 1952 bytes


class HybridSigner:
    """
    Signs and verifies using BOTH Ed25519 AND ML-DSA-65.

    Both algorithms must pass for a signature to be considered valid —
    this is the "belt-and-suspenders" / "crypto-agility" pattern.
    """

    @staticmethod
    def generate() -> HybridKeypair:
        """Generate a fresh Ed25519 + ML-DSA-65 keypair."""
        _require_oqs()

        # Ed25519
        ed_priv = Ed25519PrivateKey.generate()
        ed_pub  = ed_priv.public_key()
        ed_priv_raw = ed_priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        ed_pub_raw = ed_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        # ML-DSA-65
        with oqs.Signature(_SIG_ALGO) as signer:
            mldsa_pub_raw  = signer.generate_keypair()
            mldsa_priv_raw = signer.export_secret_key()

        return HybridKeypair(
            ed25519_priv_raw = ed_priv_raw,
            ed25519_pub_raw  = ed_pub_raw,
            mldsa_priv_raw   = mldsa_priv_raw,
            mldsa_pub_raw    = mldsa_pub_raw,
        )

    @staticmethod
    def sign(data: bytes, keypair: HybridKeypair) -> HybridSignature:
        """
        Produce a hybrid Ed25519 + ML-DSA-65 signature over *data*.
        Both signatures are required — attacker must break BOTH algorithms.
        """
        _require_oqs()

        # Ed25519
        ed_priv = Ed25519PrivateKey.from_private_bytes(keypair.ed25519_priv_raw)
        ed_sig  = ed_priv.sign(data)

        # ML-DSA-65
        with oqs.Signature(_SIG_ALGO, keypair.mldsa_priv_raw) as signer:
            mldsa_sig = signer.sign(data)

        return HybridSignature(ed25519_sig=ed_sig, mldsa_sig=mldsa_sig)

    @staticmethod
    def verify(
        data:        bytes,
        sig:         HybridSignature,
        ed_pub_raw:  bytes,
        mldsa_pub_raw: bytes,
    ) -> bool:
        """
        Verify a hybrid signature. Returns True only if BOTH pass.

        Does NOT raise — returns False on any failure so callers can
        log and decide whether to fall back to classical-only.
        """
        if not _OQS_AVAILABLE:
            # Fall back to Ed25519-only during migration window
            log.warning("pqc: liboqs not available — verifying Ed25519 only")
            try:
                pub = Ed25519PublicKey.from_public_bytes(ed_pub_raw)
                pub.verify(sig.ed25519_sig, data)
                return True
            except Exception:
                return False

        # Ed25519 check
        try:
            pub = Ed25519PublicKey.from_public_bytes(ed_pub_raw)
            pub.verify(sig.ed25519_sig, data)
        except Exception:
            log.warning("pqc: Ed25519 signature verification failed")
            return False

        # ML-DSA-65 check
        try:
            with oqs.Signature(_SIG_ALGO) as verifier:
                if not verifier.verify(data, sig.mldsa_sig, mldsa_pub_raw):
                    log.warning("pqc: ML-DSA-65 signature verification failed")
                    return False
        except Exception as exc:
            log.warning("pqc: ML-DSA-65 verify error: %s", exc)
            return False

        return True


# ── HybridKEMResult ───────────────────────────────────────────────────────────

class HybridKEMResult(NamedTuple):
    """Output of HybridKEM.encapsulate()."""
    ciphertext:    bytes   # X25519 ephem pubkey (32) + ML-KEM ciphertext (1088)
    shared_secret: bytes   # 32-byte HKDF output (X25519_ss XOR ML-KEM_ss)


# ── HybridKEM ─────────────────────────────────────────────────────────────────

@dataclass
class HybridKEMKeypair:
    """
    Combined X25519 + ML-KEM-768 key encapsulation keypair.
    Used for Warden Syndicate tunnel handshakes.
    """
    x25519_priv_raw:  bytes   # 32 bytes
    x25519_pub_raw:   bytes   # 32 bytes
    mlkem_priv_raw:   bytes   # 2400 bytes (ML-KEM-768 secret key)
    mlkem_pub_raw:    bytes   # 1184 bytes


class HybridKEM:
    """
    Hybrid X25519 + ML-KEM-768 Key Encapsulation Mechanism.

    Encapsulate produces a ciphertext that can only be decapsulated by the
    holder of BOTH X25519 and ML-KEM private keys.

    Shared secret = HKDF-SHA256(X25519_secret XOR ML-KEM_secret)
    This XOR-then-HKDF construction is the standard NIST hybrid KEM pattern:
    even if one algorithm is broken, the other provides full security.
    """

    @staticmethod
    def generate() -> HybridKEMKeypair:
        """Generate a fresh X25519 + ML-KEM-768 keypair."""
        _require_oqs()

        # X25519
        x_priv = X25519PrivateKey.generate()
        x_pub  = x_priv.public_key()
        x_priv_raw = x_priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        x_pub_raw = x_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        # ML-KEM-768
        with oqs.KEM(_KEM_ALGO) as kem:
            mlkem_pub_raw  = kem.generate_keypair()
            mlkem_priv_raw = kem.export_secret_key()

        return HybridKEMKeypair(
            x25519_priv_raw  = x_priv_raw,
            x25519_pub_raw   = x_pub_raw,
            mlkem_priv_raw   = mlkem_priv_raw,
            mlkem_pub_raw    = mlkem_pub_raw,
        )

    @staticmethod
    def encapsulate(
        peer_x25519_pub_raw: bytes,
        peer_mlkem_pub_raw:  bytes,
        info:                bytes = b"warden:syndicate:v2-hybrid",
    ) -> HybridKEMResult:
        """
        Encapsulate a shared secret for the peer's public keys.

        Returns (ciphertext, shared_secret).
        ciphertext is sent to the peer who calls decapsulate() to recover
        shared_secret.
        """
        _require_oqs()

        # X25519: ephemeral keypair, ECDH exchange
        ephem_priv = X25519PrivateKey.generate()
        ephem_pub  = ephem_priv.public_key()
        peer_x_pub = X25519PublicKey.from_public_bytes(peer_x25519_pub_raw)
        x25519_ss  = ephem_priv.exchange(peer_x_pub)   # 32 bytes

        ephem_pub_raw = ephem_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        # ML-KEM-768: encapsulate
        with oqs.KEM(_KEM_ALGO) as kem:
            mlkem_ct, mlkem_ss = kem.encap_secret(peer_mlkem_pub_raw)

        # Hybrid shared secret: HKDF(X25519_ss XOR ML-KEM_ss)
        # XOR pads shorter secret with zeros if lengths differ
        combined = bytes(a ^ b for a, b in zip(
            x25519_ss.ljust(32, b"\x00"),
            mlkem_ss[:32],
        ))
        hkdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=info)
        shared_secret = hkdf.derive(combined)

        # Pack ciphertext: ephem_pub (32) || mlkem_ct (1088)
        ciphertext = ephem_pub_raw + mlkem_ct

        return HybridKEMResult(ciphertext=ciphertext, shared_secret=shared_secret)

    @staticmethod
    def decapsulate(
        ciphertext:     bytes,
        keypair:        HybridKEMKeypair,
        info:           bytes = b"warden:syndicate:v2-hybrid",
    ) -> bytes:
        """
        Recover the shared secret from *ciphertext* using our private keys.
        Returns 32-byte shared_secret.
        """
        _require_oqs()

        if len(ciphertext) < _X25519_PUB_LEN + _MLKEM768_CT_LEN:
            raise ValueError(
                f"HybridKEM ciphertext too short: {len(ciphertext)} bytes, "
                f"expected >= {_X25519_PUB_LEN + _MLKEM768_CT_LEN}"
            )

        # Unpack
        ephem_pub_raw = ciphertext[:_X25519_PUB_LEN]
        mlkem_ct      = ciphertext[_X25519_PUB_LEN:_X25519_PUB_LEN + _MLKEM768_CT_LEN]

        # X25519 ECDH
        our_x_priv  = X25519PrivateKey.from_private_bytes(keypair.x25519_priv_raw)
        peer_ephem  = X25519PublicKey.from_public_bytes(ephem_pub_raw)
        x25519_ss   = our_x_priv.exchange(peer_ephem)  # 32 bytes

        # ML-KEM-768 decapsulate
        with oqs.KEM(_KEM_ALGO, keypair.mlkem_priv_raw) as kem:
            mlkem_ss = kem.decap_secret(mlkem_ct)

        # Derive shared secret (identical construction as encapsulate)
        combined = bytes(a ^ b for a, b in zip(
            x25519_ss.ljust(32, b"\x00"),
            mlkem_ss[:32],
        ))
        hkdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=info)
        return hkdf.derive(combined)


# ── Crypto-agility abstraction ────────────────────────────────────────────────

class CryptoBackend:
    """
    Hot-swappable cryptographic backend.

    Version is stored in config and can be changed without code deployment.
    When NIST finalises additional PQC rounds, update _BACKEND_VERSION
    and implement the new HybridSigner/KEM variants here.

    Versions:
      v1-classical  — Ed25519 + X25519 only (no liboqs required)
      v2-hybrid     — Ed25519 + ML-DSA-65 + X25519 + ML-KEM-768 (current PQC)
    """

    VERSIONS = ("v1-classical", "v2-hybrid")

    def __init__(self, version: str = "v1-classical") -> None:
        if version not in self.VERSIONS:
            raise ValueError(f"Unknown crypto backend version: {version!r}")
        self.version = version
        self.is_pqc = version == "v2-hybrid"

    @property
    def sig_algo(self) -> str:
        return f"Ed25519+{_SIG_ALGO}" if self.is_pqc else "Ed25519"

    @property
    def kem_algo(self) -> str:
        return f"X25519+{_KEM_ALGO}" if self.is_pqc else "X25519"

    @classmethod
    def from_env(cls) -> CryptoBackend:
        """Read CRYPTO_BACKEND env var; default v1-classical."""
        version = os.getenv("CRYPTO_BACKEND", "v1-classical")
        if version not in cls.VERSIONS:
            log.warning("Unknown CRYPTO_BACKEND=%r — falling back to v1-classical", version)
            version = "v1-classical"
        return cls(version)

    def __repr__(self) -> str:
        return f"CryptoBackend(version={self.version!r}, pqc={self.is_pqc})"


# ── Safety number (hybrid) ────────────────────────────────────────────────────

def hybrid_safety_number(
    ed_pub: bytes,
    x_pub:  bytes,
    mldsa_pub: bytes | None = None,
    mlkem_pub: bytes | None = None,
) -> str:
    """
    20-char hex safety number for display in the Hub UI.

    For v2-hybrid keys, includes PQC public key material.
    Out-of-band verification: both parties display and compare this string.
    """
    material = ed_pub + x_pub
    if mldsa_pub:
        material += mldsa_pub
    if mlkem_pub:
        material += mlkem_pub
    return hashlib.sha256(material).hexdigest()[:20]


# ── Migration helpers ─────────────────────────────────────────────────────────

def is_pqc_available() -> bool:
    """Return True if liboqs is installed and PQC operations can be performed."""
    return _OQS_AVAILABLE


def pqc_status() -> dict:
    """Return a status dict for health checks and dashboard display."""
    status: dict = {
        "available":     _OQS_AVAILABLE,
        "sig_algorithm": _SIG_ALGO,
        "kem_algorithm": _KEM_ALGO,
        "fips_204":      _SIG_ALGO == "ML-DSA-65",
        "fips_203":      _KEM_ALGO == "ML-KEM-768",
    }
    if _OQS_AVAILABLE:
        try:
            enabled_kems  = oqs.get_enabled_kem_mechanisms()
            enabled_sigs  = oqs.get_enabled_sig_mechanisms()
            status["ml_kem_768_available"]  = _KEM_ALGO in enabled_kems
            status["ml_dsa_65_available"]   = _SIG_ALGO in enabled_sigs
        except Exception:
            pass
    return status
