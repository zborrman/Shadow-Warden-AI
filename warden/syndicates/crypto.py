"""
warden/syndicates/crypto.py
───────────────────────────
Cryptographic primitives for Warden Syndicates Zero-Trust Tunnels.

Key exchange:  X25519 Elliptic-Curve Diffie-Hellman (ECDH)
Key derivation: HKDF-SHA256 → 256-bit AES key
Encryption:    AES-256-GCM (authenticated — integrity + confidentiality)

Design decisions
────────────────
• Perfect Forward Secrecy (PFS): every tunnel gets a fresh ephemeral key pair.
  Compromise of a later key cannot decrypt past sessions.

• HKDF info tag includes tunnel_id so the same ECDH shared secret can never
  be reused across different tunnels (Key Separation).

• AES-GCM auth tag (128-bit) guarantees payload integrity — any tampering
  during transit causes DecryptionError, which triggers tunnel revocation.

• Man-in-the-Middle protection: after handshake both gateways display
  Safety Numbers (first 12 hex chars of SHA-256(aes_key)). Admins verify
  out-of-band (phone / Slack) before activating the tunnel.

Usage
─────
    # Initiating side (Platform A)
    priv_a, pub_a = TunnelCrypto.generate_keypair()
    # → pub_a is sent to Platform B in the handshake manifest

    # Responding side (Platform B)
    priv_b, pub_b = TunnelCrypto.generate_keypair()
    aes_key_b = TunnelCrypto.derive_shared_key(priv_b, pub_a, tunnel_id)
    # → pub_b is sent back to Platform A

    # Platform A completes the exchange
    aes_key_a = TunnelCrypto.derive_shared_key(priv_a, pub_b, tunnel_id)
    assert aes_key_a == aes_key_b  # identical on both sides — tunnel ready

    # Encrypt / decrypt
    envelope = TunnelCrypto.encrypt("Hello, Platform B", aes_key_a)
    plaintext = TunnelCrypto.decrypt(envelope, aes_key_b)
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class DecryptionError(Exception):
    """Raised when AES-GCM authentication fails (tampered ciphertext or wrong key)."""


class TunnelCrypto:
    """Static utility class — no state, all methods are pure functions."""

    # ── Key generation ────────────────────────────────────────────────────────

    @staticmethod
    def generate_keypair() -> tuple[str, str]:
        """
        Generate an ephemeral X25519 key pair for a new tunnel.

        Returns
        -------
        (private_key_b64, public_key_b64)
            Both encoded as URL-safe base64 (no padding) for safe JSON transport.
        """
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return (
            base64.urlsafe_b64encode(priv_bytes).decode("ascii"),
            base64.urlsafe_b64encode(pub_bytes).decode("ascii"),
        )

    # ── ECDH + HKDF ──────────────────────────────────────────────────────────

    @staticmethod
    def derive_shared_key(
        my_private_b64: str,
        peer_public_b64: str,
        tunnel_id: str,
    ) -> bytes:
        """
        Perform X25519 ECDH and derive a 256-bit AES key via HKDF-SHA256.

        Parameters
        ----------
        my_private_b64:  URL-safe base64 private key (from generate_keypair)
        peer_public_b64: URL-safe base64 public key received from the peer
        tunnel_id:       UUID of the tunnel — used as HKDF context (info) to
                         prevent key re-use across different tunnels.

        Returns
        -------
        32-byte AES-256 key (bytes)
        """
        priv_bytes = base64.urlsafe_b64decode(my_private_b64)
        pub_bytes = base64.urlsafe_b64decode(peer_public_b64)

        private_key = X25519PrivateKey.from_private_bytes(priv_bytes)
        public_key = X25519PublicKey.from_public_bytes(pub_bytes)

        # ECDH exchange → raw shared secret (not safe to use directly as key)
        raw_secret = private_key.exchange(public_key)

        # HKDF-SHA256 → cryptographically strong 256-bit AES key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"warden-syndicate-v1-{tunnel_id}".encode(),
        )
        return hkdf.derive(raw_secret)

    # ── Safety numbers ────────────────────────────────────────────────────────

    @staticmethod
    def safety_number(aes_key: bytes) -> str:
        """
        Produce a 12-character hex fingerprint of the shared key.

        Both gateway admins see the same string after a successful handshake.
        They verify it out-of-band (phone / Slack) to prove no MitM occurred.

        Example: "3f8a-b291-04cc"
        """
        digest = hashlib.sha256(aes_key).hexdigest()[:12]
        return f"{digest[:4]}-{digest[4:8]}-{digest[8:12]}"

    # ── Encryption / Decryption ───────────────────────────────────────────────

    @staticmethod
    def encrypt(plaintext: str, aes_key: bytes) -> dict[str, str]:
        """
        Encrypt plaintext with AES-256-GCM.

        A fresh 96-bit (12-byte) nonce is generated per call.  The GCM auth
        tag (128-bit) is appended automatically by the cryptography library
        and verified on decrypt — any byte-level tampering raises DecryptionError.

        Returns
        -------
        {"nonce": "<b64>", "ciphertext": "<b64>"}
        Both fields are URL-safe base64 encoded for JSON transport.
        """
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return {
            "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        }

    @staticmethod
    def decrypt(envelope: dict[str, str], aes_key: bytes) -> str:
        """
        Decrypt an envelope produced by encrypt().

        Raises
        ------
        DecryptionError  — if the auth tag is invalid (tampered payload,
                           wrong key, or expired/revoked tunnel).
        """
        try:
            aesgcm = AESGCM(aes_key)
            nonce = base64.urlsafe_b64decode(envelope["nonce"])
            ciphertext = base64.urlsafe_b64decode(envelope["ciphertext"])
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext_bytes.decode("utf-8")
        except InvalidTag as exc:
            raise DecryptionError(
                "AES-GCM authentication failed — payload tampered or key mismatch"
            ) from exc
        except Exception as exc:
            raise DecryptionError(f"Decryption error: {exc}") from exc
