"""
warden/kya/did.py
─────────────────
Decentralized Identifier (DID) primitives for Shadow Warden agents.

DID format:  did:shadow:{base62(sha256(pubkey_bytes)[:16])}
Signing key: Ed25519 via `cryptography` library (fail-open: hashlib fallback)

Competitors: Nevermined ID, Skyfire agent identity.
Differentiator: HMAC-anchored trust score in Turso marketplace DB.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import string

from warden.secret_keys import resolve_key

_B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase  # 0-9A-Za-z


# ── Base-62 encoder ────────────────────────────────────────────────────────────

def _to_b62(data: bytes, length: int = 22) -> str:
    n = int.from_bytes(data[:16], "big")
    digits: list[str] = []
    while n:
        digits.append(_B62[n % 62])
        n //= 62
    while len(digits) < length:
        digits.append(_B62[0])
    return "".join(reversed(digits))[:length]


# ── DID derivation ─────────────────────────────────────────────────────────────

def pubkey_to_did(pubkey_bytes: bytes) -> str:
    """Derive `did:shadow:{base62}` from a raw Ed25519 public key (32 bytes)."""
    digest = hashlib.sha256(pubkey_bytes).digest()
    return f"did:shadow:{_to_b62(digest)}"


def did_from_seed(seed: bytes) -> str:
    """Deterministic DID from a 32-byte seed (without real Ed25519 keypair)."""
    return pubkey_to_did(hashlib.sha256(seed).digest())


# ── Keypair generation ─────────────────────────────────────────────────────────

def generate_keypair() -> tuple[str, str, str]:
    """
    Generate an Ed25519 keypair.  Returns (private_b64, public_b64, did).

    Falls back to HMAC-seeded deterministic bytes when `cryptography` is absent
    (test / air-gapped environments).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PrivateKey,
        )
        priv = Ed25519PrivateKey.generate()
        priv_raw = priv.private_bytes_raw()
        pub_raw  = priv.public_key().public_bytes_raw()
    except ImportError:
        priv_raw = secrets.token_bytes(32)
        pub_raw  = hashlib.sha256(priv_raw).digest()

    priv_b64 = base64.urlsafe_b64encode(priv_raw).decode()
    pub_b64  = base64.urlsafe_b64encode(pub_raw).decode()
    did      = pubkey_to_did(pub_raw)
    return priv_b64, pub_b64, did


# ── Signing / verification ─────────────────────────────────────────────────────

def sign_challenge(private_b64: str, challenge: str) -> str:
    """Ed25519-sign a challenge string. Returns base64url signature."""
    priv_raw = base64.urlsafe_b64decode(private_b64 + "==")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PrivateKey,
        )
        priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
        sig  = priv.sign(challenge.encode())
    except ImportError:
        sig = hmac.new(priv_raw, challenge.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode()


def verify_signature(pubkey_b64: str, challenge: str, signature_b64: str) -> bool:
    """Verify an Ed25519 signature. Fail-open: returns True on library error."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey,
        )
        pub_raw = base64.urlsafe_b64decode(pubkey_b64 + "==")
        pub     = Ed25519PublicKey.from_public_bytes(pub_raw)
        sig     = base64.urlsafe_b64decode(signature_b64 + "==")
        pub.verify(sig, challenge.encode())
        return True
    except ImportError:
        return True   # no crypto library → fail-open
    except Exception:
        return False


# ── DID validation ─────────────────────────────────────────────────────────────

def is_valid_did(did: str) -> bool:
    """Return True if *did* matches the `did:shadow:{22 base-62 chars}` pattern."""
    if not did.startswith("did:shadow:"):
        return False
    tail = did[len("did:shadow:"):]
    return len(tail) == 22 and all(c in _B62 for c in tail)  # noqa: SIM103


# ── Random ephemeral DID (for tests / anonymous agents) ───────────────────────

def ephemeral_did() -> str:
    return did_from_seed(secrets.token_bytes(32))


def _kya_trust_key() -> bytes:
    return resolve_key("KYA_TRUST_HMAC_KEY", purpose="kya_trust")


def sign_trust_assertion(did: str, trust_score: float, issued_at: str) -> str:
    """HMAC-SHA256 trust assertion signed by the gateway."""
    msg = f"{did}|{trust_score:.4f}|{issued_at}".encode()
    return hmac.new(_kya_trust_key(), msg, hashlib.sha256).hexdigest()
