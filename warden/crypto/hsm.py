"""
warden/crypto/hsm.py  (CR-14)
──────────────────────────────
PKCS#11 HSM bridge for sovereign key material.

HSMSigner wraps a PKCS#11-compatible HSM (Thales Luna, AWS CloudHSM,
SoftHSM2, etc.) via the `python-pkcs11` library.  When the HSM is
unavailable or `python-pkcs11` is not installed, it transparently falls
back to the software Ed25519 signer in warden/crypto/pqc.py.

Configuration (env vars)
────────────────────────
  PKCS11_LIB          — path to the PKCS#11 shared library (.so / .dll)
                         e.g. /usr/lib/softhsm/libsofthsm2.so
  PKCS11_TOKEN_LABEL  — token label (default "shadow-warden")
  PKCS11_PIN          — token user PIN
  PKCS11_KEY_LABEL    — CKA_LABEL of the signing key (default "warden-sign")
  HSM_ENABLED         — set to "true" to activate; default off (fail-open)

Supported operations
────────────────────
  sign(data: bytes) → bytes      — CKM_ECDSA_SHA256 (P-256) signature
  verify(data, sig) → bool       — verify via HSM
  public_key_pem()  → str        — export DER-encoded public key as PEM
  is_available()    → bool       — health check without signing
"""
from __future__ import annotations

import contextlib
import logging
import os

log = logging.getLogger("warden.crypto.hsm")

_HSM_ENABLED  = os.getenv("HSM_ENABLED", "false").lower() == "true"
_PKCS11_LIB   = os.getenv("PKCS11_LIB", "")
_TOKEN_LABEL  = os.getenv("PKCS11_TOKEN_LABEL", "shadow-warden")
_PIN          = os.getenv("PKCS11_PIN", "")
_KEY_LABEL    = os.getenv("PKCS11_KEY_LABEL", "warden-sign")

_OQS_AVAILABLE = False  # populated below

try:
    import pkcs11 as _pkcs11_mod  # type: ignore[import]  # noqa: F401
    _PKCS11_AVAILABLE = True
except ImportError:
    _PKCS11_AVAILABLE = False


# ── HSMSigner ─────────────────────────────────────────────────────────────────

class HSMUnavailableError(RuntimeError):
    """Raised when HSM is requested but not available."""


class HSMSigner:
    """
    PKCS#11-backed signing.  All methods are synchronous (PKCS#11 is
    inherently synchronous).  Callers in async context should use
    asyncio.get_event_loop().run_in_executor().

    Falls back to software Ed25519 when HSM_ENABLED=false or library unavailable.
    """

    def __init__(self) -> None:
        self._lib: object | None   = None
        self._token: object | None = None
        self._session: object | None = None
        self._available: bool = False
        self._sw_fallback: bool = False

        if not _HSM_ENABLED:
            log.debug("HSM disabled (HSM_ENABLED != true) — using software fallback")
            self._sw_fallback = True
            return

        if not _PKCS11_AVAILABLE:
            log.warning("python-pkcs11 not installed — HSM falls back to software keys")
            self._sw_fallback = True
            return

        if not _PKCS11_LIB:
            log.warning("PKCS11_LIB not set — HSM falls back to software keys")
            self._sw_fallback = True
            return

        self._init_session()

    def _init_session(self) -> None:
        try:
            import pkcs11  # type: ignore[import]

            lib = pkcs11.lib(_PKCS11_LIB)
            token = lib.get_token(token_label=_TOKEN_LABEL)
            self._session = token.open(user_pin=_PIN)
            self._lib     = lib
            self._token   = token
            self._available = True
            log.info("HSM session opened — token=%s key=%s", _TOKEN_LABEL, _KEY_LABEL)
        except Exception as exc:
            log.error("HSM init failed: %s — falling back to software keys", exc)
            self._sw_fallback = True

    def is_available(self) -> bool:
        return self._available

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with ECDSA-SHA256 via HSM.
        Falls back to software Ed25519 if HSM unavailable.
        """
        if self._sw_fallback or not self._available:
            return self._sw_sign(data)

        try:
            from pkcs11 import KeyType, Mechanism  # type: ignore[import]

            session = self._session
            key = session.get_key(  # type: ignore[union-attr]
                key_type=KeyType.EC,
                label=_KEY_LABEL,
            )
            sig = key.sign(data, mechanism=Mechanism.ECDSA_SHA256)
            return bytes(sig)
        except Exception as exc:
            log.error("HSM sign failed: %s — falling back", exc)
            self._available = False
            self._sw_fallback = True
            return self._sw_sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify ECDSA-SHA256 signature via HSM, or software fallback."""
        if self._sw_fallback or not self._available:
            return self._sw_verify(data, signature)

        try:
            from pkcs11 import KeyType, Mechanism  # type: ignore[import]

            session = self._session
            key = session.get_key(  # type: ignore[union-attr]
                key_type=KeyType.EC,
                label=_KEY_LABEL,
            )
            key.verify(data, signature, mechanism=Mechanism.ECDSA_SHA256)
            return True
        except Exception:
            return False

    def public_key_pem(self) -> str:
        """Export the HSM public key as PEM, or software fallback."""
        if self._sw_fallback or not self._available:
            return self._sw_public_key_pem()

        try:
            import pkcs11  # type: ignore[import]
            from pkcs11 import KeyType  # type: ignore[import]
            from pkcs11.util.ec import encode_ec_public_key  # type: ignore[import]

            session = self._session
            key = session.get_key(  # type: ignore[union-attr]
                key_type=KeyType.EC,
                label=_KEY_LABEL,
                object_class=pkcs11.ObjectClass.PUBLIC_KEY,
            )
            der = bytes(encode_ec_public_key(key))
            # Wrap in PEM
            import base64  # noqa: PLC0415
            b64 = base64.b64encode(der).decode()
            pem_body = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
            return f"-----BEGIN PUBLIC KEY-----\n{pem_body}\n-----END PUBLIC KEY-----\n"
        except Exception as exc:
            log.error("HSM public_key_pem failed: %s", exc)
            return self._sw_public_key_pem()

    # ── Software fallback ─────────────────────────────────────────────────────

    def _sw_sign(self, data: bytes) -> bytes:
        key = self._get_sw_key()
        return key.sign(data)

    def _sw_verify(self, data: bytes, sig: bytes) -> bool:
        try:
            self._get_sw_key().public_key().verify(sig, data)
            return True
        except Exception:
            return False

    def _sw_public_key_pem(self) -> str:
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            Encoding,
            PublicFormat,
        )
        return self._get_sw_key().public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def _get_sw_key(self):
        """Lazy-load or generate an in-process Ed25519 key (test / fallback only)."""
        if not hasattr(self, "_sw_key"):
            import os as _os  # noqa: PLC0415

            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,  # noqa: PLC0415
            )
            seed_hex = _os.getenv("HSM_SW_KEY_HEX", "")
            if seed_hex and len(seed_hex) == 64:
                self._sw_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
            else:
                log.warning("HSM: no HSM_SW_KEY_HEX — generating ephemeral key (not persistent!)")
                self._sw_key = Ed25519PrivateKey.generate()
        return self._sw_key

    def close(self) -> None:
        if self._session:
            with contextlib.suppress(Exception):
                self._session.close()  # type: ignore[union-attr]
            self._session = None


# ── Module-level singleton ────────────────────────────────────────────────────

_signer: HSMSigner | None = None


def get_signer() -> HSMSigner:
    global _signer
    if _signer is None:
        _signer = HSMSigner()
    return _signer


def hsm_status() -> dict:
    s = get_signer()
    return {
        "hsm_enabled":     _HSM_ENABLED,
        "pkcs11_available": _PKCS11_AVAILABLE,
        "lib":             _PKCS11_LIB or None,
        "token_label":     _TOKEN_LABEL,
        "key_label":       _KEY_LABEL,
        "session_active":  s.is_available(),
        "sw_fallback":     s._sw_fallback,
    }
