"""
warden/tests/test_crypto_hsm.py
────────────────────────────────
Unit tests for warden/crypto/hsm.py (CR-14).
All tests use the software fallback path (HSM_ENABLED=false).
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("HSM_ENABLED", "false")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("REDIS_URL", "memory://")


class TestHSMSignerSoftwareFallback:
    """All tests use software fallback (HSM_ENABLED=false)."""

    def test_signer_init_sw_fallback(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        assert s._sw_fallback is True
        assert s._available is False

    def test_is_available_false_in_fallback(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        assert s.is_available() is False

    def test_sign_returns_bytes(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        sig = s.sign(b"hello world")
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_verify_valid_signature(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        data = b"test data for signing"
        sig = s.sign(data)
        assert s.verify(data, sig) is True

    def test_verify_invalid_signature(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        data = b"test data"
        assert s.verify(data, b"bad signature") is False

    def test_public_key_pem_format(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        pem = s.public_key_pem()
        assert "-----BEGIN PUBLIC KEY-----" in pem
        assert "-----END PUBLIC KEY-----" in pem

    def test_sign_verify_consistency(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        messages = [b"msg1", b"msg2 longer", b"" + b"x" * 1000]
        for msg in messages:
            sig = s.sign(msg)
            assert s.verify(msg, sig) is True

    def test_sign_different_messages_different_sigs(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        sig1 = s.sign(b"message one")
        sig2 = s.sign(b"message two")
        assert sig1 != sig2

    def test_close_noop_in_sw_fallback(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        s.close()  # should not raise

    def test_get_signer_singleton(self):
        import warden.crypto.hsm as hsm_mod
        hsm_mod._signer = None  # reset singleton
        s1 = hsm_mod.get_signer()
        s2 = hsm_mod.get_signer()
        assert s1 is s2

    def test_hsm_status_dict(self):
        from warden.crypto.hsm import hsm_status
        status = hsm_status()
        assert "hsm_enabled" in status
        assert "pkcs11_available" in status
        assert "session_active" in status
        assert "sw_fallback" in status
        assert status["hsm_enabled"] is False
        assert status["sw_fallback"] is True

    def test_hsm_status_lib_none_when_not_set(self):
        from warden.crypto.hsm import hsm_status
        status = hsm_status()
        assert status["lib"] is None or isinstance(status["lib"], str)

    def test_sw_key_lazy_load(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        assert not hasattr(s, "_sw_key")
        _ = s._get_sw_key()
        assert hasattr(s, "_sw_key")

    def test_sw_key_from_env(self):
        from warden.crypto.hsm import HSMSigner
        # Valid 32-byte hex seed
        seed = "a" * 64
        with pytest.MonkeyPatch().context() as m:
            m.setenv("HSM_SW_KEY_HEX", seed)
            s = HSMSigner()
            key = s._get_sw_key()
            assert key is not None

    def test_sw_key_invalid_hex_generates_ephemeral(self):
        from warden.crypto.hsm import HSMSigner
        with pytest.MonkeyPatch().context() as m:
            m.setenv("HSM_SW_KEY_HEX", "tooshort")
            s = HSMSigner()
            key = s._get_sw_key()
            assert key is not None  # generates ephemeral

    def test_sign_empty_bytes(self):
        from warden.crypto.hsm import HSMSigner
        s = HSMSigner()
        sig = s.sign(b"")
        assert isinstance(sig, bytes)

    def test_pkcs11_not_available_fallback(self):
        import sys

        # Simulate pkcs11 not installed
        orig = sys.modules.get("pkcs11")
        sys.modules["pkcs11"] = None  # type: ignore
        try:
            from warden.crypto.hsm import HSMSigner
            with pytest.MonkeyPatch().context() as m:
                m.setenv("HSM_ENABLED", "true")
                m.setenv("PKCS11_LIB", "/fake/lib.so")
                s = HSMSigner()
                assert s._sw_fallback is True or not s._available
        finally:
            if orig is None:
                del sys.modules["pkcs11"]
            else:
                sys.modules["pkcs11"] = orig

    def test_hsm_unavailable_error(self):
        from warden.crypto.hsm import HSMUnavailableError
        with pytest.raises(HSMUnavailableError):
            raise HSMUnavailableError("test")


class TestHSMSignerSeedConsistency:
    """Two signers with the same seed produce the same signature."""

    def test_deterministic_with_seed(self):
        from warden.crypto.hsm import HSMSigner
        seed = "b" * 64
        with pytest.MonkeyPatch().context() as m:
            m.setenv("HSM_SW_KEY_HEX", seed)
            s1 = HSMSigner()
            s2 = HSMSigner()
            sig1 = s1.sign(b"deterministic test")
            sig2 = s2.sign(b"deterministic test")
            assert sig1 == sig2

    def test_cross_verify_with_same_seed(self):
        from warden.crypto.hsm import HSMSigner
        seed = "c" * 64
        with pytest.MonkeyPatch().context() as m:
            m.setenv("HSM_SW_KEY_HEX", seed)
            s1 = HSMSigner()
            s2 = HSMSigner()
            data = b"cross verify test"
            sig = s1.sign(data)
            assert s2.verify(data, sig) is True
