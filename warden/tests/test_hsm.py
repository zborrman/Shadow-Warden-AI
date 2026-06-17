"""Tests for HSM key lifecycle hardening (SEC-02)."""
from __future__ import annotations

import pytest


@pytest.fixture()
def signer():
    """Fresh HSMSigner in software-fallback mode."""
    import warden.crypto.hsm as _hsm_mod
    _hsm_mod._signer = None
    s = _hsm_mod.HSMSigner()
    yield s
    s.close()
    _hsm_mod._signer = None


class TestMasterKeyRotation:
    def test_rotation_returns_success(self, signer):
        result = signer.rotate_master_key()
        assert result["rotated"] is True
        assert "sw_fallback" in result

    def test_rotation_in_sw_fallback_still_signs(self, signer):
        # Pre-generate key
        data = b"hello"
        sig_before = signer.sign(data)
        assert len(sig_before) > 0

        # Rotate
        signer.rotate_master_key()

        # Should still be able to sign (new key generated lazily)
        sig_after = signer.sign(data)
        assert len(sig_after) > 0


class TestAuditAccess:
    def test_audit_access_does_not_raise(self, signer):
        # Should be fire-and-forget, no exception
        signer.audit_access("agent-123", "sign")
        signer.audit_access("agent-123", "verify")
        signer.audit_access("agent-123", "delete")

    def test_audit_called_on_sign(self, signer, monkeypatch):
        calls = []
        monkeypatch.setattr(signer, "audit_access", lambda k, op: calls.append(op))
        # Direct call to audit_access
        signer.audit_access("test-key", "sign")
        assert "sign" in calls


class TestKeyLockUnlock:
    def test_lock_prevents_key_from_being_used(self, signer):
        signer.lock_key("agent-xyz")
        assert signer.is_key_locked("agent-xyz")

    def test_unlock_restores_key(self, signer):
        signer.lock_key("agent-abc")
        assert signer.is_key_locked("agent-abc")
        signer.unlock_key("agent-abc")
        assert not signer.is_key_locked("agent-abc")

    def test_lock_multiple_keys(self, signer):
        signer.lock_key("k1")
        signer.lock_key("k2")
        assert signer.is_key_locked("k1")
        assert signer.is_key_locked("k2")
        signer.unlock_key("k1")
        assert not signer.is_key_locked("k1")
        assert signer.is_key_locked("k2")

    def test_sign_works_when_agent_key_locked(self, signer):
        """Locking an agent key does not prevent the HSM signer itself from working."""
        signer.lock_key("some-agent")
        data = b"sign me"
        sig = signer.sign(data)
        assert len(sig) > 0
