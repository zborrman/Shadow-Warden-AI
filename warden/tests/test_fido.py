"""
warden/tests/test_fido.py  (Phase 4 — 6 tests)
FIDO2/WebAuthn Passkey authentication.
"""
from __future__ import annotations

import os
import pytest

os.environ.setdefault("FIDO_DB_PATH", "/tmp/test_fido.db")
os.environ.setdefault("FIDO_RP_ID",   "test.example.com")
os.environ.setdefault("FIDO_ORIGIN",  "https://test.example.com")


class TestFIDOProvider:
    @pytest.fixture(autouse=True)
    def _clean(self, tmp_path):
        db = str(tmp_path / "fido.db")
        os.environ["FIDO_DB_PATH"] = db
        yield
        if os.path.exists(db):
            os.remove(db)

    def _fido(self):
        from warden.auth.fido import FIDOProvider
        return FIDOProvider()

    def test_registration_options_returns_challenge(self):
        opts = self._fido().generate_registration_options("tenant1", "Tenant One")
        assert "challenge" in opts
        assert len(opts["challenge"]) > 10

    def test_registration_options_has_rp(self):
        opts = self._fido().generate_registration_options("tenant1", "Tenant One")
        assert "rp" in opts or "rpId" in opts or "rp" in str(opts)

    def test_verify_registration_no_challenge_fails(self):
        result = self._fido().verify_registration("unknown_tenant", {"id": "cred1"})
        assert result["verified"] is False
        assert result["reason"] == "no_challenge"

    def test_stub_registration_roundtrip(self):
        fido = self._fido()
        fido.generate_registration_options("tenant2", "T2")
        result = fido.verify_registration("tenant2", {"id": "cred-stub-123"})
        assert result["verified"] is True

    def test_list_credentials_empty(self):
        creds = self._fido().list_credentials("new-tenant")
        assert creds == []

    def test_delete_nonexistent_returns_false(self):
        ok = self._fido().delete_credential("tenant1", "nonexistent-cred")
        assert ok is False
