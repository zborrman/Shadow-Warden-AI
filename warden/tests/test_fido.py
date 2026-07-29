"""
warden/tests/test_fido.py  (Phase 4 — 6 tests)
FIDO2/WebAuthn Passkey authentication.
"""
from __future__ import annotations

import os
import uuid

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

    def test_unverifiable_credential_is_refused_by_default(self):
        """
        This used to assert verified is True: without py_webauthn — or with a
        credential that does not parse as a WebAuthn response — the scaffolding
        path accepted anything and stored it as a real passkey. That is a
        fail-open in an authentication primitive, so the default is now refusal.
        """
        # A unique tenant per run: warden/auth/fido.py snapshots _DB_PATH at
        # import, so setting FIDO_DB_PATH in a fixture does not actually
        # repoint the database and rows survive between runs.
        tenant = f"refuse-{uuid.uuid4().hex[:8]}"
        fido = self._fido()
        fido.generate_registration_options(tenant, "T2")
        result = fido.verify_registration(tenant, {"id": "cred-stub-123"})
        assert result["verified"] is False
        assert result["reason"] == "webauthn_unavailable"
        assert fido.list_credentials(tenant) == []

    def test_stub_roundtrip_when_explicitly_enabled(self, monkeypatch):
        """The scaffolding path still works for local work, but only opt-in."""
        from warden.auth import fido as fido_mod

        monkeypatch.setenv("FIDO_ALLOW_STUB", "true")
        monkeypatch.setattr(
            type(fido_mod.settings), "is_prod", property(lambda self: False)
        )

        tenant = f"stub-{uuid.uuid4().hex[:8]}"
        fido = self._fido()
        fido.generate_registration_options(tenant, "T2")
        result = fido.verify_registration(tenant, {"id": f"cred-{tenant}"})
        assert result["verified"] is True

    def test_list_credentials_empty(self):
        creds = self._fido().list_credentials("new-tenant")
        assert creds == []

    def test_delete_nonexistent_returns_false(self):
        ok = self._fido().delete_credential("tenant1", "nonexistent-cred")
        assert ok is False
