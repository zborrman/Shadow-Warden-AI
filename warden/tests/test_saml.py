"""
warden/tests/test_saml.py
━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for SAML 2.0 SSO routes and SAMLProvider logic.

Strategy: python3-saml + PyJWT are both real dependencies, but the
OneLogin auth object is mocked so no actual IdP is needed.
Redis is replaced by a simple dict-backed fake.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

if TYPE_CHECKING:
    from warden.auth.saml_provider import SAMLProvider

import pytest
from fastapi.testclient import TestClient

# ── Fake Redis for OTP store ──────────────────────────────────────────────────

class _FakeRedis:
    def __init__(self):
        self._store: dict[str, tuple[str, float]] = {}

    def setex(self, key: str, ttl: int, value: str) -> None:
        self._store[key] = (value, time.time() + ttl)

    def getdel(self, key: str) -> str | None:
        entry = self._store.pop(key, None)
        if entry is None:
            return None
        value, exp = entry
        return value if time.time() < exp else None

    def get(self, key: str) -> str | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, exp = entry
        return value if time.time() < exp else None


# ── SAMLProvider unit tests ───────────────────────────────────────────────────

class TestSAMLProvider:

    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch):
        monkeypatch.setenv("SAML_SP_ENTITY_ID", "https://warden.test")
        monkeypatch.setenv("SAML_SP_ACS_URL",   "https://warden.test/auth/saml/acs")
        monkeypatch.setenv("SAML_JWT_SECRET",    "a" * 32)
        monkeypatch.setenv("SAML_IDP_METADATA_XML", _DUMMY_IDP_XML)

    def _make_provider(self) -> SAMLProvider:
        from warden.auth.saml_provider import SAMLProvider
        p = SAMLProvider.__new__(SAMLProvider)
        # Bypass real python3-saml settings build — inject stub settings
        p._settings = {}
        p._redis = _FakeRedis()
        return p

    def test_store_and_redeem_otp(self):
        from warden.auth.saml_provider import SamlSession
        p = self._make_provider()
        session = SamlSession(
            email="alice@acme.com", name="Alice",
            groups=["warden_tenant_acme"], tenant_id="acme",
            expires_at=int(time.time()) + 3600,
        )
        token = p.store_otp(session)
        assert token and len(token) > 10

        redeemed = p.redeem_otp(token)
        assert redeemed is not None
        assert redeemed.email == "alice@acme.com"
        assert redeemed.tenant_id == "acme"

    def test_otp_is_single_use(self):
        from warden.auth.saml_provider import SamlSession
        p = self._make_provider()
        session = SamlSession(
            email="bob@acme.com", name="Bob",
            groups=[], tenant_id="default",
            expires_at=int(time.time()) + 3600,
        )
        token = p.store_otp(session)
        assert p.redeem_otp(token) is not None
        assert p.redeem_otp(token) is None   # second use → None

    def test_invalid_otp_returns_none(self):
        p = self._make_provider()
        assert p.redeem_otp("totally-invalid-token") is None

    def test_issue_and_verify_jwt(self):
        from warden.auth.saml_provider import SamlSession
        p = self._make_provider()
        session = SamlSession(
            email="carol@acme.com", name="Carol",
            groups=["warden_tenant_acme", "admin"],
            tenant_id="acme",
            expires_at=int(time.time()) + 3600,
        )
        token = p.issue_jwt(session)
        assert isinstance(token, str)

        payload = p.verify_jwt(token)
        assert payload is not None
        assert payload["sub"] == "carol@acme.com"
        assert payload["tid"] == "acme"
        assert "admin" in payload["grp"]

    def test_verify_jwt_invalid_token(self):
        p = self._make_provider()
        assert p.verify_jwt("not.a.jwt") is None

    def test_verify_jwt_wrong_secret(self):
        import jwt

        from warden.auth.saml_provider import SamlSession
        p = self._make_provider()
        session = SamlSession(
            email="eve@acme.com", name="Eve",
            groups=[], tenant_id="default",
            expires_at=int(time.time()) + 3600,
        )
        token = jwt.encode(
            {"sub": session.email, "exp": session.expires_at},
            "wrong_secret", algorithm="HS256"
        )
        assert p.verify_jwt(token) is None

    def test_jwt_no_secret_raises(self, monkeypatch):
        from warden.auth.saml_provider import SamlSession
        monkeypatch.setenv("SAML_JWT_SECRET", "")
        # Re-import to pick up new env var
        import importlib

        import warden.auth.saml_provider as mod
        importlib.reload(mod)
        p = mod.SAMLProvider.__new__(mod.SAMLProvider)
        p._settings = {}
        p._redis = _FakeRedis()
        session = SamlSession(
            email="x@x.com", name="X", groups=[],
            tenant_id="default", expires_at=int(time.time()) + 3600
        )
        with pytest.raises(RuntimeError, match="SAML_JWT_SECRET"):
            p.issue_jwt(session)


# ── _extract_tenant helper ────────────────────────────────────────────────────

class TestExtractTenant:
    def test_extracts_tenant_from_group(self):
        from warden.auth.saml_provider import _extract_tenant
        assert _extract_tenant(["warden_tenant_acme", "admin"]) == "acme"

    def test_falls_back_to_default(self):
        from warden.auth.saml_provider import _extract_tenant
        assert _extract_tenant(["engineers", "all-staff"]) == "default"

    def test_empty_groups_default(self):
        from warden.auth.saml_provider import _extract_tenant
        assert _extract_tenant([]) == "default"


# ── FastAPI route tests ───────────────────────────────────────────────────────

class TestSAMLRoutes:
    """
    Tests for /auth/saml/* endpoints.
    We don't test the full SAML XML flow (that requires python3-saml + real
    IdP certs); instead we patch SAMLProvider at the app.state level and verify
    the route logic (redirects, OTP exchange, JWT verification).
    """

    @pytest.fixture(autouse=True)
    def _patch_saml(self, monkeypatch):
        from warden.main import app
        self._fake_redis = _FakeRedis()
        self._provider = MagicMock()
        self._provider.get_metadata_xml.return_value = ("<md:EntityDescriptor/>", [])
        self._provider.build_login_url.return_value = "https://idp.example.com/sso?SAMLRequest=abc"
        self._provider.store_otp.side_effect = lambda s: "test-otp-token"
        self._provider.redeem_otp.side_effect = self._fake_redeem_otp
        self._provider.issue_jwt.return_value = "fake.jwt.token"
        self._provider.verify_jwt.side_effect = self._fake_verify_jwt

        app.state.saml = self._provider
        self.client = TestClient(app, raise_server_exceptions=True)
        yield
        app.state.saml = None

    def _fake_redeem_otp(self, token: str):
        from warden.auth.saml_provider import SamlSession
        if token == "valid-otp":
            return SamlSession(
                email="alice@acme.com", name="Alice",
                groups=["warden_tenant_acme"], tenant_id="acme",
                expires_at=int(time.time()) + 3600,
            )
        return None

    def _fake_verify_jwt(self, token: str):
        if token == "valid.jwt.token":
            return {"sub": "alice@acme.com", "tid": "acme", "exp": int(time.time()) + 3600}
        return None

    def test_metadata_returns_xml(self):
        resp = self.client.get("/auth/saml/metadata")
        assert resp.status_code == 200
        assert "EntityDescriptor" in resp.text

    def test_login_redirects_to_idp(self):
        resp = self.client.get("/auth/saml/login", follow_redirects=False)
        assert resp.status_code == 302
        assert "idp.example.com" in resp.headers["location"]

    def test_session_valid_otp_returns_jwt(self):
        resp = self.client.get("/auth/saml/session?token=valid-otp")
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["email"] == "alice@acme.com"
        assert data["tenant_id"] == "acme"

    def test_session_invalid_otp_returns_401(self):
        resp = self.client.get("/auth/saml/session?token=bad-token")
        assert resp.status_code == 401

    def test_verify_valid_jwt(self):
        resp = self.client.get(
            "/auth/saml/verify",
            headers={"Authorization": "Bearer valid.jwt.token"},
        )
        assert resp.status_code == 200
        assert resp.json()["sub"] == "alice@acme.com"

    def test_verify_invalid_jwt_returns_401(self):
        resp = self.client.get(
            "/auth/saml/verify",
            headers={"Authorization": "Bearer invalid.jwt"},
        )
        assert resp.status_code == 401

    def test_verify_missing_header_returns_401(self):
        resp = self.client.get("/auth/saml/verify")
        assert resp.status_code == 401

    def test_all_routes_return_503_when_saml_not_configured(self):
        from warden.main import app
        app.state.saml = None
        c = TestClient(app, raise_server_exceptions=True)
        for path in ["/auth/saml/metadata", "/auth/saml/login",
                     "/auth/saml/session?token=x", "/auth/saml/verify"]:
            resp = c.get(path)
            assert resp.status_code == 503, f"Expected 503 for {path}, got {resp.status_code}"


# ── Dummy IdP metadata (minimal valid SAML metadata XML) ─────────────────────

_DUMMY_IDP_XML = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://idp.example.com">
  <md:IDPSSODescriptor
      WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o4qne60TB3pqpG3BGNQE1s3pOAGVW3X3fRDpSwBSmFEsYFiuMkFJHHPsRmVpCOlT
HLx9wHNSakQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBtest==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""
