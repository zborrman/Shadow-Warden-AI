"""
warden/auth/saml_provider.py — the real, wired SAML 2.0 SP (mounted at
/auth/saml/* per warden/main.py). Companion to test_saml.py, which already
covers OTP store/redeem, JWT issue/verify, _extract_tenant, and the FastAPI
route layer with SAMLProvider mocked out entirely.

This file exercises the provider's own internals: real python3-saml settings
construction + metadata/login-URL generation (python3-saml is a pinned
dependency, warden/constraints.txt), process_response()'s branches (via a
fake OneLogin_Saml2_Auth — this module's own docstring says that's the
intended strategy, no live IdP needed), the IdP metadata loader, and
get_provider()'s singleton/fail-open behaviour.
"""
from __future__ import annotations

import sys
import time
from unittest.mock import MagicMock

import pytest

import warden.auth.saml_provider as mod
from warden.auth.saml_provider import SamlSession

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


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SAML_SP_ENTITY_ID", "https://warden.test")
    monkeypatch.setenv("SAML_SP_ACS_URL", "https://warden.test/auth/saml/acs")
    monkeypatch.setenv("SAML_IDP_METADATA_XML", _DUMMY_IDP_XML)
    monkeypatch.setenv("SAML_JWT_SECRET", "a" * 32)
    monkeypatch.delenv("SAML_IDP_METADATA_URL", raising=False)
    monkeypatch.delenv("SAML_ALLOWED_DOMAINS", raising=False)
    yield


class _FakeRedis:
    def __init__(self):
        self._store: dict[str, str] = {}

    def getdel(self, key: str) -> str | None:
        return self._store.pop(key, None)


def _bare_provider() -> mod.SAMLProvider:
    """Bypass __init__'s real settings build — matches test_saml.py's approach."""
    p = mod.SAMLProvider.__new__(mod.SAMLProvider)
    p._settings = {}
    p._redis = None
    return p


# ── __init__ / _build_saml_settings ──────────────────────────────────────────

class TestConstruction:
    def test_real_construction_succeeds(self):
        p = mod.SAMLProvider()
        assert p._settings["sp"]["entityId"] == "https://warden.test"
        assert p._settings["idp"]["entityId"] == "https://idp.example.com"
        assert p._redis is None

    def test_missing_sp_entity_id_raises(self, monkeypatch):
        monkeypatch.delenv("SAML_SP_ENTITY_ID", raising=False)
        with pytest.raises(RuntimeError, match="SAML is not fully configured"):
            mod.SAMLProvider()

    def test_missing_acs_url_raises(self, monkeypatch):
        monkeypatch.delenv("SAML_SP_ACS_URL", raising=False)
        with pytest.raises(RuntimeError, match="SAML is not fully configured"):
            mod.SAMLProvider()

    def test_attach_redis(self):
        p = _bare_provider()
        redis = _FakeRedis()
        p.attach_redis(redis)
        assert p._redis is redis


# ── get_metadata_xml / build_login_url (real python3-saml) ──────────────────

class TestMetadataAndLoginUrl:
    def test_metadata_xml_is_valid(self):
        p = mod.SAMLProvider()
        xml, errors = p.get_metadata_xml()
        assert errors == []
        assert "EntityDescriptor" in xml
        assert "warden.test" in xml

    def test_login_url_redirects_to_idp(self):
        p = mod.SAMLProvider()
        url = p.build_login_url(
            {
                "https": "on", "http_host": "warden.test",
                "script_name": "/auth/saml/login", "get_data": {}, "post_data": {},
            },
            relay_state="my-relay-state",
        )
        assert url.startswith("https://idp.example.com/sso?SAMLRequest=")

    def test_get_metadata_xml_without_python3_saml_raises(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "onelogin.saml2.settings", None)
        p = _bare_provider()
        with pytest.raises(RuntimeError, match="python3-saml is not installed"):
            p.get_metadata_xml()

    def test_build_login_url_without_python3_saml_raises(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "onelogin.saml2.auth", None)
        p = _bare_provider()
        with pytest.raises(RuntimeError, match="python3-saml is not installed"):
            p.build_login_url({})


# ── process_response (fake OneLogin_Saml2_Auth — no live IdP needed) ────────

class _FakeAuth:
    """Stand-in for onelogin.saml2.auth.OneLogin_Saml2_Auth."""

    errors: list[str] = []
    last_error_reason: str | None = None
    authenticated = True
    name_id = "user@acme.com"
    attributes: dict[str, list[str]] = {}

    def __init__(self, request_data, old_settings=None):
        pass

    def process_response(self):
        pass

    def get_errors(self):
        return type(self).errors

    def get_last_error_reason(self):
        return type(self).last_error_reason

    def is_authenticated(self):
        return type(self).authenticated

    def get_nameid(self):
        return type(self).name_id

    def get_attributes(self):
        return type(self).attributes


@pytest.fixture(autouse=True)
def _reset_fake_auth():
    _FakeAuth.errors = []
    _FakeAuth.last_error_reason = None
    _FakeAuth.authenticated = True
    _FakeAuth.name_id = "user@acme.com"
    _FakeAuth.attributes = {}
    yield


class TestProcessResponse:
    def test_success_returns_session(self, monkeypatch):
        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", _FakeAuth)
        _FakeAuth.attributes = {
            "displayName": ["Alice"],
            "groups": ["warden_tenant_acme", "everyone"],
        }
        p = _bare_provider()
        session = p.process_response({})
        assert session.email == "user@acme.com"
        assert session.name == "Alice"
        assert session.tenant_id == "acme"
        assert session.groups == ["warden_tenant_acme", "everyone"]
        assert session.expires_at > int(time.time())

    def test_validation_errors_raise_with_reason(self, monkeypatch):
        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", _FakeAuth)
        _FakeAuth.errors = ["invalid_response"]
        _FakeAuth.last_error_reason = "signature mismatch"
        p = _bare_provider()
        with pytest.raises(ValueError, match="signature mismatch"):
            p.process_response({})

    def test_validation_errors_without_reason_joins_error_codes(self, monkeypatch):
        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", _FakeAuth)
        _FakeAuth.errors = ["invalid_response", "destination_mismatch"]
        _FakeAuth.last_error_reason = None
        p = _bare_provider()
        with pytest.raises(ValueError, match="invalid_response, destination_mismatch"):
            p.process_response({})

    def test_not_authenticated_raises(self, monkeypatch):
        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", _FakeAuth)
        _FakeAuth.authenticated = False
        p = _bare_provider()
        with pytest.raises(ValueError, match="not authenticated"):
            p.process_response({})

    def test_domain_not_allowed_raises(self, monkeypatch):
        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", _FakeAuth)
        # _ALLOWED_DOMAINS is computed once at import; patch the module
        # attribute directly rather than reloading the module (a real reload
        # would leak into every other test sharing this cached module object).
        monkeypatch.setattr(mod, "_ALLOWED_DOMAINS", frozenset({"allowed.com"}))
        _FakeAuth.name_id = "user@notallowed.com"
        p = _bare_provider()
        with pytest.raises(ValueError, match="not authorised"):
            p.process_response({})

    def test_email_from_attributes_when_nameid_has_no_at(self, monkeypatch):
        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", _FakeAuth)
        _FakeAuth.name_id = "not-an-email"
        _FakeAuth.attributes = {"mail": ["fallback@acme.com"]}
        p = _bare_provider()
        session = p.process_response({})
        assert session.email == "fallback@acme.com"

    def test_no_email_anywhere_raises(self, monkeypatch):
        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", _FakeAuth)
        _FakeAuth.name_id = "not-an-email"
        _FakeAuth.attributes = {}
        p = _bare_provider()
        with pytest.raises(ValueError, match="did not provide an email"):
            p.process_response({})

    def test_no_display_name_falls_back_to_email(self, monkeypatch):
        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", _FakeAuth)
        _FakeAuth.attributes = {}
        p = _bare_provider()
        session = p.process_response({})
        assert session.name == "user@acme.com"

    def test_no_tenant_group_falls_back_to_default(self, monkeypatch):
        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", _FakeAuth)
        _FakeAuth.attributes = {"memberOf": ["everyone"]}
        p = _bare_provider()
        session = p.process_response({})
        assert session.tenant_id == "default"
        assert session.groups == ["everyone"]

    def test_without_python3_saml_raises(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "onelogin.saml2.auth", None)
        p = _bare_provider()
        with pytest.raises(RuntimeError, match="python3-saml is not installed"):
            p.process_response({})


# ── OTP (redis edge cases not covered by test_saml.py) ───────────────────────

class TestOtpEdgeCases:
    def test_redeem_without_redis_returns_none(self):
        p = _bare_provider()
        assert p.redeem_otp("anything") is None

    def test_store_without_redis_raises(self):
        p = _bare_provider()
        session = SamlSession(
            email="x@acme.com", name="X", groups=[], tenant_id="default",
            expires_at=int(time.time()) + 3600,
        )
        with pytest.raises(RuntimeError, match="Redis not attached"):
            p.store_otp(session)

    def test_redeem_malformed_payload_returns_none(self):
        p = _bare_provider()
        redis = _FakeRedis()
        redis._store["saml:otp:tok"] = "not valid json"
        p._redis = redis
        assert p.redeem_otp("tok") is None

    def test_redeem_payload_missing_fields_returns_none(self):
        p = _bare_provider()
        redis = _FakeRedis()
        redis._store["saml:otp:tok"] = "{}"  # valid JSON, wrong shape for SamlSession
        p._redis = redis
        assert p.redeem_otp("tok") is None


# ── JWT edge cases ─────────────────────────────────────────────────────────

class TestJwtEdgeCases:
    def test_issue_without_pyjwt_raises(self, monkeypatch):
        p = _bare_provider()
        session = SamlSession(
            email="x@acme.com", name="X", groups=[], tenant_id="default",
            expires_at=int(time.time()) + 3600,
        )
        monkeypatch.setitem(sys.modules, "jwt", None)
        with pytest.raises(RuntimeError, match="PyJWT is not installed"):
            p.issue_jwt(session)

    def test_verify_without_secret_returns_none(self, monkeypatch):
        monkeypatch.delenv("SAML_JWT_SECRET", raising=False)
        p = _bare_provider()
        assert p.verify_jwt("anything") is None


# ── _load_idp_metadata ────────────────────────────────────────────────────

class TestLoadIdpMetadata:
    def test_no_xml_no_url_raises(self, monkeypatch):
        monkeypatch.delenv("SAML_IDP_METADATA_XML", raising=False)
        monkeypatch.delenv("SAML_IDP_METADATA_URL", raising=False)
        with pytest.raises(RuntimeError, match="SAML_IDP_METADATA_URL"):
            mod._load_idp_metadata()

    def test_url_fetch_failure_raises(self, monkeypatch):
        monkeypatch.delenv("SAML_IDP_METADATA_XML", raising=False)
        monkeypatch.setenv("SAML_IDP_METADATA_URL", "https://idp.example.com/metadata")

        def _boom(url, timeout=10):
            raise OSError("connection refused")

        monkeypatch.setattr(mod.urllib.request, "urlopen", _boom)
        with pytest.raises(RuntimeError, match="Failed to fetch IdP metadata"):
            mod._load_idp_metadata()

    def test_url_fetch_success_parses_metadata(self, monkeypatch):
        monkeypatch.delenv("SAML_IDP_METADATA_XML", raising=False)
        monkeypatch.setenv("SAML_IDP_METADATA_URL", "https://idp.example.com/metadata")

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return _DUMMY_IDP_XML.encode()

        monkeypatch.setattr(mod.urllib.request, "urlopen", lambda url, timeout=10: _Resp())
        idp = mod._load_idp_metadata()
        assert idp["entityId"] == "https://idp.example.com"

    def test_xml_env_var_parses_metadata(self):
        idp = mod._load_idp_metadata()
        assert idp["entityId"] == "https://idp.example.com"

    def test_without_python3_saml_raises(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "onelogin.saml2.idp_metadata_parser", None)
        with pytest.raises(RuntimeError, match="python3-saml is not installed"):
            mod._load_idp_metadata()


# ── Helper functions ─────────────────────────────────────────────────────

class TestExtractEmail:
    def test_email_from_nameid(self):
        auth = MagicMock()
        auth.get_nameid.return_value = "Alice@Acme.com"
        assert mod._extract_email(auth) == "alice@acme.com"

    def test_email_from_attributes_mail_key(self):
        auth = MagicMock()
        auth.get_nameid.return_value = "not-an-email"
        auth.get_attributes.return_value = {"mail": ["Bob@Acme.com"]}
        assert mod._extract_email(auth) == "bob@acme.com"

    def test_email_from_schema_claim_key(self):
        auth = MagicMock()
        auth.get_nameid.return_value = ""
        auth.get_attributes.return_value = {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": ["c@acme.com"],
        }
        assert mod._extract_email(auth) == "c@acme.com"

    def test_no_email_raises(self):
        auth = MagicMock()
        auth.get_nameid.return_value = ""
        auth.get_attributes.return_value = {}
        with pytest.raises(ValueError, match="did not provide an email"):
            mod._extract_email(auth)


class TestFirstAttr:
    def test_returns_first_matching_key(self):
        assert mod._first_attr({"cn": ["Carl"]}, ["displayName", "cn"]) == "Carl"

    def test_returns_empty_when_no_key_matches(self):
        assert mod._first_attr({}, ["displayName", "cn"]) == ""


# ── get_provider() singleton / fail-open ─────────────────────────────────

class TestGetProvider:
    @pytest.fixture(autouse=True)
    def _reset_singleton(self):
        mod._provider = None
        yield
        mod._provider = None

    def test_returns_none_when_unconfigured(self, monkeypatch):
        monkeypatch.delenv("SAML_SP_ENTITY_ID", raising=False)
        assert mod.get_provider() is None

    def test_returns_provider_when_configured(self):
        p = mod.get_provider()
        assert p is not None
        assert isinstance(p, mod.SAMLProvider)

    def test_singleton_returns_same_instance(self):
        p1 = mod.get_provider()
        p2 = mod.get_provider()
        assert p1 is p2

    def test_construction_failure_returns_none(self, monkeypatch):
        monkeypatch.delenv("SAML_IDP_METADATA_XML", raising=False)
        monkeypatch.delenv("SAML_IDP_METADATA_URL", raising=False)
        # SP entity/ACS present (env fixture), but IdP metadata is unresolvable
        # -> SAMLProvider() raises inside get_provider()'s try/except -> None.
        assert mod.get_provider() is None
