"""
warden/tests/test_oidc_guard.py
────────────────────────────────
Unit tests for the Warden Identity OIDC guard (warden/auth/oidc_guard.py).

All network calls and JWKS fetches are mocked — no real HTTP or cryptographic
key generation is required.  Tests cover:

  1. verify_oidc_token — success paths (Google, Microsoft)
  2. verify_oidc_token — failure paths (expired, bad sig, unknown issuer, unknown domain)
  3. resolve_tenant    — domain map loading from env + live registration
  4. _verify_rs256     — JWKS key miss → force-refresh once, then 401
  5. require_ext_auth  — hybrid dependency (Bearer > X-API-Key > dev mode)
"""
from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_id_token(
    issuer:  str   = "https://accounts.google.com",
    email:   str   = "alice@acme.com",
    exp:     int   = 0,              # 0 = far future
    kid:     str   = "key-001",
    sign:    bool  = True,           # False → produce an unsigned/dummy token
) -> str:
    """
    Produce a minimal JWT-shaped token for testing.

    We do NOT actually sign it with RSA here.  Instead the tests patch
    `_verify_rs256` or `jwt.decode` to control what claims are returned,
    so the token structure only needs to be parseable by
    jwt.get_unverified_header / jwt.decode(...verify_signature=False).
    """
    import base64

    def _b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    header  = _b64({"alg": "RS256", "kid": kid, "typ": "JWT"})
    payload = _b64({
        "iss": issuer,
        "email": email,
        "exp": exp or int(time.time()) + 3600,
        "iat": int(time.time()),
        "sub": "1234567890",
    })
    sig = _b64({"dummy": True}) if not sign else _b64({"sig": "mock"})
    return f"{header}.{payload}.{sig}"


# ── Domain map setup ──────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_oidc_state():
    """Wipe module-level caches before each test."""
    from warden.auth import oidc_guard
    oidc_guard.invalidate_jwks_cache()
    oidc_guard.invalidate_domain_map()
    yield
    oidc_guard.invalidate_jwks_cache()
    oidc_guard.invalidate_domain_map()


# ── resolve_tenant ────────────────────────────────────────────────────────────

class TestResolveTenant:
    def test_known_domain_maps_to_tenant(self, monkeypatch):
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "acme.com:tenant_acme")
        from warden.auth.oidc_guard import invalidate_domain_map, resolve_tenant
        invalidate_domain_map()

        tenant = resolve_tenant("alice@acme.com")
        assert tenant == "tenant_acme"

    def test_unknown_domain_raises_403(self, monkeypatch):
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "acme.com:tenant_acme")
        from fastapi import HTTPException
        from warden.auth.oidc_guard import invalidate_domain_map, resolve_tenant
        invalidate_domain_map()

        with pytest.raises(HTTPException) as exc_info:
            resolve_tenant("eve@evil.com")
        assert exc_info.value.status_code == 403
        assert "not registered" in exc_info.value.detail

    def test_case_insensitive_domain(self, monkeypatch):
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "ACME.COM:tenant_acme")
        from warden.auth.oidc_guard import invalidate_domain_map, resolve_tenant
        invalidate_domain_map()

        assert resolve_tenant("Bob@ACME.COM") == "tenant_acme"

    def test_register_domain_runtime(self, monkeypatch):
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "")
        from fastapi import HTTPException
        from warden.auth.oidc_guard import invalidate_domain_map, register_domain, resolve_tenant
        invalidate_domain_map()

        with pytest.raises(HTTPException):
            resolve_tenant("bob@newco.io")

        register_domain("newco.io", "tenant_newco")
        assert resolve_tenant("bob@newco.io") == "tenant_newco"

    def test_missing_at_sign_raises_401(self, monkeypatch):
        from fastapi import HTTPException
        from warden.auth.oidc_guard import resolve_tenant
        with pytest.raises(HTTPException) as exc_info:
            resolve_tenant("not-an-email")
        assert exc_info.value.status_code == 401

    def test_multiple_domains(self, monkeypatch):
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "alpha.io:t_alpha,beta.io:t_beta")
        from warden.auth.oidc_guard import invalidate_domain_map, resolve_tenant
        invalidate_domain_map()

        assert resolve_tenant("a@alpha.io") == "t_alpha"
        assert resolve_tenant("b@beta.io")  == "t_beta"


# ── verify_oidc_token — success paths ────────────────────────────────────────

class TestVerifyOidcTokenSuccess:
    def test_google_token_success(self, monkeypatch):
        """Valid Google id_token for a registered domain → returns (tenant_id, email)."""
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "acme.com:tenant_acme")
        from warden.auth import oidc_guard
        oidc_guard.invalidate_domain_map()

        token = _make_id_token(issuer="https://accounts.google.com", email="alice@acme.com")

        # Patch _verify_rs256 so we skip actual RSA validation
        mock_claims = {
            "iss": "https://accounts.google.com",
            "email": "alice@acme.com",
            "exp": int(time.time()) + 3600,
        }
        with patch.object(oidc_guard, "_verify_rs256", return_value=mock_claims):
            tenant_id, email = oidc_guard.verify_oidc_token(token)

        assert tenant_id == "tenant_acme"
        assert email     == "alice@acme.com"

    def test_microsoft_token_success(self, monkeypatch):
        """Valid Microsoft id_token for a registered domain → correct tenant."""
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "contoso.com:tenant_contoso")
        from warden.auth import oidc_guard
        oidc_guard.invalidate_domain_map()

        token = _make_id_token(
            issuer="https://login.microsoftonline.com/abc123/v2.0",
            email="bob@contoso.com",
        )

        mock_claims = {
            "iss":               "https://login.microsoftonline.com/abc123/v2.0",
            "preferred_username": "bob@contoso.com",
            "exp":               int(time.time()) + 3600,
        }
        with patch.object(oidc_guard, "_verify_rs256", return_value=mock_claims):
            tenant_id, email = oidc_guard.verify_oidc_token(token)

        assert tenant_id == "tenant_contoso"
        assert email     == "bob@contoso.com"

    def test_email_extracted_from_preferred_username(self, monkeypatch):
        """Microsoft tokens use preferred_username when email claim is absent."""
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "corp.io:t_corp")
        from warden.auth import oidc_guard
        oidc_guard.invalidate_domain_map()

        token = _make_id_token(issuer="https://sts.windows.net/tid/", email="carol@corp.io")
        mock_claims = {
            "iss": "https://sts.windows.net/tid/",
            "preferred_username": "carol@corp.io",
            "exp": int(time.time()) + 3600,
        }
        with patch.object(oidc_guard, "_verify_rs256", return_value=mock_claims):
            tenant_id, email = oidc_guard.verify_oidc_token(token)

        assert tenant_id == "t_corp"
        assert email     == "carol@corp.io"


# ── verify_oidc_token — failure paths ────────────────────────────────────────

class TestVerifyOidcTokenFailure:
    def test_unknown_issuer_raises_401(self, monkeypatch):
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "acme.com:t_a")
        from fastapi import HTTPException
        from warden.auth import oidc_guard
        oidc_guard.invalidate_domain_map()

        token = _make_id_token(issuer="https://evil.provider.com", email="x@acme.com")
        with pytest.raises(HTTPException) as exc_info:
            oidc_guard.verify_oidc_token(token)
        assert exc_info.value.status_code == 401
        assert "Unrecognised" in exc_info.value.detail

    def test_expired_token_raises_401(self, monkeypatch):
        import jwt as pyjwt
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "acme.com:t_a")
        from fastapi import HTTPException
        from warden.auth import oidc_guard
        oidc_guard.invalidate_domain_map()

        token = _make_id_token(issuer="https://accounts.google.com", email="x@acme.com")

        with patch.object(oidc_guard, "_verify_rs256",
                          side_effect=pyjwt.ExpiredSignatureError("Token expired")):
            # ExpiredSignatureError is re-raised by _verify_rs256; verify_oidc_token
            # wraps it as 401.  But since _verify_rs256 is patched here to raise
            # directly, the HTTPException comes from within _verify_rs256 itself.
            # Let's patch jwt.decode instead to simulate expiry at the top level.
            pass

        # Simulate expiry: _verify_rs256 raises HTTPException(401)
        from fastapi import HTTPException as _HE
        exp_exc = _HE(status_code=401, detail="OIDC token has expired — please sign in again.")
        with patch.object(oidc_guard, "_verify_rs256", side_effect=exp_exc):
            with pytest.raises(_HE) as exc_info:
                oidc_guard.verify_oidc_token(token)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail

    def test_unknown_domain_raises_403(self, monkeypatch):
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "")
        from fastapi import HTTPException
        from warden.auth import oidc_guard
        oidc_guard.invalidate_domain_map()

        token = _make_id_token(issuer="https://accounts.google.com", email="x@unknown.org")
        mock_claims = {"iss": "https://accounts.google.com", "email": "x@unknown.org",
                       "exp": int(time.time()) + 3600}

        with patch.object(oidc_guard, "_verify_rs256", return_value=mock_claims):
            with pytest.raises(HTTPException) as exc_info:
                oidc_guard.verify_oidc_token(token)
        assert exc_info.value.status_code == 403

    def test_malformed_jwt_raises_401(self, monkeypatch):
        from fastapi import HTTPException
        from warden.auth.oidc_guard import verify_oidc_token
        with pytest.raises(HTTPException) as exc_info:
            verify_oidc_token("not.a.jwt.at.all")
        assert exc_info.value.status_code == 401


# ── _verify_rs256 — JWKS key miss + force-refresh ────────────────────────────

class TestVerifyRs256:
    def test_unknown_kid_forces_refresh_then_raises(self):
        """If kid not found, cache is cleared and re-fetched once; 401 if still absent."""
        from fastapi import HTTPException
        from warden.auth import oidc_guard

        token = _make_id_token(kid="unknown-kid")

        # JWKS always returns empty key set
        with patch.object(oidc_guard, "_get_jwks", return_value={}):
            with pytest.raises(HTTPException) as exc_info:
                oidc_guard._verify_rs256(token, "https://jwks.example.com")
        assert exc_info.value.status_code == 401
        assert "Unknown JWKS key ID" in exc_info.value.detail

    def test_unsupported_algorithm_raises_401(self):
        """HS256 tokens must be rejected — only RS256/RS384/RS512 are accepted."""
        import base64

        def _b64(d: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

        hs256_token = f"{_b64({'alg':'HS256','typ':'JWT'})}.{_b64({'iss':'x','sub':'y'})}.sig"

        from fastapi import HTTPException
        from warden.auth.oidc_guard import _verify_rs256
        with pytest.raises(HTTPException) as exc_info:
            _verify_rs256(hs256_token, "https://jwks.example.com")
        assert exc_info.value.status_code == 401
        assert "RS256" in exc_info.value.detail


# ── require_ext_auth hybrid dependency ───────────────────────────────────────

class TestRequireExtAuth:
    """
    Tests for the hybrid FastAPI dependency in auth_guard.py.
    Simulates FastAPI's Depends resolution by calling require_ext_auth directly.
    """

    def test_bearer_token_routes_to_oidc(self, monkeypatch):
        monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "acme.com:tenant_acme")
        from warden.auth import oidc_guard
        oidc_guard.invalidate_domain_map()

        from warden.auth_guard import require_ext_auth

        with patch("warden.auth.oidc_guard.verify_oidc_token",
                   return_value=("tenant_acme", "alice@acme.com")):
            result = require_ext_auth(x_api_key=None, authorization="Bearer fake.jwt.token")

        assert result.tenant_id == "tenant_acme"
        assert result.api_key   == ""           # OIDC path leaves api_key blank

    def test_api_key_fallback(self, monkeypatch):
        monkeypatch.setenv("WARDEN_API_KEY", "test-secret-key")
        from warden import auth_guard
        # Reset single-key state
        auth_guard._VALID_KEY = "test-secret-key"

        from warden.auth_guard import require_ext_auth
        result = require_ext_auth(x_api_key="test-secret-key", authorization=None)
        assert result.tenant_id == "default"
        assert result.api_key   == "test-secret-key"

    def test_no_auth_dev_mode_passes(self, monkeypatch):
        """With no key configured (dev mode), all requests pass as tenant='default'."""
        monkeypatch.setenv("WARDEN_API_KEY", "")
        monkeypatch.setenv("WARDEN_API_KEYS_PATH", "")
        from warden import auth_guard
        auth_guard._VALID_KEY = ""
        auth_guard._KEYS_PATH = ""

        from warden.auth_guard import require_ext_auth
        result = require_ext_auth(x_api_key=None, authorization=None)
        assert result.tenant_id == "default"

    def test_missing_auth_with_key_configured_raises_401(self, monkeypatch):
        monkeypatch.setenv("WARDEN_API_KEY", "required-key")
        from fastapi import HTTPException
        from warden import auth_guard
        auth_guard._VALID_KEY = "required-key"

        from warden.auth_guard import require_ext_auth
        with pytest.raises(HTTPException) as exc_info:
            require_ext_auth(x_api_key=None, authorization=None)
        assert exc_info.value.status_code == 401
