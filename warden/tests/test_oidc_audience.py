"""
OIDC id_token audience must be bound to our own OAuth client (vuln-0005 / CWE-1174).

Strix authenticated as another org's tenant by presenting a Google-signed
id_token minted for an UNRELATED OAuth client that merely carried the victim's
email — the verifier used options={"verify_aud": False}. `_verify_rs256` now
verifies `aud` against OIDC_ALLOWED_AUDIENCES and fails closed when unconfigured.
"""
from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from warden.auth import oidc_guard

_JWKS_URL = "https://jwks.example.com"
_OUR_CLIENT = "our-extension.apps.googleusercontent.com"
_ATTACKER_CLIENT = "attacker-unrelated-client.apps.googleusercontent.com"


def _rsa_token(aud: str, kid: str = "k1"):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tok = jwt.encode(
        {
            "iss": "https://accounts.google.com",
            "email": "ceo@acme.com",
            "aud": aud,
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        },
        priv,
        algorithm="RS256",
        headers={"kid": kid},
    )
    return tok, priv.public_key()


@pytest.fixture(autouse=True)
def _reset():
    oidc_guard.invalidate_jwks_cache()
    yield
    oidc_guard.invalidate_jwks_cache()


def test_missing_audience_config_fails_closed(monkeypatch):
    monkeypatch.delenv("OIDC_ALLOWED_AUDIENCES", raising=False)
    tok, pub = _rsa_token(_OUR_CLIENT)
    with pytest.raises(HTTPException) as ei, \
         mock_jwks(monkeypatch, pub):
        oidc_guard._verify_rs256(tok, _JWKS_URL)
    assert ei.value.status_code == 401
    assert "audience not configured" in ei.value.detail


def test_foreign_client_audience_rejected(monkeypatch):
    """The exact PoC: a token minted for an unrelated OAuth client is rejected."""
    monkeypatch.setenv("OIDC_ALLOWED_AUDIENCES", _OUR_CLIENT)
    tok, pub = _rsa_token(_ATTACKER_CLIENT)
    with pytest.raises(HTTPException) as ei, mock_jwks(monkeypatch, pub):
        oidc_guard._verify_rs256(tok, _JWKS_URL)
    assert ei.value.status_code == 401


def test_matching_audience_accepted(monkeypatch):
    monkeypatch.setenv("OIDC_ALLOWED_AUDIENCES", f"other-client,{_OUR_CLIENT}")
    tok, pub = _rsa_token(_OUR_CLIENT)
    with mock_jwks(monkeypatch, pub):
        claims = oidc_guard._verify_rs256(tok, _JWKS_URL)
    assert claims["email"] == "ceo@acme.com"


def mock_jwks(monkeypatch, pub_key):
    """Context manager: _get_jwks returns our public key under kid 'k1'."""
    import contextlib

    @contextlib.contextmanager
    def _cm():
        monkeypatch.setattr(oidc_guard, "_get_jwks", lambda url: {"k1": pub_key})
        yield

    return _cm()
