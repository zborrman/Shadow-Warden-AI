"""
warden/auth/saml_provider.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
SAML 2.0 Service Provider (SP) implementation for Shadow Warden AI.

Supports Okta, Microsoft Entra ID (Azure AD), Google Workspace, and any
SAML 2.0-compliant Identity Provider.

Flow
────
  1. Browser hits  GET  /auth/saml/login
     → SP builds AuthnRequest, redirects user to IdP login page

  2. IdP authenticates user, POSTs signed SAMLResponse to
     POST /auth/saml/acs  (Assertion Consumer Service)

  3. ACS validates X.509 signature, extracts NameID + attributes,
     writes a one-time token to Redis (30 s TTL), and redirects the
     browser to the Streamlit dashboard with ?token=<otp>

  4. Dashboard reads ?token from query string, calls
     GET  /auth/saml/session?token=<otp>  to exchange it for a JWT

  5. JWT is stored in st.session_state; all privileged dashboard calls
     include it as Bearer auth

Required environment variables
────────────────────────────────
  SAML_SP_ENTITY_ID      — your SP Entity ID, e.g. https://warden.example.com
  SAML_SP_ACS_URL        — ACS endpoint, e.g. https://warden.example.com/auth/saml/acs
  SAML_IDP_METADATA_URL  — IdP Metadata XML URL (Okta / Entra provide this)
         OR
  SAML_IDP_METADATA_XML  — Raw IdP metadata XML (alternative to URL)
  SAML_JWT_SECRET        — Secret for signing session JWTs (min 32 chars)

Optional
  SAML_ALLOWED_DOMAINS   — Comma-separated list of allowed email domains
                           (e.g. "acme.com,acmecorp.com").  Empty = all allowed.
  SAML_SESSION_TTL       — JWT lifetime in seconds (default: 28800 = 8 h)
  SAML_OTP_TTL           — One-time token lifetime in seconds (default: 30)

Dependency
────────────
  pip install python3-saml>=1.16.0 PyJWT>=2.8.0
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import time
import urllib.request
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_OTP_PREFIX  = "saml:otp:"
_OTP_TTL     = int(os.getenv("SAML_OTP_TTL", "30"))         # seconds
_SESSION_TTL = int(os.getenv("SAML_SESSION_TTL", "28800"))  # 8 hours

_JWT_SECRET     = os.getenv("SAML_JWT_SECRET", "")
_ALLOWED_DOMAINS: frozenset[str] = frozenset(
    d.strip() for d in os.getenv("SAML_ALLOWED_DOMAINS", "").split(",") if d.strip()
)

# ── Session data ──────────────────────────────────────────────────────────────

@dataclass
class SamlSession:
    email:      str
    name:       str
    groups:     list[str]
    tenant_id:  str
    expires_at: int          # UTC epoch seconds


# ── SAMLProvider ─────────────────────────────────────────────────────────────

class SAMLProvider:
    """
    Thin wrapper around python3-saml that integrates with the Warden
    Redis store for one-time tokens and issues PyJWT session tokens.

    Instantiated once at startup (if SAML is configured) and injected
    into the FastAPI app as ``app.state.saml``.
    """

    def __init__(self) -> None:
        self._settings = _build_saml_settings()
        self._redis: Any = None   # injected after Redis is available

    def attach_redis(self, redis_client: Any) -> None:
        self._redis = redis_client

    # ── SP Metadata XML ───────────────────────────────────────────────────────

    def get_metadata_xml(self) -> tuple[str, list[str]]:
        """Return (metadata_xml, errors).  Errors list is empty on success."""
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
            from onelogin.saml2.settings import OneLogin_Saml2_Settings
        except ImportError as exc:
            raise RuntimeError("python3-saml is not installed") from exc

        saml_settings = OneLogin_Saml2_Settings(settings=self._settings, sp_validation_only=True)
        meta = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(meta)
        return meta.decode() if isinstance(meta, bytes) else meta, errors

    # ── AuthnRequest redirect URL ─────────────────────────────────────────────

    def build_login_url(self, request_data: dict[str, Any], relay_state: str = "") -> str:
        """Return the IdP login URL for HTTP-Redirect binding."""
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
        except ImportError as exc:
            raise RuntimeError("python3-saml is not installed") from exc

        auth = OneLogin_Saml2_Auth(request_data, old_settings=self._settings)
        return auth.login(return_to=relay_state or None)

    # ── Process ACS POST ──────────────────────────────────────────────────────

    def process_response(
        self,
        request_data: dict[str, Any],
    ) -> SamlSession:
        """
        Validate the SAMLResponse POSTed to /auth/saml/acs.

        Returns a SamlSession on success.
        Raises ValueError with a user-safe message on validation failure.
        """
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
        except ImportError as exc:
            raise RuntimeError("python3-saml is not installed") from exc

        auth = OneLogin_Saml2_Auth(request_data, old_settings=self._settings)
        auth.process_response()

        errors = auth.get_errors()
        if errors:
            reason = auth.get_last_error_reason() or ", ".join(errors)
            log.warning("SAML ACS validation failed: %s", reason)
            raise ValueError(f"SAML validation error: {reason}")

        if not auth.is_authenticated():
            raise ValueError("SAML authentication failed — user not authenticated.")

        email = _extract_email(auth)
        if _ALLOWED_DOMAINS and email.split("@")[-1].lower() not in _ALLOWED_DOMAINS:
            log.warning("SAML login rejected — domain not allowed: %s", email)
            raise ValueError("Your email domain is not authorised for this service.")

        attributes = auth.get_attributes()
        name   = _first_attr(attributes, ["displayName", "cn", "name"]) or email
        groups = list(attributes.get("groups", attributes.get("memberOf", [])))
        # Tenant = first group that matches "warden_tenant_*", or "default"
        tenant = _extract_tenant(groups)

        session = SamlSession(
            email      = email,
            name       = name,
            groups     = groups,
            tenant_id  = tenant,
            expires_at = int(time.time()) + _SESSION_TTL,
        )
        log.info("SAML login accepted: email=%s tenant=%s", email, tenant)
        return session

    # ── One-time token (Redis) ────────────────────────────────────────────────

    def store_otp(self, session: SamlSession) -> str:
        """Store session in Redis under a random OTP; return the token."""
        if self._redis is None:
            raise RuntimeError("Redis not attached to SAMLProvider")
        token = secrets.token_urlsafe(32)
        key   = f"{_OTP_PREFIX}{token}"
        payload = json.dumps({
            "email":      session.email,
            "name":       session.name,
            "groups":     session.groups,
            "tenant_id":  session.tenant_id,
            "expires_at": session.expires_at,
        })
        self._redis.setex(key, _OTP_TTL, payload)
        return token

    def redeem_otp(self, token: str) -> SamlSession | None:
        """
        Exchange a one-time token for a SamlSession.
        Returns None if the token is invalid or expired.
        Token is deleted on first use (true one-time).
        """
        if self._redis is None:
            return None
        key  = f"{_OTP_PREFIX}{token}"
        raw  = self._redis.getdel(key)   # atomic get-and-delete (Redis 6.2+)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            return SamlSession(**data)
        except Exception:
            return None

    # ── JWT issuance ──────────────────────────────────────────────────────────

    def issue_jwt(self, session: SamlSession) -> str:
        """Return a signed JWT encoding the session."""
        if not _JWT_SECRET:
            raise RuntimeError("SAML_JWT_SECRET is not set")
        try:
            import jwt
        except ImportError as exc:
            raise RuntimeError("PyJWT is not installed") from exc

        payload = {
            "sub":  session.email,
            "name": session.name,
            "grp":  session.groups,
            "tid":  session.tenant_id,
            "exp":  session.expires_at,
            "iat":  int(time.time()),
        }
        return jwt.encode(payload, _JWT_SECRET, algorithm="HS256")

    def verify_jwt(self, token: str) -> dict[str, Any] | None:
        """Verify a JWT and return its payload, or None if invalid/expired."""
        if not _JWT_SECRET:
            return None
        try:
            import jwt
            return jwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
        except Exception:
            return None


# ── Settings builder ─────────────────────────────────────────────────────────

def _build_saml_settings() -> dict[str, Any]:
    sp_entity_id = os.getenv("SAML_SP_ENTITY_ID", "")
    acs_url      = os.getenv("SAML_SP_ACS_URL", "")

    if not sp_entity_id or not acs_url:
        raise RuntimeError(
            "SAML is not fully configured. "
            "Set SAML_SP_ENTITY_ID and SAML_SP_ACS_URL environment variables."
        )

    idp = _load_idp_metadata()

    return {
        "strict": True,
        "debug":  os.getenv("LOG_LEVEL", "info").lower() == "debug",
        "sp": {
            "entityId":                 sp_entity_id,
            "assertionConsumerService": {
                "url":     acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": "",
            "privateKey": "",
        },
        "idp": idp,
        "security": {
            "authnRequestsSigned":         False,
            "wantMessagesSigned":          True,
            "wantAssertionsSigned":        True,
            "wantAssertionsEncrypted":     False,
            "wantNameId":                  True,
            "wantNameIdEncrypted":         False,
            "signatureAlgorithm":
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm":
                "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def _load_idp_metadata() -> dict[str, Any]:
    """
    Parse IdP metadata from SAML_IDP_METADATA_URL or SAML_IDP_METADATA_XML.
    Returns a python3-saml compatible IdP settings dict.
    """
    xml = os.getenv("SAML_IDP_METADATA_XML", "")
    if not xml:
        url = os.getenv("SAML_IDP_METADATA_URL", "")
        if not url:
            raise RuntimeError(
                "Set SAML_IDP_METADATA_URL or SAML_IDP_METADATA_XML to configure the IdP."
            )
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310
                xml = resp.read().decode()
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch IdP metadata from {url}: {exc}") from exc

    try:
        from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
    except ImportError as exc:
        raise RuntimeError("python3-saml is not installed") from exc

    return OneLogin_Saml2_IdPMetadataParser.parse(xml)["idp"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_email(auth: Any) -> str:
    """Extract email from NameID or attributes (IdPs differ)."""
    name_id = auth.get_nameid() or ""
    if "@" in name_id:
        return name_id.lower().strip()
    attrs = auth.get_attributes()
    for key in ("email", "mail", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"):
        values = attrs.get(key, [])
        if values:
            return str(values[0]).lower().strip()
    raise ValueError("IdP did not provide an email address in the SAML assertion.")


def _first_attr(attrs: dict[str, list[str]], keys: list[str]) -> str:
    for k in keys:
        v = attrs.get(k, [])
        if v:
            return str(v[0])
    return ""


def _extract_tenant(groups: list[str]) -> str:
    """
    Map SAML groups → Warden tenant_id.

    Convention: a group named "warden_tenant_<id>" sets tenant = "<id>".
    Falls back to "default" if no such group is found.
    """
    prefix = "warden_tenant_"
    for g in groups:
        if g.startswith(prefix):
            return g[len(prefix):]
    return "default"


# ── Module-level singleton factory ────────────────────────────────────────────

_provider: SAMLProvider | None = None


def get_provider() -> SAMLProvider | None:
    """
    Return the SAMLProvider singleton, or None if SAML is not configured.
    Safe to call at startup — returns None rather than raising if env vars absent.
    """
    global _provider
    if _provider is not None:
        return _provider
    required = ("SAML_SP_ENTITY_ID", "SAML_SP_ACS_URL")
    if not all(os.getenv(k) for k in required):
        return None
    try:
        _provider = SAMLProvider()
        log.info("SAML 2.0 provider initialised (entity_id=%s)", os.getenv("SAML_SP_ENTITY_ID"))
        return _provider
    except Exception as exc:
        log.error("SAML provider failed to initialise: %s", exc)
        return None
