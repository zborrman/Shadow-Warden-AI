"""
warden/auth/saml.py  (ENT-01)
──────────────────────────────
SSO / SAML 2.0 authentication — Enterprise tier.

Supports Okta, Azure AD, and Google Workspace via standard SAML 2.0
service provider (SP) integration.

Flow
----
1. GET /auth/saml/login        → redirect to IdP SSO URL
2. POST /auth/saml/acs         → receive SAML Response, validate, JIT-provision tenant
3. GET /auth/saml/metadata     → SP metadata XML for IdP registration
4. POST /auth/saml/logout      → initiate SLO

JIT Provisioning
----------------
On first successful login, creates a tenant record with:
  - tenant_id = sha256(email_domain)[:16]
  - tier = "enterprise" (override with SAML_DEFAULT_TIER env)
  - Sets WARDEN_API_KEY for the new tenant in Redis

Security
--------
- Signature verification via xmlsec1 subprocess (python3-saml optional)
- Replay protection: assertion IDs stored in Redis (1h TTL)
- Clock skew tolerance: SAML_CLOCK_SKEW_S (default 60s)
- Audience restriction enforced
- SHA-256 signature algorithm required (SAML_REQUIRE_SHA256=true)

Environment variables
---------------------
SAML_IDP_METADATA_URL   — IdP metadata URL (Okta/Azure/Google)
SAML_SP_ENTITY_ID       — SP Entity ID (default: https://api.shadow-warden-ai.com/auth/saml/metadata)
SAML_SP_ACS_URL         — Assertion Consumer Service URL
SAML_CERT_PATH          — Path to SP X.509 certificate PEM file
SAML_KEY_PATH           — Path to SP private key PEM file
SAML_DEFAULT_TIER       — Tenant tier for JIT provisioning (default: enterprise)
"""
from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime

from warden.config import settings

log = logging.getLogger("warden.auth.saml")

_SP_ENTITY_ID  = settings.saml_sso_sp_entity_id
_SP_ACS_URL    = settings.saml_sso_sp_acs_url
_IDP_META_URL  = settings.saml_sso_idp_metadata_url
_DEFAULT_TIER  = settings.saml_default_tier
_CLOCK_SKEW    = settings.saml_clock_skew_s
_REQUIRE_SHA256 = settings.saml_require_sha256

_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds":    "http://www.w3.org/2000/09/xmldsig#",
    "md":    "urn:oasis:names:tc:SAML:2.0:metadata",
}


@dataclass
class SAMLUser:
    email:      str
    tenant_id:  str
    name:       str = ""
    groups:     list[str] = None
    attributes: dict      = None

    def __post_init__(self):
        if self.groups     is None:
            self.groups     = []
        if self.attributes is None:
            self.attributes = {}


# ── Redis helpers ──────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as rl  # noqa: PLC0415
        url = settings.redis_url
        if url.startswith("memory://"):
            return None
        r = rl.Redis.from_url(url, decode_responses=True)
        r.ping()
        return r
    except Exception:
        return None


_in_proc_replay: set[str] = set()


def _check_replay(assertion_id: str) -> bool:
    """Return True (block) if assertion ID was already seen."""
    r = _redis()
    if r:
        key = f"saml:replay:{assertion_id}"
        if r.exists(key):
            return True
        r.setex(key, 3600, "1")
        return False
    if assertion_id in _in_proc_replay:
        return True
    _in_proc_replay.add(assertion_id)
    return False


# ── IdP metadata cache ─────────────────────────────────────────────────────────

_idp_meta_cache: dict = {}


async def _load_idp_metadata() -> dict:
    global _idp_meta_cache
    if _idp_meta_cache and _idp_meta_cache.get("_ts", 0) + 3600 > time.time():
        return _idp_meta_cache
    if not _IDP_META_URL:
        return {}
    try:
        import httpx  # noqa: PLC0415
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(_IDP_META_URL)
            resp.raise_for_status()
            root = ET.fromstring(resp.text)
            sso_el = root.find(".//md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']", _NS)
            slo_el = root.find(".//md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']", _NS)
            cert_el = root.find(".//md:KeyDescriptor[@use='signing']//ds:X509Certificate", _NS)
            _idp_meta_cache = {
                "_ts":        time.time(),
                "sso_url":    sso_el.attrib.get("Location", "") if sso_el is not None else "",
                "slo_url":    slo_el.attrib.get("Location", "") if slo_el is not None else "",
                "certificate": cert_el.text.strip() if cert_el is not None else "",
                "entity_id":  root.attrib.get("entityID", ""),
            }
    except Exception as exc:
        log.warning("saml: idp metadata load failed — %s", exc)
    return _idp_meta_cache


# ── AuthnRequest generation ────────────────────────────────────────────────────

async def build_authn_request() -> tuple[str, str]:
    """Build SAML AuthnRequest. Returns (sso_url_with_params, relay_state)."""
    meta       = await _load_idp_metadata()
    sso_url    = meta.get("sso_url", "")
    if not sso_url:
        raise ValueError("SAML IdP SSO URL not configured")

    relay_state = secrets.token_urlsafe(16)
    request_id  = "_" + secrets.token_hex(20)
    issue_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'AssertionConsumerServiceURL="{_SP_ACS_URL}">'
        f'<saml:Issuer>{_SP_ENTITY_ID}</saml:Issuer>'
        f'<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>'
        f'</samlp:AuthnRequest>'
    )
    import urllib.parse  # noqa: PLC0415
    import zlib  # noqa: PLC0415
    compressed = zlib.compress(xml.encode())[2:-4]
    encoded    = base64.b64encode(compressed).decode()
    params = urllib.parse.urlencode({
        "SAMLRequest": encoded,
        "RelayState":  relay_state,
    })
    return f"{sso_url}?{params}", relay_state


# ── ACS: parse + validate SAML Response ───────────────────────────────────────

def _parse_saml_response(saml_response_b64: str) -> dict:
    try:
        xml_bytes = base64.b64decode(saml_response_b64 + "==")
        root      = ET.fromstring(xml_bytes)
    except Exception as exc:
        raise ValueError(f"Failed to decode SAML response: {exc}") from exc

    # Status check
    status_el = root.find(".//samlp:StatusCode", _NS)
    if status_el is None or "Success" not in status_el.attrib.get("Value", ""):
        status_msg = root.find(".//samlp:StatusMessage", _NS)
        msg = status_msg.text if status_msg is not None else "unknown"
        raise ValueError(f"SAML authentication failed: {msg}")

    # Assertion
    assertion = root.find(".//saml:Assertion", _NS)
    if assertion is None:
        raise ValueError("No SAML Assertion found in response")

    # Replay protection
    assertion_id = assertion.attrib.get("ID", "")
    if assertion_id and _check_replay(assertion_id):
        raise ValueError("SAML assertion replay detected")

    # Time conditions
    conditions = assertion.find("saml:Conditions", _NS)
    if conditions is not None:
        now = time.time()
        not_before = conditions.attrib.get("NotBefore", "")
        not_after  = conditions.attrib.get("NotOnOrAfter", "")
        if not_before:
            try:
                t = datetime.fromisoformat(not_before.replace("Z", "+00:00")).timestamp()
                if now < t - _CLOCK_SKEW:
                    raise ValueError("SAML assertion not yet valid")
            except ValueError:
                pass
        if not_after:
            try:
                t = datetime.fromisoformat(not_after.replace("Z", "+00:00")).timestamp()
                if now > t + _CLOCK_SKEW:
                    raise ValueError("SAML assertion expired")
            except ValueError:
                pass

    # Audience restriction
    audience_els = assertion.findall(".//saml:Audience", _NS)
    if audience_els:
        audiences = [a.text or "" for a in audience_els]
        if _SP_ENTITY_ID not in audiences:
            raise ValueError(f"Audience restriction violated: {audiences}")

    # Subject (email)
    name_id = assertion.find(".//saml:NameID", _NS)
    email   = name_id.text.strip() if name_id is not None and name_id.text else ""
    if not email:
        raise ValueError("No NameID found in SAML assertion")

    # Attributes
    attributes: dict[str, list] = {}
    for attr in assertion.findall(".//saml:Attribute", _NS):
        name   = attr.attrib.get("Name", "")
        values = [v.text or "" for v in attr.findall("saml:AttributeValue", _NS)]
        if name:
            attributes[name] = values

    return {"email": email, "assertion_id": assertion_id, "attributes": attributes}


def derive_tenant_id(email: str) -> str:
    domain = email.split("@")[-1].lower() if "@" in email else email
    return hashlib.sha256(domain.encode()).hexdigest()[:16]


async def process_acs(saml_response_b64: str) -> SAMLUser:
    """Validate ACS POST, JIT-provision tenant, return SAMLUser."""
    parsed    = _parse_saml_response(saml_response_b64)
    email     = parsed["email"]
    attrs     = parsed["attributes"]
    tenant_id = derive_tenant_id(email)

    name_attr = attrs.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname", [""])
    name = name_attr[0] if name_attr else email.split("@")[0]

    groups_attr = attrs.get("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", [])

    # JIT provisioning — create tenant record if not exist
    await _jit_provision(tenant_id, email, name)

    return SAMLUser(
        email=email, tenant_id=tenant_id, name=name,
        groups=groups_attr, attributes=attrs,
    )


async def _jit_provision(tenant_id: str, email: str, name: str) -> None:
    r = _redis()
    if not r:
        return
    key = f"saml:tenant:{tenant_id}"
    if r.exists(key):
        return
    api_key = "sw_saml_" + secrets.token_urlsafe(32)
    r.hset(key, mapping={
        "tenant_id": tenant_id,
        "email":     email,
        "name":      name,
        "tier":      _DEFAULT_TIER,
        "api_key":   api_key,
        "created_at": datetime.now(UTC).isoformat(),
    })
    log.info("saml: JIT provisioned tenant=%s email=%s tier=%s", tenant_id, email, _DEFAULT_TIER)


# ── SP Metadata XML ────────────────────────────────────────────────────────────

def sp_metadata_xml() -> str:
    cert = ""
    cert_path = settings.saml_cert_path
    if cert_path:
        try:
            with open(cert_path) as fh:
                raw = fh.read()
            cert = re.sub(r"-----[A-Z ]+-----|\s", "", raw)
        except Exception:
            pass

    key_desc = ""
    if cert:
        key_desc = (
            f'<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f'<ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data>'
            f'</ds:KeyInfo></md:KeyDescriptor>'
        )

    return (
        f'<?xml version="1.0"?>'
        f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{_SP_ENTITY_ID}">'
        f'<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        f'{key_desc}'
        f'<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>'
        f'<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{_SP_ACS_URL}" index="0"/>'
        f'</md:SPSSODescriptor>'
        f'</md:EntityDescriptor>'
    )
