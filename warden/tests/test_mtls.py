"""
warden/tests/test_mtls.py
━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for warden.mtls — mTLS client-certificate enforcement middleware.

All tests run without Redis, real TLS, or external services.
MTLS_ENABLED and MTLS_ALLOWED_CNS are toggled via monkeypatch.
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

import warden.mtls as mtls_module
from warden.mtls import MTLSMiddleware, _cn_from_dn

# ── Shared test application ───────────────────────────────────────────────────

async def _ok(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


async def _health(request: Request) -> PlainTextResponse:
    return PlainTextResponse("healthy")


_app = Starlette(routes=[
    Route("/",       _ok,     methods=["GET"]),
    Route("/health", _health, methods=["GET"]),
    Route("/filter", _ok,     methods=["POST"]),
])
_app.add_middleware(MTLSMiddleware)

_client = TestClient(_app, raise_server_exceptions=True)


# ── _cn_from_dn ───────────────────────────────────────────────────────────────

def test_cn_from_dn_comma_format():
    assert _cn_from_dn("CN=proxy,O=ShadowWarden,C=US") == "proxy"


def test_cn_from_dn_slash_format():
    assert _cn_from_dn("/CN=analytics/O=ShadowWarden/C=US") == "analytics"


def test_cn_from_dn_uppercase_cn_key():
    assert _cn_from_dn("cn=warden,O=ShadowWarden") == "warden"


def test_cn_from_dn_no_cn_returns_none():
    assert _cn_from_dn("O=ShadowWarden,C=US") is None


def test_cn_from_dn_empty_string_returns_none():
    assert _cn_from_dn("") is None


# ── Middleware disabled ───────────────────────────────────────────────────────

def test_disabled_passes_all_requests(monkeypatch):
    """MTLS_ENABLED=false → every request is allowed regardless of cert headers."""
    monkeypatch.setattr(mtls_module, "_MTLS_ENABLED", False)
    resp = _client.get("/")
    assert resp.status_code == 200


def test_disabled_no_cert_still_passes(monkeypatch):
    monkeypatch.setattr(mtls_module, "_MTLS_ENABLED", False)
    resp = _client.get("/", headers={})
    assert resp.status_code == 200


# ── Middleware enabled — exempt paths ─────────────────────────────────────────

def test_health_exempt_no_cert_needed(monkeypatch):
    """/health skips cert check even when MTLS_ENABLED=true."""
    monkeypatch.setattr(mtls_module, "_MTLS_ENABLED", True)
    resp = _client.get("/health")
    assert resp.status_code == 200


# ── Middleware enabled — cert required ────────────────────────────────────────

def test_no_cert_returns_403(monkeypatch):
    """No cert headers → 403 with descriptive message."""
    monkeypatch.setattr(mtls_module, "_MTLS_ENABLED", True)
    monkeypatch.setattr(mtls_module, "_ALLOWED_CNS", frozenset({"proxy"}))
    resp = _client.get("/")
    assert resp.status_code == 403
    assert "certificate" in resp.json()["detail"].lower()


def test_allowed_cn_with_success_verify_passes(monkeypatch):
    """Allowed CN + nginx SUCCESS header → 200."""
    monkeypatch.setattr(mtls_module, "_MTLS_ENABLED", True)
    monkeypatch.setattr(mtls_module, "_ALLOWED_CNS", frozenset({"proxy"}))
    resp = _client.get("/", headers={
        "X-Client-Cert-Subject": "CN=proxy,O=ShadowWarden,C=US",
        "X-Client-Cert-Verify":  "SUCCESS",
    })
    assert resp.status_code == 200


def test_disallowed_cn_returns_403(monkeypatch):
    """Valid cert, but CN not in allowlist → 403."""
    monkeypatch.setattr(mtls_module, "_MTLS_ENABLED", True)
    monkeypatch.setattr(mtls_module, "_ALLOWED_CNS", frozenset({"proxy"}))
    resp = _client.get("/", headers={
        "X-Client-Cert-Subject": "CN=attacker,O=Evil,C=XX",
        "X-Client-Cert-Verify":  "SUCCESS",
    })
    assert resp.status_code == 403
    assert "attacker" in resp.json()["detail"]


def test_failed_verify_returns_403(monkeypatch):
    """nginx reports FAILED verification → reject even if CN matches."""
    monkeypatch.setattr(mtls_module, "_MTLS_ENABLED", True)
    monkeypatch.setattr(mtls_module, "_ALLOWED_CNS", frozenset({"proxy"}))
    resp = _client.get("/", headers={
        "X-Client-Cert-Subject": "CN=proxy,O=ShadowWarden,C=US",
        "X-Client-Cert-Verify":  "FAILED",
    })
    assert resp.status_code == 403


def test_subject_without_verify_header_returns_403(monkeypatch):
    """Subject header present but no Verify header → reject (cannot trust subject)."""
    monkeypatch.setattr(mtls_module, "_MTLS_ENABLED", True)
    monkeypatch.setattr(mtls_module, "_ALLOWED_CNS", frozenset({"proxy"}))
    resp = _client.get("/", headers={
        "X-Client-Cert-Subject": "CN=proxy,O=ShadowWarden,C=US",
        # no X-Client-Cert-Verify
    })
    assert resp.status_code == 403


def test_analytics_cn_allowed(monkeypatch):
    """analytics service uses its CN to call /filter successfully."""
    monkeypatch.setattr(mtls_module, "_MTLS_ENABLED", True)
    monkeypatch.setattr(mtls_module, "_ALLOWED_CNS",
                        frozenset({"proxy", "analytics", "app"}))
    resp = _client.post("/filter", json={}, headers={
        "X-Client-Cert-Subject": "CN=analytics,O=ShadowWarden,C=US",
        "X-Client-Cert-Verify":  "SUCCESS",
    })
    assert resp.status_code == 200


def test_slash_format_dn_is_accepted(monkeypatch):
    """OpenSSL slash-separated DN format is parsed correctly."""
    monkeypatch.setattr(mtls_module, "_MTLS_ENABLED", True)
    monkeypatch.setattr(mtls_module, "_ALLOWED_CNS", frozenset({"app"}))
    resp = _client.get("/", headers={
        "X-Client-Cert-Subject": "/CN=app/O=ShadowWarden/C=US",
        "X-Client-Cert-Verify":  "SUCCESS",
    })
    assert resp.status_code == 200
