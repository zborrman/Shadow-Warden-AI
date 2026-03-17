"""
warden/mtls.py
━━━━━━━━━━━━━━
Starlette middleware that enforces mTLS client-certificate verification.

Deployment modes
────────────────
Mode A — nginx upstream TLS termination (default for Docker Compose):
    nginx verifies the client cert and forwards the result as HTTP headers::

        ssl_client_certificate  /etc/nginx/certs/ca.crt;
        ssl_verify_client       on;
        proxy_set_header        X-Client-Cert-Subject  $ssl_client_s_dn;
        proxy_set_header        X-Client-Cert-Verify   $ssl_client_verify;

    Warden's uvicorn does NOT need --ssl-* flags in this mode.

Mode B — direct uvicorn TLS (uvicorn owns the socket):
    Start uvicorn with::

        --ssl-certfile /certs/warden.crt
        --ssl-keyfile  /certs/warden.key
        --ssl-ca-certs /certs/ca.crt
        --ssl-cert-reqs 2          # ssl.CERT_REQUIRED

    The middleware reads the peer cert from request.scope["ssl"].

Environment variables
─────────────────────
MTLS_ENABLED       true | false  (default false — disabled in dev/CI)
MTLS_ALLOWED_CNS   comma-separated Common Names of authorised callers
                   (default "proxy,analytics,app")
"""
from __future__ import annotations

import logging
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

log = logging.getLogger("warden.mtls")

_MTLS_ENABLED: bool = os.getenv("MTLS_ENABLED", "false").lower() == "true"

# nginx header set after ssl_verify_client
_SUBJECT_HEADER = "X-Client-Cert-Subject"   # DN string, e.g. "CN=proxy,O=…"
_VERIFY_HEADER  = "X-Client-Cert-Verify"    # "SUCCESS" | "FAILED" | "NONE"

_ALLOWED_CNS: frozenset[str] = frozenset(
    s.strip()
    for s in os.getenv("MTLS_ALLOWED_CNS", "proxy,analytics,app").split(",")
    if s.strip()
)

# Internal probe paths that don't carry client certs — exempt from enforcement
_EXEMPT_PATHS: frozenset[str] = frozenset({"/health", "/metrics", "/demo/filter"})


class MTLSMiddleware(BaseHTTPMiddleware):
    """Enforce mTLS: every non-exempt request must come from an authorised
    internal service identified by its client-certificate CN."""

    async def dispatch(self, request: Request, call_next):
        if not _MTLS_ENABLED or request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        cn = _extract_cn(request)

        if cn is None:
            log.warning(
                "mTLS: rejected — no client certificate "
                "(path=%s remote=%s)",
                request.url.path,
                request.client.host if request.client else "unknown",
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Client certificate required."},
            )

        if cn not in _ALLOWED_CNS:
            log.warning(
                "mTLS: rejected — CN '%s' not in allowlist (path=%s)",
                cn, request.url.path,
            )
            return JSONResponse(
                status_code=403,
                content={"detail": f"Client certificate CN '{cn}' not authorised."},
            )

        log.debug("mTLS: OK — CN='%s' (path=%s)", cn, request.url.path)
        return await call_next(request)


# ── Extraction helpers ────────────────────────────────────────────────────────

def _extract_cn(request: Request) -> str | None:
    """Return the client CN from the first available source:

    1. nginx-forwarded headers (Mode A).
    2. uvicorn SSL socket peer cert (Mode B).
    """
    # Mode A: header forwarded by nginx after ssl_verify_client
    verify  = request.headers.get(_VERIFY_HEADER, "")
    subject = request.headers.get(_SUBJECT_HEADER, "")
    if subject and verify.upper() == "SUCCESS":
        return _cn_from_dn(subject)

    # Mode B: peer cert on uvicorn's SSL socket
    ssl_obj = request.scope.get("ssl")
    if ssl_obj is not None:
        try:
            peer = ssl_obj.getpeercert()
            if peer:
                for rdn in peer.get("subject", ()):
                    for attr, value in rdn:
                        if attr == "commonName":
                            return value
        except Exception:  # noqa: BLE001
            pass

    return None


def _cn_from_dn(dn: str) -> str | None:
    """Parse CN from an OpenSSL DN string.

    Accepts both comma-separated (RFC 2253) and slash-separated (OpenSSL)
    formats::

        "CN=proxy,O=ShadowWarden,C=US"
        "/CN=proxy/O=ShadowWarden/C=US"
    """
    if not dn:
        return None
    # Detect format by leading slash (OpenSSL) vs comma (RFC 2253)
    if dn.startswith("/"):
        for part in dn.split("/"):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:]
    else:
        for part in dn.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:]
    return None
