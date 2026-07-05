"""
warden/net_guard.py
────────────────────
SSRF guard for outbound HTTP requests.

Any code path that fetches a **user-supplied URL** (webhook delivery, remote
attestation probes, etc.) must call :func:`assert_public_url` first.  The guard:

  • allows only ``http`` / ``https`` schemes (no ``file://``, ``gopher://``, …);
  • resolves the hostname to *every* A/AAAA record and rejects the request if
    *any* resolved address is loopback, private (RFC 1918 / ULA), link-local,
    cloud-metadata (``169.254.169.254`` / ``fd00:ec2::254``), multicast, or
    otherwise reserved — closing DNS-rebind and metadata-exfil vectors;
  • blocks raw-IP hosts in those same ranges without a DNS round-trip.

Set ``NET_GUARD_ALLOW_PRIVATE=true`` to disable the private-range check.  This
is intended for local dev / CI only (where a webhook may point at
``127.0.0.1``); it must never be set in production.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

__all__ = ["SSRFError", "assert_public_url", "is_public_url"]

_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Cloud metadata endpoints get an explicit block in addition to range checks,
# so the guard still holds if a provider moves them outside link-local space.
_METADATA_HOSTS = frozenset({
    "169.254.169.254",       # AWS / GCP / Azure / DigitalOcean IMDS
    "fd00:ec2::254",         # AWS IMDS over IPv6
    "metadata.google.internal",
})


class SSRFError(ValueError):
    """Raised when a URL is rejected as an SSRF risk."""


def _allow_private() -> bool:
    return os.getenv("NET_GUARD_ALLOW_PRIVATE", "false").strip().lower() == "true"


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if the address is in a range that must never be reached externally."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_all(host: str) -> list[str]:
    """Return every IP (v4+v6) the host resolves to. Raises on failure."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return list({str(info[4][0]) for info in infos})


def assert_public_url(url: str) -> None:
    """Validate *url* for outbound use, raising :class:`SSRFError` if unsafe.

    Fail-closed: any parse/DNS error is treated as unsafe.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SSRFError(f"unparseable URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFError(f"scheme not allowed: {scheme or '(none)'}")

    host = (parsed.hostname or "").strip()
    if not host:
        raise SSRFError("URL has no host")

    if _allow_private():
        return

    if host.lower() in _METADATA_HOSTS:
        raise SSRFError("cloud-metadata host is blocked")

    # Raw-IP host: check directly, no DNS.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _ip_is_blocked(literal):
            raise SSRFError(f"IP address in blocked range: {host}")
        return

    # Hostname: resolve and check every returned address (DNS-rebind defence).
    try:
        addresses = _resolve_all(host)
    except OSError as exc:
        raise SSRFError(f"DNS resolution failed for {host}: {exc}") from exc
    if not addresses:
        raise SSRFError(f"no addresses resolved for {host}")

    for addr in addresses:
        if addr in _METADATA_HOSTS:
            raise SSRFError("cloud-metadata address is blocked")
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as exc:
            raise SSRFError(f"unparseable resolved address {addr}") from exc
        if _ip_is_blocked(ip):
            raise SSRFError(f"{host} resolves to blocked range: {addr}")


def is_public_url(url: str) -> bool:
    """Non-raising variant of :func:`assert_public_url`."""
    try:
        assert_public_url(url)
        return True
    except SSRFError:
        return False
