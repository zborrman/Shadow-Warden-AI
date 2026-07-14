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
from typing import Any
from urllib.parse import urlparse

__all__ = [
    "SSRFError",
    "assert_public_url",
    "build_pinned_url",
    "is_public_url",
    "resolve_validated_ips",
    "send_pinned_async",
]

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


def resolve_validated_ips(url: str) -> list[str]:
    """
    Resolve *url*'s host and return the set of IPs, raising :class:`SSRFError` if any
    is a blocked (private/loopback/link-local/metadata/reserved) address.

    This is the building block for closing the TOCTOU / DNS-rebind gap (SR-2.3): a
    caller that validates a URL with :func:`assert_public_url` and then hands the URL
    to httpx lets httpx **re-resolve** at connect time — so attacker-controlled DNS can
    answer "public" during the check and "127.0.0.1 / 169.254.169.254" at connect. The
    only robust fix is to pin the connection to one of the IPs validated *here* (while
    preserving Host/SNI). This function returns exactly those validated IPs so a pinned
    transport can dial them directly instead of re-resolving.

    A raw-IP host returns itself (already validated, no DNS). Fail-closed throughout.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SSRFError(f"unparseable URL: {exc}") from exc

    host = (parsed.hostname or "").strip()
    if not host:
        raise SSRFError("URL has no host")

    # Raw-IP host: validate directly, no DNS.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _ip_is_blocked(literal):
            raise SSRFError(f"IP address in blocked range: {host}")
        return [host]

    if host.lower() in _METADATA_HOSTS:
        raise SSRFError("cloud-metadata host is blocked")

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
    return addresses


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

    # Resolve + validate every address (raw-IP, metadata, and DNS-rebind defence all
    # live in resolve_validated_ips — one place, so the two entry points can't drift).
    resolve_validated_ips(url)


def is_public_url(url: str) -> bool:
    """Non-raising variant of :func:`assert_public_url`."""
    try:
        assert_public_url(url)
        return True
    except SSRFError:
        return False


# ── Connection pinning (closes the DNS-rebind / TOCTOU window) ─────────────────
#
# assert_public_url resolves + validates a host, but a caller that then hands the
# URL to httpx lets httpx *re-resolve* at connect time — attacker DNS can answer
# "public" during the check and "127.0.0.1 / 169.254.169.254" a moment later at
# connect. The only robust fix is to dial one of the IPs validated *here* while
# preserving the Host header and TLS SNI so the certificate still verifies against
# the real hostname (not the IP).

def _select_pinned_ip(ips: list[str]) -> str:
    """Prefer an IPv4 address (broadest egress compatibility); else the first IP."""
    for ip in ips:
        if ":" not in ip:
            return ip
    return ips[0]


def build_pinned_url(url: str) -> tuple[str, str, str]:
    """
    Validate *url* (SSRF, fail-closed) and return ``(connect_url, host_header, sni_hostname)``.

    ``connect_url``  — *url* with its host replaced by a validated public IP, so a
                       client connects to that exact address and cannot re-resolve.
    ``host_header``  — the original host (plus non-default port) for the HTTP ``Host`` header.
    ``sni_hostname`` — the original hostname, used as the TLS ``server_hostname`` so the
                       certificate verifies against the real name, not the pinned IP.

    Raises :class:`SSRFError` on any blocked/unresolvable host. Userinfo, path, query
    and fragment are preserved.
    """
    ips = resolve_validated_ips(url)          # fail-closed: raises on any blocked IP
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip()

    ip = _select_pinned_ip(ips)
    ip_netloc = f"[{ip}]" if ":" in ip else ip
    if parsed.port:
        ip_netloc = f"{ip_netloc}:{parsed.port}"

    # Preserve userinfo (user[:pass]@) if present.
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"

    connect_url = parsed._replace(netloc=f"{userinfo}{ip_netloc}").geturl()

    default_port = 443 if parsed.scheme == "https" else 80
    host_header = f"{host}:{parsed.port}" if parsed.port and parsed.port != default_port else host

    return connect_url, host_header, host


async def send_pinned_async(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    content: bytes | None = None,
    json: Any = None,
    timeout: float = 5.0,
    verify: bool = True,
    follow_redirects: bool = False,
    transport: Any = None,
) -> Any:
    """
    SSRF-safe outbound HTTP request: validate *url*, pin the connection to a validated
    IP, and preserve the Host header + TLS SNI. Returns the ``httpx.Response``.

    Raises :class:`SSRFError` before any network I/O if the URL is unsafe.

    ``follow_redirects`` is **False** by default and should stay that way: a redirect
    to an internal URL would re-open the SSRF hole, because the redirected hop is
    resolved and dialled *without* this pinning. A caller that must follow redirects
    has to re-validate every hop itself.
    """
    import httpx  # lazy — keeps net_guard importable without httpx

    connect_url, host_header, sni_hostname = build_pinned_url(url)

    hdrs = {k: v for k, v in (headers or {}).items() if k.lower() != "host"}
    hdrs["Host"] = host_header

    async with httpx.AsyncClient(
        timeout=timeout, verify=verify, transport=transport, follow_redirects=follow_redirects
    ) as client:
        return await client.request(
            method,
            connect_url,
            headers=hdrs,
            content=content,
            json=json,
            extensions={"sni_hostname": sni_hostname},
        )
