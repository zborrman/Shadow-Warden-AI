"""
warden/client_ip.py
━━━━━━━━━━━━━━━━━━━
Single source of truth for "who is the caller" behind the Cloudflare → Caddy
edge chain.

Why this module exists
──────────────────────
warden never sees the real client socket: every request arrives from the Caddy
container on the internal docker network. ``request.client.host`` is therefore a
*constant* (the proxy's container IP) for the entire internet. Keying ERS,
shadow ban or the rate limiter on it collapses every anonymous caller into one
bucket — a single attacker shadow-bans everyone, and the per-minute quota is
shared globally.

The real address is carried in a forwarded header. Those headers are
attacker-controlled unless the *immediate peer* is a proxy we trust, so this
module trusts them only when ``request.client.host`` falls inside
``TRUSTED_PROXY_CIDRS`` (default: loopback + RFC1918 — i.e. the docker network
Caddy/cloudflared live on). An untrusted peer falls back to its socket address,
which cannot be spoofed.

Header preference order (first non-empty wins):
    CF-Connecting-IP → X-Real-IP → X-Forwarded-For (leftmost entry)

``CF-Connecting-IP`` comes first because Cloudflare overwrites it at the edge on
every request; it is the only one an origin-side attacker cannot influence when
traffic actually flows through the zone.
"""
from __future__ import annotations

import hmac
import ipaddress
import os
from functools import lru_cache

from fastapi import Request

# Headers a verified Vercel edge hop uses to carry the true client through a
# server-side rewrite (www.* → Vercel → api.*). See get_client_ip.
_VERCEL_SECRET_HEADER = "x-warden-proxy-secret"
_VERCEL_CLIENT_IP_HEADER = "x-warden-client-ip"

_DEFAULT_TRUSTED = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

# Checked in order; first non-empty value wins.
_FORWARD_HEADERS = ("cf-connecting-ip", "x-real-ip", "x-forwarded-for")


@lru_cache(maxsize=1)
def _trusted_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    raw = os.getenv("TRUSTED_PROXY_CIDRS", _DEFAULT_TRUSTED)
    nets = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            nets.append(ipaddress.ip_network(chunk, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def is_trusted_proxy(addr: str) -> bool:
    """True when *addr* is one of the reverse proxies allowed to assert an IP."""
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in _trusted_networks())


def get_client_ip(request: Request) -> str:
    """Resolve the caller's address, honouring forwarded headers from a trusted peer.

    Returns the peer socket address (or ``""`` when unavailable) whenever the
    peer is not a trusted proxy, so a direct-to-origin request can never spoof
    its identity.
    """
    peer = request.client.host if request.client else ""

    if not is_trusted_proxy(peer):
        return peer

    # Verified Vercel-rewrite hop. The browser's same-origin /api/auth/* call is
    # server-side rewritten by Vercel to api.*, so the standard forward headers
    # (CF-Connecting-IP etc.) carry Vercel's egress IP, not the user's — which
    # would collapse every browser login into one shared rate-limit bucket. The
    # Vercel edge middleware re-asserts the true client in a dedicated header,
    # proven by a shared secret so a direct-to-origin attacker cannot forge it.
    # Fail-safe: an unset/mismatched secret simply ignores the header (current
    # behaviour), never a bypass.
    from warden.config import settings
    secret = settings.vercel_proxy_secret
    if secret:
        presented = request.headers.get(_VERCEL_SECRET_HEADER, "")
        if presented and hmac.compare_digest(presented, secret):
            vercel_ip = request.headers.get(_VERCEL_CLIENT_IP_HEADER, "").split(",")[0].strip()
            if vercel_ip:
                return vercel_ip

    for header in _FORWARD_HEADERS:
        value = request.headers.get(header)
        if not value:
            continue
        candidate = value.split(",")[0].strip()
        if candidate:
            return candidate

    return peer
