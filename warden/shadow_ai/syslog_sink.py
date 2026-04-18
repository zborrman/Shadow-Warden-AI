"""
warden/shadow_ai/syslog_sink.py
─────────────────────────────────
Passive DNS telemetry — async UDP syslog listener.

Receives DNS query log lines forwarded by pfSense/OPNsense (dnsmasq),
BIND 9 (query logging), Zeek (dns.log via syslog), or any RFC 3164
syslog source, and classifies each domain against the Shadow AI provider
signature database.

Deployment options
──────────────────
  pfSense/OPNsense:
    Services → DNS Resolver → Advanced → Custom Options:
      log-queries
    System → Settings → Logging → Remote log servers → <warden_ip>:5514

  Zeek:
    zeek -i eth0 /path/to/dns_syslog.zeek  (custom script forwarding dns.log)

  dnsmasq:
    log-facility=/var/log/dnsmasq.log + forward with syslog-ng/rsyslog

Port
────
  Default: UDP 5514  (configurable via SHADOW_AI_SYSLOG_PORT env var)
  Root privilege required for port 514; containers should use 5514 and
  have the firewall DNAT UDP 514 → 5514.

Parsed patterns (DNS query extraction)
───────────────────────────────────────
  dnsmasq:   "query[A] openai.com from 10.0.0.5"
  BIND:      "client 10.0.0.5#12345 query: openai.com IN A"
  Zeek:      "query openai.com"
  Generic:   any token that looks like a hostname after "query"

Matched domains are fed to ShadowAIDetector.classify_dns_event(),
which stores findings in Redis and applies policy.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any

log = logging.getLogger("warden.shadow_ai.syslog_sink")

_SYSLOG_PORT = int(os.getenv("SHADOW_AI_SYSLOG_PORT", "5514"))
_DEFAULT_TENANT = os.getenv("SHADOW_AI_SYSLOG_TENANT", "default")

# ── DNS query extraction patterns ─────────────────────────────────────────────

# dnsmasq: "query[A] openai.com from 10.0.0.5"
_RE_DNSMASQ  = re.compile(r"query\[[A-Z]+\]\s+([\w.\-]+)\s+from\s+([\d.]+)")

# BIND9: "client @0xXX 10.0.0.5#PORT query: openai.com IN A"
_RE_BIND     = re.compile(r"client[^\d]+([\d.]+)#\d+.*?query:\s+([\w.\-]+)")

# Generic: any word after "query " that looks like a domain
_RE_GENERIC  = re.compile(r"\bquery\s+([\w.\-]{4,253})")

# Source IP extraction (fallback for patterns that don't capture it)
_RE_IP       = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _parse_dns_line(line: str) -> tuple[str, str] | None:
    """
    Extract (domain, source_ip) from a syslog line.

    Returns None if no DNS query pattern is matched.
    """
    # dnsmasq
    m = _RE_DNSMASQ.search(line)
    if m:
        return m.group(1), m.group(2)

    # BIND9
    m = _RE_BIND.search(line)
    if m:
        return m.group(2), m.group(1)

    # Generic fallback
    m = _RE_GENERIC.search(line)
    if m:
        domain = m.group(1)
        # Skip short tokens that are clearly not domains (e.g. PTR labels)
        if "." not in domain:
            return None
        # Grab first IP as source
        ips = _RE_IP.findall(line)
        src = ips[0] if ips else ""
        return domain, src

    return None


# ── UDP syslog protocol ────────────────────────────────────────────────────────

class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol that feeds received packets into the classifier."""

    def __init__(self, detector: Any, tenant_id: str) -> None:
        self._detector  = detector
        self._tenant_id = tenant_id
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]
        log.info("syslog_sink: listening on UDP port %d", _SYSLOG_PORT)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            line = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return

        parsed = _parse_dns_line(line)
        if not parsed:
            return

        domain, source_ip = parsed
        if not source_ip:
            source_ip = addr[0]  # fall back to UDP sender IP

        try:
            result = self._detector.classify_dns_event(
                domain    = domain,
                source_ip = source_ip,
                tenant_id = self._tenant_id,
            )
            if result.get("match"):
                log.info(
                    "syslog_sink: shadow_ai detected domain=%s provider=%s src=%s",
                    domain, result.get("provider_key"), source_ip,
                )
        except Exception as exc:
            log.debug("syslog_sink: classify error: %s", exc)

    def error_received(self, exc: Exception) -> None:
        log.warning("syslog_sink: UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        log.info("syslog_sink: connection lost: %s", exc)


# ── Public API ────────────────────────────────────────────────────────────────

async def start_syslog_sink(tenant_id: str = _DEFAULT_TENANT) -> asyncio.DatagramTransport | None:
    """
    Start the async UDP syslog listener as a background task.

    Call from FastAPI lifespan or main startup.  Returns the transport
    so the caller can close it on shutdown, or None if startup failed.

    Example (lifespan):
        transport = await start_syslog_sink()
        yield
        if transport:
            transport.close()
    """
    if os.getenv("SHADOW_AI_SYSLOG_ENABLED", "false").lower() != "true":
        log.debug("syslog_sink: disabled (SHADOW_AI_SYSLOG_ENABLED != true)")
        return None

    try:
        from warden.shadow_ai.discovery import ShadowAIDetector
    except ImportError:
        log.warning("syslog_sink: ShadowAIDetector unavailable — sink not started")
        return None

    detector = ShadowAIDetector()
    loop     = asyncio.get_running_loop()

    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(detector, tenant_id),
            local_addr=("0.0.0.0", _SYSLOG_PORT),
        )
        log.info(
            "syslog_sink: started on UDP %d (tenant=%s)",
            _SYSLOG_PORT, tenant_id,
        )
        return transport  # type: ignore[return-value]
    except OSError as exc:
        log.warning(
            "syslog_sink: could not bind UDP %d — %s (run as root or set SHADOW_AI_SYSLOG_PORT)",
            _SYSLOG_PORT, exc,
        )
        return None
