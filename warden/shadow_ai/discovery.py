"""
warden/shadow_ai/discovery.py
───────────────────────────────
Shadow AI Discovery Engine.

Two detection surfaces:

1. Network probe (scan)
   Iterates hosts in a CIDR subnet, probes common AI ports with async HTTP,
   fingerprints responses against the AI provider signature database, and
   returns a ranked list of discovered AI endpoints.

   Safety limits:
     - Max subnet prefix: /24 (256 hosts). Rejects larger ranges.
     - Max concurrent probes: 50 (configurable via SHADOW_AI_CONCURRENCY).
     - Per-host timeout: 3 s.
     - HTTP only (no TCP-only port scan). Reduces blast radius.

2. DNS telemetry sink (classify_dns_event)
   Accepts a single DNS query event (domain + source IP) and classifies it
   against the known AI domain list.  Call this from syslog forwarder /
   DNS RPZ / Zeek / Suricata to feed real-time telemetry.

Both surfaces store findings in Redis (shadow_ai:findings:{tenant_id})
with a capped list of 1 000 most recent entries.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

import httpx

from warden.shadow_ai.policy import get_policy, get_verdict
from warden.shadow_ai.signatures import (
    AI_PROVIDERS,
    DOMAIN_TO_PROVIDER,
    PROBE_PORTS,
    RISK_ORDER,
)

log = logging.getLogger("warden.shadow_ai.discovery")

_MAX_PREFIX    = 24          # refuse to scan subnets larger than /24
_MAX_HOSTS     = 256
_PROBE_TIMEOUT = float(os.getenv("SHADOW_AI_PROBE_TIMEOUT", "3"))
_CONCURRENCY   = int(os.getenv("SHADOW_AI_CONCURRENCY", "50"))
_FINDINGS_CAP  = 1_000
# Scapy ARP/ICMP pre-probe: skip dead hosts before HTTP fingerprinting.
# Reduces scan time by 60-80% on sparse subnets.
# Requires: pip install scapy>=2.5.0 AND root/CAP_NET_RAW privileges.
# Set SHADOW_AI_USE_SCAPY=true to activate; silently disabled if unavailable.
_USE_SCAPY     = os.getenv("SHADOW_AI_USE_SCAPY", "false").lower() == "true"
_SCAPY_TIMEOUT = float(os.getenv("SHADOW_AI_SCAPY_TIMEOUT", "2"))


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


def _store_finding(finding: dict, tenant_id: str) -> None:
    r = _redis()
    if not r:
        return
    key = f"shadow_ai:findings:{tenant_id}"
    try:
        r.lpush(key, json.dumps(finding))
        r.ltrim(key, 0, _FINDINGS_CAP - 1)
    except Exception as exc:
        log.debug("_store_finding redis error: %s", exc)


def get_findings(tenant_id: str, limit: int = 100) -> list[dict]:
    r = _redis()
    if not r:
        return []
    key = f"shadow_ai:findings:{tenant_id}"
    try:
        raw = r.lrange(key, 0, limit - 1)
        return [json.loads(x) for x in raw]
    except Exception as exc:
        log.debug("get_findings redis error: %s", exc)
        return []


def clear_findings(tenant_id: str) -> int:
    r = _redis()
    if not r:
        return 0
    key = f"shadow_ai:findings:{tenant_id}"
    try:
        n = r.llen(key)
        r.delete(key)
        return n
    except Exception:
        return 0


# ── Scapy host discovery (optional) ──────────────────────────────────────────

def _scapy_live_hosts(hosts: list[str]) -> set[str]:
    """
    ARP-ping all *hosts* and return the set of responding IPs.

    Falls back to the full host list (no filtering) if:
      - scapy is not installed
      - caller lacks raw-socket privileges (non-root / no CAP_NET_RAW)
      - any other scapy error

    Must be called in a thread executor (scapy send/recv is synchronous).
    """
    try:
        from scapy.layers.l2 import ARP, Ether  # type: ignore[import]  # noqa: PLC0415
        from scapy.sendrecv import srp  # type: ignore[import]  # noqa: PLC0415
    except ImportError:
        log.debug("scapy not installed — skipping live-host pre-probe")
        return set(hosts)

    try:
        # Build a single broadcast ARP request for all hosts
        # Craft: Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
        targets = " ".join(hosts)
        pkt     = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
        answered, _ = srp(pkt, timeout=_SCAPY_TIMEOUT, verbose=False)
        live = {rcv.psrc for _, rcv in answered}
        log.debug(
            "scapy arp-ping: %d/%d hosts responded",
            len(live), len(hosts),
        )
        return live if live else set(hosts)
    except PermissionError:
        log.debug("scapy arp-ping: insufficient privileges — scanning all hosts")
        return set(hosts)
    except Exception as exc:
        log.debug("scapy arp-ping error: %s — scanning all hosts", exc)
        return set(hosts)


async def _discover_live_hosts(hosts: list[str]) -> set[str]:
    """
    Async wrapper for _scapy_live_hosts — runs in a thread executor so
    the blocking scapy call doesn't stall the event loop.
    """
    if not _USE_SCAPY:
        return set(hosts)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _scapy_live_hosts, hosts)


# ── Fingerprinting ────────────────────────────────────────────────────────────

def _fingerprint_response(
    url: str,
    status_code: int,
    headers: dict[str, str],
    body_excerpt: str,
) -> str | None:
    """
    Match an HTTP response against the AI provider signature database.
    Returns a provider key (e.g. 'openai') or None if no match.
    """
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    url_lower     = url.lower()

    for provider_key, sig in AI_PROVIDERS.items():
        # Header match
        for hdr in sig["response_headers"]:
            if hdr.lower() in headers_lower:
                return provider_key

        # URL path match
        for pattern in sig["url_patterns"]:
            if pattern.lower() in url_lower:
                return provider_key

        # Body heuristic (OpenAI-compatible APIs return JSON with "model" key)
        body_lower = body_excerpt.lower()
        if (
            '"object"' in body_lower
            and ('"chat.completion"' in body_lower or '"text_completion"' in body_lower)
        ):
            # Generic OpenAI-compatible response; mark as LOCAL_AI if local port
            return "localai"

    return None


# ── Single host probe ─────────────────────────────────────────────────────────

async def _probe_host(ip: str, port: int) -> dict | None:
    """
    Attempt an HTTP GET to *ip:port* and fingerprint the response.
    Returns a raw probe result dict or None if no AI detected.
    """
    scheme = "https" if port in (443, 8443) else "http"
    # Probe a neutral path — we're fingerprinting, not exploiting
    url = f"{scheme}://{ip}:{port}/"

    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=_PROBE_TIMEOUT,
            follow_redirects=False,
        ) as client:
            resp = await client.get(url)
            body_excerpt = resp.text[:500]
            provider_key = _fingerprint_response(
                url,
                resp.status_code,
                dict(resp.headers),
                body_excerpt,
            )
            if provider_key:
                return {
                    "ip":           ip,
                    "port":         port,
                    "url":          url,
                    "status_code":  resp.status_code,
                    "provider_key": provider_key,
                }
    except (httpx.ConnectError, httpx.TimeoutException):
        pass   # host offline / filtered — expected
    except Exception as exc:
        log.debug("_probe_host %s:%d error: %s", ip, port, exc)
    return None


# ── ShadowAIDetector ──────────────────────────────────────────────────────────

class ShadowAIDetector:
    """
    Main Shadow AI detection engine.

    Methods
    ───────
    scan(subnet, tenant_id)          Async subnet probe → findings list
    classify_dns_event(domain, ...)  Classify a single DNS query event
    """

    async def scan(
        self,
        subnet:    str = "",
        tenant_id: str = "default",
    ) -> dict[str, Any]:
        """
        Probe all hosts in *subnet* (CIDR) for AI API endpoints.

        Args:
            subnet:    CIDR block (e.g. "10.0.0.0/24"). Must be ≤ /24.
                       Pass "" to skip network probing (DNS-only report).
            tenant_id: Tenant to apply policy against and store findings under.

        Returns:
            {
              "status":       "ok" | "error",
              "subnet":       str,
              "hosts_probed": int,
              "findings":     list[FindingDict],
              "summary":      {risk_level: count, ...},
              "tenant_id":    str,
              "scanned_at":   ISO timestamp,
            }
        """
        pol          = get_policy(tenant_id)
        findings:    list[dict] = []
        hosts_probed = 0

        if subnet:
            try:
                network = ipaddress.ip_network(subnet, strict=False)
            except ValueError as exc:
                return {"status": "error", "reason": f"Invalid CIDR: {exc}"}

            if network.prefixlen < _MAX_PREFIX:
                return {
                    "status": "error",
                    "reason": f"Subnet too large (/{network.prefixlen}). Max /{_MAX_PREFIX}.",
                }

            all_hosts   = list(network.hosts()) or [network.network_address]
            # Optional scapy pre-probe: filter to live hosts before HTTP scan
            live_set    = await _discover_live_hosts([str(h) for h in all_hosts])
            hosts       = [h for h in all_hosts if str(h) in live_set]
            if _USE_SCAPY:
                log.info(
                    "shadow_ai scan: scapy filtered %d/%d hosts",
                    len(hosts), len(all_hosts),
                )
            sem         = asyncio.Semaphore(_CONCURRENCY)

            async def _bounded_probe(ip_obj: Any, port: int) -> dict | None:
                async with sem:
                    return await _probe_host(str(ip_obj), port)

            tasks = [
                _bounded_probe(host, port)
                for host in hosts
                for port in PROBE_PORTS
            ]
            hosts_probed = len(all_hosts)   # report total, not filtered
            results      = await asyncio.gather(*tasks, return_exceptions=False)

            for r in results:
                if r is None:
                    continue
                finding = self._build_finding(r, tenant_id, pol, source="NETWORK_PROBE")
                findings.append(finding)
                _store_finding(finding, tenant_id)

        # De-duplicate by (ip, provider_key)
        seen: set[tuple[str, str]] = set()
        deduped: list[dict] = []
        for f in findings:
            key = (f.get("ip", ""), f["provider_key"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Sort: risk HIGH → MEDIUM → LOW, then provider name
        deduped.sort(
            key=lambda f: (-RISK_ORDER.get(f["risk_level"], 0), f["provider_key"])
        )

        # Summary counts
        summary: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in deduped:
            summary[f["risk_level"]] = summary.get(f["risk_level"], 0) + 1

        return {
            "status":       "ok",
            "subnet":       subnet or "none",
            "hosts_probed": hosts_probed,
            "findings":     deduped,
            "summary":      summary,
            "tenant_id":    tenant_id,
            "scanned_at":   datetime.now(UTC).isoformat(),
        }

    def classify_dns_event(
        self,
        domain:    str,
        source_ip: str = "",
        tenant_id: str = "default",
    ) -> dict[str, Any]:
        """
        Classify a DNS query event against the AI provider domain list.

        Call this from a DNS RPZ hook, syslog forwarder, or Zeek script to
        feed real-time DNS telemetry into the governance engine.

        Returns a finding dict (and stores it) when a match is found,
        or {"match": False} when the domain is not a known AI provider.
        """
        domain_lower = domain.lower().strip()

        # Exact match
        provider_key = DOMAIN_TO_PROVIDER.get(domain_lower)

        # Suffix match (e.g. "tenant.openai.azure.com" → "azure_openai")
        if not provider_key:
            for known_domain, key in DOMAIN_TO_PROVIDER.items():
                if domain_lower.endswith("." + known_domain) or domain_lower == known_domain:
                    provider_key = key
                    break

        if not provider_key:
            return {"match": False, "domain": domain}

        pol     = get_policy(tenant_id)
        finding = self._build_finding(
            raw={
                "ip":          source_ip or "dns-telemetry",
                "port":        0,
                "url":         f"dns://{domain}",
                "status_code": 0,
                "provider_key": provider_key,
            },
            tenant_id = tenant_id,
            policy    = pol,
            source    = "DNS_TELEMETRY",
        )
        _store_finding(finding, tenant_id)
        return {**finding, "match": True}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_finding(
        self,
        raw:       dict,
        tenant_id: str,
        policy:    dict,
        source:    str,
    ) -> dict:
        provider_key = raw["provider_key"]
        sig: dict[str, Any] = AI_PROVIDERS.get(provider_key, {})
        verdict      = get_verdict(provider_key, tenant_id)

        return {
            "provider_key":   provider_key,
            "display_name":   sig.get("display_name", provider_key),
            "category":       sig.get("category", "UNKNOWN"),
            "risk_level":     sig.get("risk_level", "UNKNOWN"),
            "verdict":        verdict,
            "ip":             raw.get("ip", ""),
            "port":           raw.get("port", 0),
            "url":            raw.get("url", ""),
            "source":         source,
            "policy_mode":    policy.get("mode", "MONITOR"),
            "tenant_id":      tenant_id,
            "detected_at":    datetime.now(UTC).isoformat(),
        }
