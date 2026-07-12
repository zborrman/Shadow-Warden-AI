"""
SAC execution guard — screens agent tool calls (the "Inner Warden").

For every tool call the guard performs two independent checks:

  1. **URL screening (fail-CLOSED).** Every ``http(s)`` URL found anywhere in the
     tool input is validated with :func:`warden.net_guard.is_public_url`. Any URL
     that resolves to a private / loopback / link-local / cloud-metadata address
     (or that fails to parse/resolve) marks the call ``COMPROMISED`` and
     ``blocked``. This closes the SSRF/exfil gap where agent-supplied URLs reach
     ``BrowserSandbox`` (which runs ``--no-sandbox``) with no check.

  2. **Secret/path read denylist (WARNING, non-blocking).** String args are
     scanned for well-known credential paths (``.ssh``, ``id_rsa``, ``.env``,
     ``.git/config``, ``/etc/shadow`` …) and ``../`` traversal. These raise a
     flag and downgrade the verdict to ``WARNING`` but do not block by default —
     legitimate tools legitimately mention such paths.

The verdict is then shipped to GSAM as a **metadata-only** observation (event
``tool_call``). Telemetry is fail-OPEN: any error building or emitting the
observation is swallowed so it can never break tool dispatch.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Verdict labels align with Observation.scan_verdict (CLEAN/WARNING/COMPROMISED).
CLEAN = "CLEAN"
WARNING = "WARNING"
COMPROMISED = "COMPROMISED"

# Tool inputs whose values commonly carry outbound URLs. Not required for
# correctness (all http(s) URLs are screened regardless) — it documents intent
# and lets us also screen URL-shaped values that omit the scheme.
_URL_KEYS = frozenset({
    "url", "uri", "endpoint", "target_url", "baseline_url", "candidate_url",
    "href", "webhook_url", "callback_url", "image_url", "page_url",
})

# Credential paths / traversal markers an agent should never be reading.
_SECRET_MARKERS = (
    ".ssh", "id_rsa", "id_ed25519", ".env", ".git/config", ".git\\config",
    "/etc/shadow", "/etc/passwd", ".aws/credentials", ".npmrc", ".pgpass",
    "authorized_keys",
)
_TRAVERSAL = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


@dataclass
class GuardVerdict:
    """Outcome of screening one tool call. ``blocked`` is the enforcement bit."""

    verdict: str = CLEAN
    blocked: bool = False
    reason: str = ""
    resolved_domains: list[str] = field(default_factory=list)
    network_calls: int = 0
    flags: list[str] = field(default_factory=list)


def _iter_strings(value: object) -> list[str]:
    """Flatten every string reachable in a nested dict/list/tuple input."""
    out: list[str] = []
    stack = [value]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            out.append(cur)
        elif isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)
    return out


def _extract_urls(strings: list[str]) -> list[str]:
    urls: list[str] = []
    for s in strings:
        urls.extend(_URL_RE.findall(s))
    return urls


def screen_tool_call(
    agent_id: str,
    tenant_id: str,
    tool_name: str,
    tool_input: dict,
    *,
    url_sensitive: bool = False,
) -> GuardVerdict:
    """Screen one tool call. Pure — never emits, never raises.

    ``url_sensitive`` additionally treats bare (scheme-less) values under
    :data:`_URL_KEYS` as candidate hosts. All ``http(s)`` URLs are screened
    regardless of this flag.
    """
    verdict = GuardVerdict()
    try:
        strings = _iter_strings(tool_input)
    except Exception:  # screening must never raise
        return verdict

    # ── URL screening (fail-CLOSED) ─────────────────────────────────────────
    candidates = _extract_urls(strings)
    if url_sensitive and isinstance(tool_input, dict):
        for key in _URL_KEYS:
            val = tool_input.get(key)
            if isinstance(val, str) and val and not _URL_RE.match(val):
                candidates.append(val if "://" in val else f"https://{val}")

    from warden.net_guard import is_public_url  # lazy

    domains: list[str] = []
    for url in candidates:
        host = (urlparse(url).hostname or "").lower()
        if host:
            domains.append(host)
        if not is_public_url(url):
            verdict.verdict = COMPROMISED
            verdict.blocked = True
            verdict.reason = f"outbound URL blocked (SSRF/exfil): host={host or '?'}"
            verdict.flags.append("ssrf_blocked")

    verdict.network_calls = len(candidates)
    # Dedupe + cap; hostnames only (Observation caps to 50 anyway).
    verdict.resolved_domains = list(dict.fromkeys(domains))[:50]

    # ── Secret/path read denylist (WARNING) ─────────────────────────────────
    for s in strings:
        low = s.lower()
        for marker in _SECRET_MARKERS:
            if marker in low:
                verdict.flags.append(f"secret_path:{marker}")
                if not verdict.blocked:
                    verdict.verdict = WARNING
        if _TRAVERSAL.search(s):
            verdict.flags.append("path_traversal")
            if not verdict.blocked:
                verdict.verdict = WARNING

    if verdict.verdict == WARNING and not verdict.reason:
        verdict.reason = "sensitive path/traversal reference"
    return verdict


def _emit(
    agent_id: str,
    tenant_id: str,
    tool_name: str,
    verdict: GuardVerdict,
    latency_ms: float,
    status: str,
) -> None:
    """Ship a metadata-only GSAM observation. Fail-OPEN."""
    try:
        from warden.gsam import gsam_emit
        from warden.gsam.schema import Observation

        obs = Observation(
            tenant_id=tenant_id or "",
            agent_id=agent_id or "",
            role="SERVICE",
            event="tool_call",
            payload_kind=tool_name[:64],  # short label — never content
            status=status,
            network_calls_count=verdict.network_calls,
            resolved_domains=verdict.resolved_domains,
            unauthorized_commands_flag=verdict.blocked,
            scan_verdict=verdict.verdict,
            latency_ms=round(latency_ms, 3),
        )
        gsam_emit(obs.to_row())
    except Exception as exc:  # telemetry never breaks dispatch
        from warden.observability import Reason, record_failopen
        record_failopen("sac_guard", Reason.BACKEND_ERROR, exc)


def screen_and_emit(
    agent_id: str,
    tenant_id: str,
    tool_name: str,
    tool_input: dict,
    *,
    url_sensitive: bool = False,
) -> GuardVerdict:
    """Screen a tool call and emit its GSAM observation. Returns the verdict.

    Callers enforce by checking ``verdict.blocked`` — the guard itself does not
    raise (security = fail-CLOSED via the ``blocked`` bit; telemetry = fail-OPEN).
    """
    t0 = time.perf_counter()
    verdict = screen_tool_call(
        agent_id, tenant_id, tool_name, tool_input, url_sensitive=url_sensitive
    )
    latency_ms = (time.perf_counter() - t0) * 1000
    status = "blocked" if verdict.blocked else "ok"
    _emit(agent_id, tenant_id, tool_name, verdict, latency_ms, status)
    return verdict
