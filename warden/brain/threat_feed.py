"""
warden/brain/threat_feed.py  (DET-03)
──────────────────────────────────────
Live Threat Feed Sync — fetches new attack advisories every 4 hours and
injects them into the EvolutionEngine as synthetic examples.

Sources
-------
1. MITRE ATLAS  — https://atlas.mitre.org/matrices/ATLAS/
   (GitHub JSON feed)
2. OWASP LLM Top 10 — GitHub releases RSS
3. HuggingFace Security Advisories — HF blog RSS

Each advisory is converted into an attack description string and passed
to `synthesize_from_intel()` which generates detection examples.

Activation
----------
THREAT_FEED_ENABLED=true (default false — opt-in)
THREAT_FEED_INTERVAL_HRS=4 (default)
Requires ANTHROPIC_API_KEY for synthesis.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

# defusedxml, not stdlib xml.etree: every document parsed here is UNTRUSTED
# (SAML assertion / external threat feed), and xml.etree resolves external
# entities -> XXE: local-file exfiltration, SSRF, and billion-laughs DoS.
from defusedxml.ElementTree import fromstring as _xml_fromstring

log = logging.getLogger("warden.brain.threat_feed")

_ENABLED  = os.getenv("THREAT_FEED_ENABLED", "false").lower() == "true"
_INTERVAL = int(os.getenv("THREAT_FEED_INTERVAL_HRS", "4"))

_ATLAS_FEED_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/"
    "dist/ATLAS.json"
)
_OWASP_LLM_RSS = (
    "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/"
    "releases.atom"
)
_HUGGINGFACE_RSS = "https://huggingface.co/blog/feed.xml"

_SEEN_CACHE: set[str] = set()


# ── Fetch helpers ──────────────────────────────────────────────────────────────

async def _fetch(url: str, timeout: int = 15) -> str | None:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(url)
            r.raise_for_status()
            return r.text
    except Exception as exc:
        log.warning("threat_feed: fetch failed %s — %s", url, exc)
        return None


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


# ── Source parsers ─────────────────────────────────────────────────────────────

async def _fetch_atlas() -> list[str]:
    raw = await _fetch(_ATLAS_FEED_URL)
    if not raw:
        return []
    try:
        data = json.loads(raw)
        techniques: list[str] = []
        for t in data.get("techniques", []):
            name = t.get("name", "")
            desc = t.get("description", "")
            if name and desc:
                techniques.append(f"MITRE ATLAS technique '{name}': {desc[:400]}")
        return techniques
    except Exception as exc:
        log.warning("threat_feed: ATLAS parse error — %s", exc)
        return []


async def _fetch_rss(url: str, label: str) -> list[str]:
    raw = await _fetch(url)
    if not raw:
        return []
    items: list[str] = []
    try:
        root = _xml_fromstring(raw)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        entries = root.findall(".//item") or root.findall(".//atom:entry", ns)
        for entry in entries[:10]:
            title_el = entry.find("title") or entry.find("atom:title", ns)
            summary_el = entry.find("description") or entry.find("atom:summary", ns)
            title   = title_el.text   if title_el   else ""
            summary = summary_el.text if summary_el else ""
            if title:
                items.append(f"{label}: {title}. {summary[:300]}")
    except Exception as exc:
        log.warning("threat_feed: RSS parse error %s — %s", url, exc)
    return items


# ── Injection ──────────────────────────────────────────────────────────────────

async def _inject(advisories: list[str]) -> int:
    """Push new advisories into EvolutionEngine via synthesize_from_intel."""
    injected = 0
    try:
        from warden.brain.evolve import EvolutionEngine  # noqa: PLC0415
        engine = EvolutionEngine()
        for advisory in advisories:
            h = _sha(advisory)
            if h in _SEEN_CACHE:
                continue
            try:
                await engine.synthesize_from_intel(advisory, title=advisory[:80], link="")
                _SEEN_CACHE.add(h)
                injected += 1
            except Exception as exc:
                log.debug("threat_feed: inject failed — %s", exc)
    except ImportError:
        log.info("threat_feed: EvolutionEngine not available — skipping inject")
    return injected


# ── Main sync ──────────────────────────────────────────────────────────────────

async def sync_threat_feeds() -> dict[str, Any]:
    """Fetch all threat feeds and inject new advisories. Returns summary."""
    if not _ENABLED:
        return {"status": "disabled", "injected": 0}

    atlas_items, owasp_items, hf_items = (
        await _fetch_atlas(),
        await _fetch_rss(_OWASP_LLM_RSS, "OWASP LLM"),
        await _fetch_rss(_HUGGINGFACE_RSS, "HuggingFace Security"),
    )

    all_items = atlas_items + owasp_items + hf_items
    log.info("threat_feed: fetched %d advisories (atlas=%d owasp=%d hf=%d)",
             len(all_items), len(atlas_items), len(owasp_items), len(hf_items))

    injected = await _inject(all_items)
    log.info("threat_feed: injected %d new advisories into EvolutionEngine", injected)

    return {
        "status": "ok",
        "fetched": len(all_items),
        "injected": injected,
        "sources": {
            "atlas": len(atlas_items),
            "owasp_llm": len(owasp_items),
            "huggingface": len(hf_items),
        },
        "ts": datetime.now(UTC).isoformat(),
    }
