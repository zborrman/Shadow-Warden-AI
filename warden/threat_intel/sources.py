"""
warden/threat_intel/sources.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Abstract ThreatSource base class + five concrete source implementations.

All sources are fail-open: any exception in fetch() is logged and returns [].
HTTP is performed with httpx (synchronous, runs in a thread pool via collector).
No new dependencies are added — httpx and stdlib xml.etree are sufficient.

Sources
───────
  MitreAtlasSource       MITRE ATLAS ML attack techniques (JSON from GitHub)
  NvdCveSource           NVD CVE API v2 filtered by AI/LLM keywords
  GitHubAdvisorySource   GitHub Security Advisories REST API (pip ecosystem)
  ArxivSource            arXiv Atom feed — adversarial LLM / prompt injection
  OwaspLlmSource         OWASP LLM Top 10 GitHub releases Atom feed
"""
from __future__ import annotations

import logging
import os
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass

log = logging.getLogger("warden.threat_intel.sources")

# ── Raw normalized item (pre-analysis) ────────────────────────────────────────


@dataclass
class RawThreatItem:
    source:          str
    title:           str
    url:             str          # canonical dedup key
    published_at:    str | None
    raw_description: str


# ── Abstract base ─────────────────────────────────────────────────────────────


class ThreatSource(ABC):
    name:    str = ""
    timeout: int = 20

    @abstractmethod
    def fetch(self, max_items: int = 20) -> list[RawThreatItem]:
        """Pull items from the external source. Fail-open: log + return []."""


# ── MITRE ATLAS ───────────────────────────────────────────────────────────────


class MitreAtlasSource(ThreatSource):
    """
    MITRE ATLAS — Adversarial Threat Landscape for Artificial-Intelligence Systems.
    Fetches the ATLAS.json data bundle from the mitre-atlas/atlas-data GitHub repo.
    Extracts Technique objects (ML-specific attack techniques).
    """

    name = "mitre_atlas"
    _FEED_URL = (
        "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.json"
    )

    def fetch(self, max_items: int = 20) -> list[RawThreatItem]:
        try:
            import httpx
            resp = httpx.get(self._FEED_URL, timeout=self.timeout, follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log.warning("MitreAtlasSource: fetch failed — %s", exc)
            return []

        items: list[RawThreatItem] = []
        try:
            matrices = data.get("matrices", [])
            for matrix in matrices:
                for technique in matrix.get("techniques", []):
                    tid   = technique.get("id", "")
                    name  = technique.get("name", "")
                    desc  = technique.get("description", "")
                    if not tid or not name:
                        continue
                    url = f"https://atlas.mitre.org/techniques/{tid}"
                    items.append(RawThreatItem(
                        source=self.name,
                        title=f"[{tid}] {name}",
                        url=url,
                        published_at=None,
                        raw_description=desc,
                    ))
                    if len(items) >= max_items:
                        return items
        except Exception as exc:
            log.warning("MitreAtlasSource: parse failed — %s", exc)

        return items


# ── NVD CVE ───────────────────────────────────────────────────────────────────


class NvdCveSource(ThreatSource):
    """
    NIST NVD CVE API v2.0 filtered by keywords relevant to LLM security.
    Optional NVD_API_KEY header increases rate limits from 5 to 50 req/30s.
    """

    name = "nvd"
    _API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    _KEYWORD = "prompt injection LLM AI machine learning"

    def fetch(self, max_items: int = 20) -> list[RawThreatItem]:
        try:
            import httpx
            headers: dict[str, str] = {}
            api_key = os.getenv("NVD_API_KEY", "")
            if api_key:
                headers["apiKey"] = api_key

            resp = httpx.get(
                self._API_URL,
                params={"keywordSearch": self._KEYWORD, "resultsPerPage": min(max_items, 20)},
                headers=headers,
                timeout=self.timeout,
                follow_redirects=True,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log.warning("NvdCveSource: fetch failed — %s", exc)
            return []

        items: list[RawThreatItem] = []
        try:
            for vuln in data.get("vulnerabilities", [])[:max_items]:
                cve   = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descs  = cve.get("descriptions", [])
                desc   = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                pub    = cve.get("published", "")
                if not cve_id or not desc:
                    continue
                items.append(RawThreatItem(
                    source=self.name,
                    title=cve_id,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published_at=pub or None,
                    raw_description=desc,
                ))
        except Exception as exc:
            log.warning("NvdCveSource: parse failed — %s", exc)

        return items


# ── GitHub Security Advisories ────────────────────────────────────────────────


class GitHubAdvisorySource(ThreatSource):
    """
    GitHub Security Advisories REST API.
    Filters to Python (pip) ecosystem advisories, searches for AI/LLM keywords.
    Optional GITHUB_TOKEN header increases rate limits from 60 to 5000 req/hr.
    """

    name = "github"
    _REST_URL = "https://api.github.com/advisories"
    _KEYWORDS = ("prompt injection", "jailbreak", "LLM", "large language model")

    def fetch(self, max_items: int = 20) -> list[RawThreatItem]:
        try:
            import httpx
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            token = os.getenv("GITHUB_TOKEN", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"

            resp = httpx.get(
                self._REST_URL,
                params={"type": "reviewed", "ecosystem": "pip", "per_page": max_items},
                headers=headers,
                timeout=self.timeout,
                follow_redirects=True,
            )
            resp.raise_for_status()
            advisories = resp.json()
        except Exception as exc:
            log.warning("GitHubAdvisorySource: fetch failed — %s", exc)
            return []

        items: list[RawThreatItem] = []
        try:
            for adv in advisories[:max_items]:
                summary = adv.get("summary", "")
                desc    = adv.get("description", "") or summary
                # Filter by keyword relevance
                text_lower = (summary + " " + desc).lower()
                if not any(kw.lower() in text_lower for kw in self._KEYWORDS):
                    continue
                ghsa_id  = adv.get("ghsa_id", "")
                html_url = adv.get("html_url") or f"https://github.com/advisories/{ghsa_id}"
                pub_at   = adv.get("published_at")
                items.append(RawThreatItem(
                    source=self.name,
                    title=f"[{ghsa_id}] {summary[:120]}",
                    url=html_url,
                    published_at=pub_at,
                    raw_description=desc,
                ))
        except Exception as exc:
            log.warning("GitHubAdvisorySource: parse failed — %s", exc)

        return items


# ── arXiv ─────────────────────────────────────────────────────────────────────


class ArxivSource(ThreatSource):
    """
    arXiv Atom API — adversarial LLM / prompt injection / jailbreak papers.
    Parses Atom XML using stdlib xml.etree (no feedparser dependency).
    """

    name = "arxiv"
    _API_URL = "http://export.arxiv.org/api/query"
    _QUERY   = (
        "ti:prompt+injection+OR+ti:jailbreak+OR+ti:adversarial+LLM"
        "+OR+abs:prompt+injection+attack"
    )
    _NS = {"atom": "http://www.w3.org/2005/Atom"}

    def fetch(self, max_items: int = 20) -> list[RawThreatItem]:
        try:
            import httpx
            resp = httpx.get(
                self._API_URL,
                params={"search_query": self._QUERY, "max_results": max_items,
                        "sortBy": "submittedDate", "sortOrder": "descending"},
                timeout=self.timeout,
                follow_redirects=True,
            )
            resp.raise_for_status()
            root = ET.fromstring(resp.text)
        except Exception as exc:
            log.warning("ArxivSource: fetch failed — %s", exc)
            return []

        items: list[RawThreatItem] = []
        try:
            for entry in root.findall("atom:entry", self._NS)[:max_items]:
                title   = (entry.findtext("atom:title", "", self._NS) or "").strip()
                summary = (entry.findtext("atom:summary", "", self._NS) or "").strip()
                pub     = entry.findtext("atom:published", None, self._NS)
                # prefer the abs link
                url = ""
                for link in entry.findall("atom:link", self._NS):
                    if link.get("rel") == "alternate" or link.get("type") == "text/html":
                        url = link.get("href", "")
                        break
                if not url:
                    url = entry.findtext("atom:id", "", self._NS) or ""
                if not title or not url:
                    continue
                items.append(RawThreatItem(
                    source=self.name,
                    title=title[:200],
                    url=url,
                    published_at=pub,
                    raw_description=summary[:2000],
                ))
        except Exception as exc:
            log.warning("ArxivSource: parse failed — %s", exc)

        return items


# ── OWASP LLM Top 10 ─────────────────────────────────────────────────────────


class OwaspLlmSource(ThreatSource):
    """
    OWASP LLM Top 10 GitHub releases Atom feed.
    Low frequency (version releases only) — each release is one threat item.
    """

    name = "owasp"
    _ATOM_URL = (
        "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications"
        "/releases.atom"
    )
    _NS = {"atom": "http://www.w3.org/2005/Atom"}

    def fetch(self, max_items: int = 20) -> list[RawThreatItem]:
        try:
            import httpx
            resp = httpx.get(self._ATOM_URL, timeout=self.timeout, follow_redirects=True)
            resp.raise_for_status()
            root = ET.fromstring(resp.text)
        except Exception as exc:
            log.warning("OwaspLlmSource: fetch failed — %s", exc)
            return []

        items: list[RawThreatItem] = []
        try:
            for entry in root.findall("atom:entry", self._NS)[:max_items]:
                title   = (entry.findtext("atom:title", "", self._NS) or "").strip()
                content = (entry.findtext("atom:content", "", self._NS) or "").strip()
                summary = (entry.findtext("atom:summary", "", self._NS) or "").strip()
                updated = entry.findtext("atom:updated", None, self._NS)
                url = ""
                for link in entry.findall("atom:link", self._NS):
                    url = link.get("href", "")
                    if url:
                        break
                if not title or not url:
                    continue
                items.append(RawThreatItem(
                    source=self.name,
                    title=f"OWASP LLM: {title}",
                    url=url,
                    published_at=updated,
                    raw_description=(content or summary)[:2000],
                ))
        except Exception as exc:
            log.warning("OwaspLlmSource: parse failed — %s", exc)

        return items


# ── Registry ──────────────────────────────────────────────────────────────────

ALL_SOURCES: list[type[ThreatSource]] = [
    MitreAtlasSource,
    NvdCveSource,
    GitHubAdvisorySource,
    ArxivSource,
    OwaspLlmSource,
]
