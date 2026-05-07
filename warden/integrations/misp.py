"""
warden/integrations/misp.py
────────────────────────────
MISP threat feed connector.

Pulls events from a MISP instance, converts relevant attributes to natural-language
attack descriptions, and synthesises them into the local SemanticGuard corpus via
EvolutionEngine.synthesize_from_intel().

Configuration (env vars)
  MISP_URL          e.g. https://misp.example.com
  MISP_API_KEY      PyMISP authkey
  MISP_VERIFY_SSL   true|false (default true)
  MISP_LOOKBACK_DAYS  how many days back to fetch (default 7)
  MISP_TAG_FILTER   comma-separated tags to filter (default: all)
  MISP_MAX_EVENTS   max events per sync (default 100)

The connector is OPTIONAL: import errors are caught at mount time.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

log = logging.getLogger("warden.integrations.misp")

_ATTR_TYPES = {
    "url":              "malicious URL",
    "domain":           "malicious domain",
    "ip-dst":           "malicious destination IP",
    "md5":              "malware file hash (MD5)",
    "sha256":           "malware file hash (SHA-256)",
    "filename":         "malicious filename",
    "vulnerability":    "CVE exploitation attempt",
    "yara":             "YARA rule detection signature",
    "snort":            "Snort IDS rule",
    "email-src":        "phishing sender address",
    "text":             "threat intelligence note",
}


@dataclass
class MISPSyncResult:
    events_fetched:   int = 0
    attrs_extracted:  int = 0
    examples_added:   int = 0
    errors:           list[str] = field(default_factory=list)
    ts:               str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict:
        return {
            "events_fetched":  self.events_fetched,
            "attrs_extracted": self.attrs_extracted,
            "examples_added":  self.examples_added,
            "errors":          self.errors,
            "ts":              self.ts,
        }


class MISPConnector:
    """
    Lightweight MISP → EvolutionEngine bridge.

    Does NOT require pymisp — uses plain httpx so the warden container
    stays minimal.  Falls back gracefully if the MISP server is unreachable.
    """

    def __init__(self) -> None:
        self.url    = os.getenv("MISP_URL", "").rstrip("/")
        self.apikey = os.getenv("MISP_API_KEY", "")
        self.verify = os.getenv("MISP_VERIFY_SSL", "true").lower() != "false"
        self.lookback_days = int(os.getenv("MISP_LOOKBACK_DAYS", "7"))
        self.max_events    = int(os.getenv("MISP_MAX_EVENTS", "100"))
        self.tag_filter    = [
            t.strip() for t in os.getenv("MISP_TAG_FILTER", "").split(",") if t.strip()
        ]

        if not self.url or not self.apikey:
            raise ValueError("MISP_URL and MISP_API_KEY must be set")

    @property
    def _headers(self) -> dict:
        return {
            "Authorization": self.apikey,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }

    async def _fetch_events(self) -> list[dict]:
        import httpx  # noqa: PLC0415

        since = (datetime.now(UTC) - timedelta(days=self.lookback_days)).strftime("%Y-%m-%d")
        payload: dict = {
            "request": {
                "returnFormat": "json",
                "limit":        self.max_events,
                "from":         since,
                "published":    True,
            }
        }
        if self.tag_filter:
            payload["request"]["tags"] = self.tag_filter

        async with httpx.AsyncClient(verify=self.verify, timeout=30) as client:
            resp = await client.post(
                f"{self.url}/events/restSearch",
                headers=self._headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        events = data.get("response", data) if isinstance(data, dict) else data
        if isinstance(events, dict):
            events = events.get("Event", [])
        return events if isinstance(events, list) else []

    @staticmethod
    def _event_to_descriptions(event: dict) -> list[str]:
        """Convert a MISP event's attributes to attack description strings."""
        info   = event.get("info", "Unknown threat")
        attrs  = event.get("Attribute", [])
        tags   = [t.get("name", "") for t in event.get("Tag", [])]

        descs: list[str] = []
        for attr in attrs:
            atype  = attr.get("type", "")
            avalue = attr.get("value", "")
            if not avalue or atype not in _ATTR_TYPES:
                continue
            label = _ATTR_TYPES[atype]
            tag_str = ", ".join(tags[:3]) if tags else "unclassified"
            descs.append(
                f"Threat indicator [{label}]: {avalue} — from MISP event '{info}' "
                f"(tags: {tag_str}). This represents a known malicious indicator "
                f"that should be treated as a HIGH-risk prompt or request containing this value."
            )
        return descs[:10]  # cap per event

    async def sync(self) -> MISPSyncResult:
        result = MISPSyncResult()
        try:
            events = await self._fetch_events()
        except Exception as exc:
            result.errors.append(f"MISP fetch failed: {exc}")
            log.error("MISP sync: fetch failed: %s", exc)
            return result

        result.events_fetched = len(events)
        all_descriptions: list[str] = []

        for event in events:
            descs = self._event_to_descriptions(event)
            all_descriptions.extend(descs)
            result.attrs_extracted += len(descs)

        if not all_descriptions:
            log.info("MISP sync: no usable attributes found in %d events", result.events_fetched)
            return result

        try:
            from warden.brain.evolve import EvolutionEngine  # noqa: PLC0415
            engine = EvolutionEngine()
            pseudo_paper = (
                "MISP Threat Intelligence Sync\n\n"
                + "\n".join(f"- {d}" for d in all_descriptions)
            )
            added = await engine.synthesize_from_intel(
                pseudo_paper,
                title="MISP Threat Intelligence Sync",
                link="",
            )
            result.examples_added = added if isinstance(added, int) else len(added or [])
        except Exception as exc:
            result.errors.append(f"Evolution Engine synthesis failed: {exc}")
            log.warning("MISP sync: synthesis failed: %s", exc)

        log.info(
            "MISP sync: events=%d attrs=%d examples_added=%d errors=%d",
            result.events_fetched, result.attrs_extracted, result.examples_added, len(result.errors),
        )
        return result
