"""
ThreatVault — Adversarial prompt signature library for Shadow Warden AI.

Loads threat signatures from data/signatures/threat_feed.json and provides
a fast scan() method used as Stage 1.5 in the filter pipeline.

Signatures are matched before the heavy ML stage to catch well-known jailbreak
templates and prompt-injection techniques with near-zero latency.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Resolved at import time; override via THREAT_FEED_PATH env var.
_DEFAULT_FEED_PATH = Path(
    os.getenv("THREAT_FEED_PATH", "data/signatures/threat_feed.json")
)

SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
}


@dataclass
class ThreatMatch:
    threat_id:     str
    name:          str
    category:      str
    severity:      str   # critical | high | medium | low
    owasp:         str   # LLM01 .. LLM10
    description:   str
    neutralization: str
    pattern_type:  str   # regex | keyword | phrase


class ThreatVault:
    """
    Signature-based adversarial prompt scanner.

    Thread-safe; supports hot-reload from disk without restart.
    Used as Stage 1.5 in the filter pipeline — after secret redaction,
    before the rule-based semantic analyser.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self._path: Path = Path(path) if path else _DEFAULT_FEED_PATH
        self._lock: threading.RLock = threading.RLock()
        self._threats:  list[dict]  = []
        self._compiled: list[tuple] = []   # (meta_dict, compiled_pattern_or_keyword_list)
        self._version:  str         = ""
        self._loaded_at: float      = 0.0
        self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, text: str) -> list[ThreatMatch]:
        """Scan *text* against all loaded signatures.  Returns unique matches."""
        matches: list[ThreatMatch] = []
        text_lower = text.lower()

        with self._lock:
            compiled_snapshot = list(self._compiled)

        for meta, pattern in compiled_snapshot:
            ptype = meta.get("pattern_type", "regex")
            hit = False
            try:
                if ptype == "regex":
                    hit = bool(pattern.search(text))
                elif ptype == "keyword":
                    hit = any(kw in text_lower for kw in pattern)
                elif ptype == "phrase":
                    hit = bool(pattern.search(text_lower))
            except Exception:
                continue

            if hit:
                matches.append(ThreatMatch(
                    threat_id=meta["id"],
                    name=meta["name"],
                    category=meta.get("category", "unknown"),
                    severity=meta.get("severity", "medium"),
                    owasp=meta.get("owasp", "LLM01"),
                    description=meta.get("description", ""),
                    neutralization=meta.get("neutralization", ""),
                    pattern_type=ptype,
                ))

        # Deduplicate by threat_id while preserving first-match order
        seen: set[str] = set()
        unique: list[ThreatMatch] = []
        for m in matches:
            if m.threat_id not in seen:
                seen.add(m.threat_id)
                unique.append(m)
        return unique

    def reload(self) -> int:
        """Hot-reload signatures from disk.  Returns new signature count."""
        return self._load()

    def stats(self) -> dict[str, Any]:
        with self._lock:
            threats   = list(self._threats)
            version   = self._version
            loaded_at = self._loaded_at

        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_owasp:    dict[str, int] = {}

        for t in threats:
            sev = t.get("severity", "unknown")
            cat = t.get("category", "unknown")
            owasp = t.get("owasp", "unknown")
            by_severity[sev]   = by_severity.get(sev, 0) + 1
            by_category[cat]   = by_category.get(cat, 0) + 1
            by_owasp[owasp]    = by_owasp.get(owasp, 0) + 1

        return {
            "version":     version,
            "loaded_at":   loaded_at,
            "total":       len(threats),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_owasp":    by_owasp,
        }

    def list_threats(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "id":            t["id"],
                    "name":          t["name"],
                    "category":      t.get("category", ""),
                    "severity":      t.get("severity", ""),
                    "owasp":         t.get("owasp", ""),
                    "description":   t.get("description", ""),
                    "neutralization": t.get("neutralization", ""),
                    "pattern_type":  t.get("pattern_type", ""),
                }
                for t in self._threats
            ]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load(self) -> int:
        path = self._path
        if not path.exists():
            log.warning("ThreatVault: feed not found at %s — vault is empty.", path)
            return 0

        try:
            raw: dict = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.error("ThreatVault: failed to parse %s: %s", path, exc)
            return 0

        threats: list[dict] = raw.get("threats", [])
        compiled: list[tuple] = []
        errors = 0

        for t in threats:
            ptype = t.get("pattern_type", "regex")
            try:
                if ptype == "regex":
                    compiled.append((t, re.compile(t["pattern"], re.IGNORECASE | re.DOTALL)))
                elif ptype == "keyword":
                    kws = [kw.lower() for kw in t.get("keywords", [])]
                    compiled.append((t, kws))
                elif ptype == "phrase":
                    compiled.append((t, re.compile(re.escape(t["pattern"]), re.IGNORECASE)))
                else:
                    log.warning("ThreatVault: unknown pattern_type %r for %s", ptype, t.get("id"))
                    errors += 1
            except re.error as exc:
                log.warning("ThreatVault: bad regex for %s: %s", t.get("id"), exc)
                errors += 1

        with self._lock:
            self._threats   = threats
            self._compiled  = compiled
            self._version   = raw.get("version", "unknown")
            self._loaded_at = time.time()

        log.info(
            "ThreatVault: loaded %d signatures (v%s), %d compile errors.",
            len(compiled), self._version, errors,
        )
        return len(compiled)
