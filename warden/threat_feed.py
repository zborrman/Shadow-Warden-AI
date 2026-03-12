"""
warden/threat_feed.py
─────────────────────
Shadow Warden AI — Threat Intelligence Feed Client.

Opt-in, privacy-first feed that lets Shadow Warden instances share
anonymised attack rules and benefit from the collective intelligence
of the entire fleet.

How it works
────────────
1.  When the Evolution Engine generates a new rule from a real attack,
    ``ThreatFeedClient.submit_rule()`` anonymises it and POSTs it to the
    central feed server (your SaaS or self-hosted instance).

2.  A background loop calls ``ThreatFeedClient.sync()`` every N hours.
    It downloads ``/v1/feed.json`` and loads any new examples into the
    local ``BrainSemanticGuard`` corpus via ``add_examples()``.

3.  Anonymisation: only the rule text (pattern / semantic example) is
    submitted.  No content, no tenant identity, no IP addresses.  Each
    submission is tagged with a random ``source_id`` that rotates daily.

Privacy guarantees
──────────────────
  • Opt-in only (``THREAT_FEED_ENABLED=true`` in .env)
  • No original payload content is ever submitted
  • Submitted rules are vetted by the feed server before publication
  • ``source_id`` is a daily-rotating random hex — unlinked to tenant_id

Pricing tiers (for the hosted SaaS feed at shadowwarden.ai)
────────────────────────────────────────────────────────────
  Free  — read-only, daily refresh, up to 500 rules
  Pro   — read-write, hourly refresh, unlimited rules   ($49/mo)
  MSP   — priority feed + SLA + SOC report             ($199/mo)

Environment variables
─────────────────────
  THREAT_FEED_ENABLED    true/false           (default: false)
  THREAT_FEED_URL        https://…/v1         (default: disabled)
  THREAT_FEED_API_KEY    hex key for write     (default: "")
  THREAT_FEED_SYNC_HRS   hours between sync    (default: 6)
  THREAT_FEED_MAX_RULES  cap on imported rules (default: 500)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from warden.brain.semantic import SemanticGuard as BrainSemanticGuard

log = logging.getLogger("warden.threat_feed")

# ── Config ────────────────────────────────────────────────────────────────────

_ENABLED        = os.getenv("THREAT_FEED_ENABLED", "false").lower() == "true"
_FEED_URL       = os.getenv("THREAT_FEED_URL", "").rstrip("/")
_FEED_API_KEY   = os.getenv("THREAT_FEED_API_KEY", "")
_SYNC_HRS       = float(os.getenv("THREAT_FEED_SYNC_HRS", "6"))
_MAX_RULES      = int(os.getenv("THREAT_FEED_MAX_RULES", "500"))
_CACHE_PATH     = Path(os.getenv("THREAT_FEED_CACHE_PATH", "/warden/data/threat_feed_cache.json"))

# Rotating daily source_id — unlinked to tenant identity
def _daily_source_id() -> str:
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    return hashlib.sha256(f"shadow-warden-source-{today}".encode()).hexdigest()[:16]


# ── Anonymiser ────────────────────────────────────────────────────────────────

# Strip any patterns that look like real PII before submission
_STRIP_PATTERNS = [
    re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),  # email
    re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),                # SSN
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),                           # credit card
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                               # OpenAI key
    re.compile(r"sk-ant-[A-Za-z0-9\-_]{30,}"),                       # Anthropic key
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),                              # GitHub token
    re.compile(r"hf_[A-Za-z0-9]{30,}"),                               # HuggingFace token
]

def _anonymise(text: str) -> str:
    """Strip PII / secrets from a rule string before it leaves the box."""
    for pat in _STRIP_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text.strip()


# ── Feed entry schema ─────────────────────────────────────────────────────────

@dataclass
class FeedRule:
    rule_id:     str
    rule_type:   str      # "semantic_example" | "regex_pattern"
    value:       str      # the anonymised rule text
    attack_type: str      # e.g. "jailbreak", "prompt_injection", "data_exfil"
    risk_level:  str      # "high" | "block"
    published:   str      # ISO-8601 timestamp
    source_id:   str      # daily-rotating opaque hex
    downloads:   int = 0  # how many instances have imported this rule


@dataclass
class FeedStatus:
    enabled:         bool
    feed_url:        str
    last_sync:       str | None
    next_sync:       str | None
    rules_imported:  int
    rules_submitted: int
    errors:          list[str] = field(default_factory=list)


# ── Client ────────────────────────────────────────────────────────────────────

class ThreatFeedClient:
    """
    Opt-in client that downloads shared threat rules and publishes new ones.

    Thread-safe: all state changes are protected by _lock.
    Fail-open: any network error is logged and swallowed — the local
    Warden continues to protect even when the feed is unreachable.
    """

    def __init__(
        self,
        guard:       BrainSemanticGuard | None = None,
        feed_url:    str = _FEED_URL,
        api_key:     str = _FEED_API_KEY,
        enabled:     bool = _ENABLED,
        max_rules:   int = _MAX_RULES,
        cache_path:  Path = _CACHE_PATH,
    ) -> None:
        self._guard       = guard
        self._feed_url    = feed_url.rstrip("/")
        self._api_key     = api_key
        self._enabled     = enabled and bool(feed_url)
        self._max_rules   = max_rules
        self._cache_path  = cache_path
        self._lock        = threading.Lock()

        # Persisted state
        self._imported:   set[str] = set()   # rule_ids already in corpus
        self._submitted:  int      = 0
        self._last_sync:  str | None = None
        self._errors:     list[str] = []

        self._load_cache()

    # ── Public API ────────────────────────────────────────────────────────────

    def is_enabled(self) -> bool:
        return self._enabled

    def sync(self) -> int:
        """
        Download the feed and load new rules into the guard corpus.
        Returns the number of new rules imported (0 on error or if disabled).
        """
        if not self._enabled:
            return 0
        try:
            return self._do_sync()
        except Exception as exc:
            msg = f"sync failed: {exc}"
            log.warning("ThreatFeed: %s", msg)
            with self._lock:
                self._errors.append(msg)
                if len(self._errors) > 20:
                    self._errors = self._errors[-20:]
            return 0

    def submit_rule(
        self,
        rule_text:   str,
        rule_type:   str = "semantic_example",
        attack_type: str = "jailbreak",
        risk_level:  str = "high",
    ) -> bool:
        """
        Anonymise and submit a rule to the central feed.
        Returns True if successfully submitted, False otherwise.
        Only submits when THREAT_FEED_ENABLED=true and an API key is set.
        """
        if not self._enabled or not self._api_key:
            return False
        clean = _anonymise(rule_text)
        if len(clean) < 10:
            log.debug("ThreatFeed: rule too short after anonymisation — skipped.")
            return False
        try:
            return self._do_submit(clean, rule_type, attack_type, risk_level)
        except Exception as exc:
            log.warning("ThreatFeed: submit failed — %s", exc)
            return False

    def status(self) -> FeedStatus:
        with self._lock:
            next_sync = None
            if self._last_sync:
                try:
                    t = datetime.fromisoformat(self._last_sync)
                    next_sync = (t + timedelta(hours=_SYNC_HRS)).isoformat()
                except ValueError:
                    pass
            return FeedStatus(
                enabled         = self._enabled,
                feed_url        = self._feed_url,
                last_sync       = self._last_sync,
                next_sync       = next_sync,
                rules_imported  = len(self._imported),
                rules_submitted = self._submitted,
                errors          = list(self._errors[-5:]),
            )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _do_sync(self) -> int:
        log.info("ThreatFeed: syncing from %s …", self._feed_url)
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["X-Feed-Key"] = self._api_key

        r = httpx.get(
            f"{self._feed_url}/feed.json",
            headers=headers,
            timeout=15,
            follow_redirects=True,
        )
        r.raise_for_status()
        feed: dict = r.json()

        rules: list[dict] = feed.get("rules", [])
        new_examples: list[str] = []

        with self._lock:
            for rule in rules:
                rid = rule.get("rule_id", "")
                if not rid or rid in self._imported:
                    continue
                if len(self._imported) >= self._max_rules:
                    log.info("ThreatFeed: import cap (%d) reached.", self._max_rules)
                    break
                rtype = rule.get("rule_type", "semantic_example")
                value = rule.get("value", "").strip()
                if not value:
                    continue
                self._imported.add(rid)
                if rtype == "semantic_example" and self._guard is not None:
                    new_examples.append(value)

            self._last_sync = datetime.now(UTC).isoformat()

        if new_examples and self._guard is not None:
            self._guard.add_examples(new_examples)
            log.info("ThreatFeed: loaded %d new rule(s) into corpus.", len(new_examples))

        self._save_cache()
        return len(new_examples)

    def _do_submit(
        self,
        clean_rule:  str,
        rule_type:   str,
        attack_type: str,
        risk_level:  str,
    ) -> bool:
        payload = {
            "rule_type":   rule_type,
            "value":       clean_rule,
            "attack_type": attack_type,
            "risk_level":  risk_level,
            "source_id":   _daily_source_id(),
        }
        r = httpx.post(
            f"{self._feed_url}/rules",
            json=payload,
            headers={
                "X-Feed-Key":    self._api_key,
                "Content-Type":  "application/json",
            },
            timeout=10,
        )
        r.raise_for_status()
        with self._lock:
            self._submitted += 1
        log.info("ThreatFeed: submitted rule (attack_type=%s).", attack_type)
        return True

    def _load_cache(self) -> None:
        """Restore previously imported rule_ids from disk (survive restarts)."""
        if not self._cache_path.exists():
            return
        try:
            data = json.loads(self._cache_path.read_text(encoding="utf-8"))
            self._imported   = set(data.get("imported", []))
            self._submitted  = int(data.get("submitted", 0))
            self._last_sync  = data.get("last_sync")
        except Exception as exc:
            log.warning("ThreatFeed: could not load cache — %s", exc)

    def _save_cache(self) -> None:
        """Persist imported rule_ids so we don't re-import after restart."""
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "imported":   list(self._imported),
            "submitted":  self._submitted,
            "last_sync":  self._last_sync,
            "saved_at":   datetime.now(UTC).isoformat(),
        }
        import tempfile
        tmp = self._cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        import os as _os
        _os.replace(tmp, self._cache_path)
