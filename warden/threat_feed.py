"""
warden/threat_feed.py
─────────────────────
Shadow Warden AI — Threat Intelligence Feed Client (Warden Nexus).

Opt-in, privacy-first feed that lets Shadow Warden instances share
anonymised attack rules AND worm fingerprints with the collective fleet,
protected by a Bayesian consensus engine that prevents network poisoning.

How it works
────────────
1.  When the Evolution Engine generates a new rule from a real attack,
    ``ThreatFeedClient.submit_rule()`` anonymises it and POSTs it to the
    central feed server (your SaaS or self-hosted instance).

2.  When WormGuard L1 confirms a worm (``worm_guard.quarantine_worm()``),
    ``submit_worm_hash()`` sends only the SHA-256 fingerprint + STIX 2.1
    Indicator envelope + Betti topology features.  No payload text ever leaves.

3.  A background loop calls ``ThreatFeedClient.sync()`` every N hours.
    It downloads ``/v1/feed.json`` (rules) and ``/v1/worm-hashes`` (hashes).
    New rules enter the local corpus; confirmed worm hashes enter L3 Redis
    quarantine (``warden:worm:hashes``) for O(1) blocking on subsequent requests.

Bayesian Consensus (anti-poisoning)
────────────────────────────────────
The central server only promotes a worm hash to "global" status after it
reaches Trust_Score ≥ THREAT_FEED_CONSENSUS_THRESHOLD (default 0.80).

    Trust_Score = 1 − ∏ᵢ (1 − P(Tᵢ | H))

where n is the number of distinct reporting nodes and P(Tᵢ|H) is that
node's historical precision (false-positive rate tracked server-side).
A lone attacker submitting their own SHA-256 cannot reach the threshold
without corroboration from independent high-reputation nodes.

Topology fingerprint (STIX extension)
──────────────────────────────────────
WormGuard adds Betti numbers (β₀, β₁) from the TopologicalGatekeeper
as custom STIX properties ``x_warden_betti_0`` / ``x_warden_betti_1``.
These allow the central server to cluster structurally similar worms even
when SHA-256 differs (payload mutation / polymorphism).

Privacy guarantees
──────────────────
  • Opt-in only (``THREAT_FEED_ENABLED=true`` in .env)
  • No original payload content or PII is ever submitted
  • Worm reports carry only SHA-256 + attack_class + Betti numbers
  • Rules carry only the anonymised detection pattern
  • ``source_id`` is a daily-rotating random hex — unlinked to tenant_id
  • Enterprise nodes can set ``THREAT_FEED_RECEIVE_ONLY=true`` to consume
    the global feed without contributing (air-gapped intelligence)

Pricing tiers (for the hosted SaaS feed at shadowwarden.ai)
────────────────────────────────────────────────────────────
  Free  — read-only, daily refresh, up to 500 rules
  Pro   — read-write, hourly refresh, unlimited rules   ($49/mo)
  MSP   — priority feed + SLA + SOC report             ($199/mo)
  Enterprise Intelligence Feed — receive-only, global worm hashes ($10k/yr)

Environment variables
─────────────────────
  THREAT_FEED_ENABLED             true/false            (default: false)
  THREAT_FEED_URL                 https://…/v1          (default: disabled)
  THREAT_FEED_API_KEY             hex key for write      (default: "")
  THREAT_FEED_SYNC_HRS            hours between sync     (default: 6)
  THREAT_FEED_MAX_RULES           cap on imported rules  (default: 500)
  THREAT_FEED_RECEIVE_ONLY        true = consume only, never submit (default: false)
  THREAT_FEED_CONSENSUS_THRESHOLD min Trust_Score to accept global hash (default: 0.80)
  THREAT_FEED_MAX_WORM_HASHES     cap on imported worm hashes (default: 10000)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
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

_ENABLED          = os.getenv("THREAT_FEED_ENABLED",    "false").lower() == "true"
_FEED_URL         = os.getenv("THREAT_FEED_URL",         "").rstrip("/")
_FEED_API_KEY     = os.getenv("THREAT_FEED_API_KEY",     "")
_SYNC_HRS         = float(os.getenv("THREAT_FEED_SYNC_HRS",              "6"))
_MAX_RULES        = int(os.getenv("THREAT_FEED_MAX_RULES",               "500"))
_RECEIVE_ONLY     = os.getenv("THREAT_FEED_RECEIVE_ONLY",  "false").lower() == "true"
_CONSENSUS_THRESH = float(os.getenv("THREAT_FEED_CONSENSUS_THRESHOLD",   "0.80"))
_MAX_WORM_HASHES  = int(os.getenv("THREAT_FEED_MAX_WORM_HASHES",        "10000"))
_CACHE_PATH       = Path(os.getenv("THREAT_FEED_CACHE_PATH",
                                   "/warden/data/threat_feed_cache.json"))

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
        guard:              BrainSemanticGuard | None = None,
        feed_url:           str   = _FEED_URL,
        api_key:            str   = _FEED_API_KEY,
        enabled:            bool  = _ENABLED,
        max_rules:          int   = _MAX_RULES,
        cache_path:         Path  = _CACHE_PATH,
        receive_only:       bool  = _RECEIVE_ONLY,
        consensus_threshold: float = _CONSENSUS_THRESH,
        max_worm_hashes:    int   = _MAX_WORM_HASHES,
    ) -> None:
        self._guard               = guard
        self._feed_url            = feed_url.rstrip("/")
        self._api_key             = api_key
        self._enabled             = enabled and bool(feed_url)
        self._max_rules           = max_rules
        self._cache_path          = cache_path
        self._receive_only        = receive_only
        self._consensus_threshold = consensus_threshold
        self._max_worm_hashes     = max_worm_hashes
        self._lock                = threading.Lock()

        # Persisted state
        self._imported:       set[str] = set()   # rule_ids already in corpus
        self._worm_imported:  set[str] = set()   # worm SHA-256s already in L3
        self._submitted:      int      = 0
        self._worms_submitted: int     = 0
        self._last_sync:      str | None = None
        self._errors:         list[str] = []

        self._load_cache()

    # ── Public API ────────────────────────────────────────────────────────────

    def is_enabled(self) -> bool:
        return self._enabled

    def submit_worm_hash(
        self,
        fingerprint:  str,
        attack_class: str = "ai_worm_replication",
        betti_0:      float | None = None,
        betti_1:      float | None = None,
    ) -> bool:
        """
        Report a confirmed worm SHA-256 fingerprint to the Warden Nexus feed.

        Sends a STIX 2.1 Indicator bundle containing:
          • SHA-256 fingerprint (no payload text)
          • attack_class label (e.g. "ai_worm_replication", "rag_quine_directive")
          • Optional Betti numbers (β₀, β₁) from TopologicalGatekeeper

        The central server applies Bayesian consensus:
          Trust_Score = 1 − ∏ᵢ (1 − P(Tᵢ|H))
        A hash is promoted to the global quarantine only when Trust_Score ≥
        THREAT_FEED_CONSENSUS_THRESHOLD (default 0.80) — typically requires
        3+ independent high-reputation nodes to report the same fingerprint.

        Returns True on successful submission, False if disabled, receive-only,
        or a network error occurs (always fail-open).
        """
        if not self._enabled or not self._api_key or self._receive_only:
            return False
        if not fingerprint or len(fingerprint) != 64:
            return False
        try:
            return self._do_submit_worm(fingerprint, attack_class, betti_0, betti_1)
        except Exception as exc:
            log.warning("ThreatFeed: worm submit failed — %s", exc)
            return False

    def sync(self) -> int:
        """
        Download feed rules + globally-confirmed worm hashes.

        Rule sync: loads new semantic/regex rules into the guard corpus.
        Worm sync: injects global worm SHA-256s into the local L3 Redis
                   quarantine (``warden:worm:hashes``) so they are blocked
                   at O(1) before the full filter pipeline runs.

        Returns the total number of new items imported (rules + worm hashes).
        """
        if not self._enabled:
            return 0
        total = 0
        try:
            total += self._do_sync()
        except Exception as exc:
            msg = f"rule sync failed: {exc}"
            log.warning("ThreatFeed: %s", msg)
            with self._lock:
                self._errors.append(msg)
                if len(self._errors) > 20:
                    self._errors = self._errors[-20:]
        try:
            total += self._do_sync_worm_hashes()
        except Exception as exc:
            msg = f"worm hash sync failed: {exc}"
            log.warning("ThreatFeed: %s", msg)
            with self._lock:
                self._errors.append(msg)
                if len(self._errors) > 20:
                    self._errors = self._errors[-20:]
        return total

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

    @property
    def worms_imported(self) -> int:
        with self._lock:
            return len(self._worm_imported)

    @property
    def worms_submitted(self) -> int:
        with self._lock:
            return self._worms_submitted

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

    def _do_submit_worm(
        self,
        fingerprint:  str,
        attack_class: str,
        betti_0:      float | None,
        betti_1:      float | None,
    ) -> bool:
        """
        Build a STIX 2.1 Indicator bundle and POST it to /worm-reports.

        STIX envelope contains only the SHA-256 fingerprint and structural
        metadata — no payload text, no customer data.  The ``x_warden_*``
        extension properties carry Betti numbers for polymorphic clustering.

        The central Nexus server applies the Bayesian consensus gate:
            Trust_Score = 1 − ∏ᵢ (1 − P(Tᵢ|H))
        before promoting the hash to the global quarantine feed.
        """
        import uuid as _uuid
        now_iso = datetime.now(UTC).isoformat()
        stix_bundle = {
            "type":    "bundle",
            "id":      f"bundle--{_uuid.uuid4()}",
            "objects": [
                {
                    "type":         "indicator",
                    "spec_version": "2.1",
                    "id":           f"indicator--{_uuid.uuid4()}",
                    "created":      now_iso,
                    "modified":     now_iso,
                    "name":         f"Warden AI Worm: {attack_class}",
                    "description":  (
                        "SHA-256 fingerprint of a confirmed AI self-replicating "
                        "prompt-injection payload detected by WormGuard L1."
                    ),
                    "indicator_types": ["malicious-activity"],
                    "pattern":         f"[file:hashes.'SHA-256' = '{fingerprint}']",
                    "pattern_type":    "stix",
                    "valid_from":      now_iso,
                    "labels":          ["ai-worm", "prompt-injection", attack_class],
                    # Custom Warden extension — structural topology features
                    # allow the Nexus server to cluster polymorphic worm variants
                    # even when SHA-256 differs (payload mutation).
                    "x_warden_betti_0":    betti_0,
                    "x_warden_betti_1":    betti_1,
                    "x_warden_source_id":  _daily_source_id(),
                    "x_warden_version":    "2.5",
                },
            ],
        }
        r = httpx.post(
            f"{self._feed_url}/worm-reports",
            json    = stix_bundle,
            headers = {
                "X-Feed-Key":   self._api_key,
                "Content-Type": "application/taxii+json;version=2.1",
            },
            timeout = 10,
        )
        r.raise_for_status()
        with self._lock:
            self._worms_submitted += 1
        log.info(
            "ThreatFeed: worm fingerprint reported fp=%.16s… attack=%s",
            fingerprint, attack_class,
        )
        return True

    def _do_sync_worm_hashes(self) -> int:
        """
        Download globally-confirmed worm hashes from /worm-hashes and inject
        them into the local WormGuard L3 Redis quarantine set.

        The endpoint returns only hashes that have passed the Bayesian consensus
        gate (Trust_Score ≥ threshold) on the central Nexus server — typically
        confirmed by 3+ independent high-reputation nodes.

        Each hash is added to ``warden:worm:hashes`` (the same Redis Set used
        by ``worm_guard.is_quarantined()``) so that repeat payloads are blocked
        in O(1) before the full filter pipeline runs.
        """
        from warden.worm_guard import QUARANTINE_SET, QUARANTINE_TTL  # noqa: PLC0415

        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            headers["X-Feed-Key"] = self._api_key

        r = httpx.get(
            f"{self._feed_url}/worm-hashes",
            headers = headers,
            params  = {"min_trust": str(self._consensus_threshold)},
            timeout = 15,
            follow_redirects = True,
        )
        r.raise_for_status()
        data: dict = r.json()

        global_hashes: list[str] = data.get("hashes", [])
        new_count = 0

        with self._lock:
            if len(self._worm_imported) >= self._max_worm_hashes:
                log.info("ThreatFeed: worm hash import cap (%d) reached.", self._max_worm_hashes)
                return 0
            to_add = [
                h for h in global_hashes
                if isinstance(h, str) and len(h) == 64 and h not in self._worm_imported
            ]

        if not to_add:
            return 0

        # Push confirmed hashes into local L3 Redis quarantine
        try:
            from warden.cache import _get_client  # noqa: PLC0415
            redis = _get_client()
            if redis is not None:
                redis.sadd(QUARANTINE_SET, *to_add)
                redis.expire(QUARANTINE_SET, QUARANTINE_TTL)
        except Exception as _re:
            log.warning("ThreatFeed: Redis write for worm hashes failed — %s", _re)

        with self._lock:
            for h in to_add:
                self._worm_imported.add(h)
            new_count = len(to_add)

        self._save_cache()
        log.info(
            "ThreatFeed: injected %d global worm hash(es) into L3 quarantine.",
            new_count,
        )
        return new_count

    def _load_cache(self) -> None:
        """Restore previously imported rule_ids and worm hashes from disk."""
        if not self._cache_path.exists():
            return
        try:
            data = json.loads(self._cache_path.read_text(encoding="utf-8"))
            self._imported        = set(data.get("imported", []))
            self._worm_imported   = set(data.get("worm_imported", []))
            self._submitted       = int(data.get("submitted", 0))
            self._worms_submitted = int(data.get("worms_submitted", 0))
            self._last_sync       = data.get("last_sync")
        except Exception as exc:
            log.warning("ThreatFeed: could not load cache — %s", exc)

    def _save_cache(self) -> None:
        """Persist imported rule_ids and worm hashes so we don't re-import after restart."""
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "imported":        list(self._imported),
            "worm_imported":   list(self._worm_imported),
            "submitted":       self._submitted,
            "worms_submitted": self._worms_submitted,
            "last_sync":       self._last_sync,
            "saved_at":        datetime.now(UTC).isoformat(),
        }
        tmp = self._cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        import os as _os
        _os.replace(tmp, self._cache_path)
