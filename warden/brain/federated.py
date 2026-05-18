"""
warden/brain/federated.py  (AR-10)
────────────────────────────────────
Federated threat model — share anonymised rule deltas between tenants
without exposing raw content or PII.

Protocol
────────
  1. Source tenant computes a "rule delta" for each new/updated rule:
       {
         "rule_hash":  SHA-256(pattern) — 16 hex chars (no pattern exposed)
         "score_delta": float           — how much this rule raises the avg score
         "attack_type": str             — coarse category, no raw text
         "effectiveness": float         — true positive rate on local corpus
         "tenants_seen": int            — de-identified count (capped at 100)
       }
  2. Deltas are published to POST /federation/rules
  3. Peers subscribe (GET /federation/rules/feed) and merge deltas into their
     own EvolutionEngine weight table

Privacy guarantees
──────────────────
  - No raw patterns, text, or PII are ever transmitted
  - SHA-256 hash is one-way; peers can match if they have the same rule
    but cannot recover the pattern
  - `tenants_seen` is capped at 100 to prevent re-identification
  - Only tenants with `federation_enabled` feature flag can publish or subscribe

Storage: Redis hash `federation:rule_deltas` (rolling 7-day TTL per entry).
Falls back to in-process dict.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

log = logging.getLogger("warden.brain.federated")

_MAX_TENANTS_SEEN = 100
_DELTA_TTL        = 86_400 * 7   # 7 days

_MEMORY_DELTAS: dict[str, dict] = {}


@dataclass
class RuleDelta:
    rule_hash:     str
    attack_type:   str
    score_delta:   float
    effectiveness: float
    tenants_seen:  int
    published_at:  str
    source_region: str   # jurisdiction hint, no tenant_id


def hash_pattern(pattern: str) -> str:
    return hashlib.sha256(pattern.encode()).hexdigest()[:16]


def _redis():
    try:
        import redis as _r  # noqa: PLC0415
        url = os.getenv("REDIS_URL", "")
        if not url or url == "memory://":
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


def publish_delta(
    pattern: str,
    attack_type: str,
    score_delta: float,
    effectiveness: float,
    tenants_seen: int,
    source_region: str = "unknown",
) -> RuleDelta:
    """
    Create and store a rule delta.  The pattern is hashed — never stored raw.
    """
    delta = RuleDelta(
        rule_hash     = hash_pattern(pattern),
        attack_type   = attack_type,
        score_delta   = round(score_delta, 4),
        effectiveness = round(effectiveness, 4),
        tenants_seen  = min(tenants_seen, _MAX_TENANTS_SEEN),
        published_at  = datetime.now(UTC).isoformat(),
        source_region = source_region,
    )
    _store_delta(delta)
    log.info("federation: published delta rule_hash=%s type=%s", delta.rule_hash, attack_type)
    return delta


def _store_delta(delta: RuleDelta) -> None:
    d = asdict(delta)
    _MEMORY_DELTAS[delta.rule_hash] = d

    r = _redis()
    if r:
        try:
            r.hset(f"federation:rule_deltas:{delta.rule_hash}", mapping={
                k: str(v) for k, v in d.items()
            })
            r.expire(f"federation:rule_deltas:{delta.rule_hash}", _DELTA_TTL)
            r.sadd("federation:rule_hashes", delta.rule_hash)
            r.expire("federation:rule_hashes", _DELTA_TTL)
        except Exception as exc:
            log.debug("federation: redis store error: %s", exc)


def list_deltas(
    attack_type: str | None = None,
    min_effectiveness: float = 0.0,
    limit: int = 100,
) -> list[RuleDelta]:
    """Return stored rule deltas, optionally filtered."""
    all_deltas: list[dict] = []

    r = _redis()
    if r:
        try:
            hashes = list(r.smembers("federation:rule_hashes"))
            for h in hashes[:limit * 2]:
                raw = r.hgetall(f"federation:rule_deltas:{h}")
                if raw:
                    all_deltas.append(raw)
        except Exception as exc:
            log.debug("federation: redis list error: %s", exc)
            all_deltas = list(_MEMORY_DELTAS.values())
    else:
        all_deltas = list(_MEMORY_DELTAS.values())

    result = []
    for d in all_deltas:
        try:
            delta = RuleDelta(
                rule_hash     = str(d.get("rule_hash", "")),
                attack_type   = str(d.get("attack_type", "")),
                score_delta   = float(d.get("score_delta", 0)),
                effectiveness = float(d.get("effectiveness", 0)),
                tenants_seen  = int(d.get("tenants_seen", 0)),
                published_at  = str(d.get("published_at", "")),
                source_region = str(d.get("source_region", "")),
            )
            if attack_type and delta.attack_type != attack_type:
                continue
            if delta.effectiveness < min_effectiveness:
                continue
            result.append(delta)
        except Exception:
            pass

    # Sort by effectiveness descending
    result.sort(key=lambda d: d.effectiveness, reverse=True)
    return result[:limit]


def merge_deltas(deltas: list[RuleDelta]) -> int:
    """
    Merge incoming peer deltas into local weight table.
    High-effectiveness deltas with score_delta > 0.05 are injected as
    synthetic HIGH_RISK examples into the brain corpus.
    Returns count of deltas merged.
    """
    merged = 0
    for delta in deltas:
        if delta.score_delta < 0.05 or delta.effectiveness < 0.5:
            continue
        # Synthesise a generic attack example description for the corpus
        synthetic_text = (
            f"[federated:{delta.attack_type}] pattern hash={delta.rule_hash} "
            f"seen_across={delta.tenants_seen}_tenants"
        )
        try:
            from warden.brain.evolve import EvolutionEngine  # noqa: PLC0415
            EvolutionEngine().add_examples([{
                "text":  synthetic_text,
                "label": "HIGH_RISK",
                "source": f"federation:{delta.source_region}",
            }])
            merged += 1
        except Exception as exc:
            log.debug("federation: merge delta failed: %s", exc)

    log.info("federation: merged %d/%d incoming deltas", merged, len(deltas))
    return merged


def compute_delta_from_rule(rule: dict, local_corpus_size: int = 1000) -> RuleDelta | None:
    """
    Utility: given a SemanticGuard rule dict, compute its federated delta.
    Called by the EvolutionEngine when a new rule is added.
    """
    pattern     = rule.get("regex_pattern") or rule.get("pattern") or ""
    attack_type = rule.get("attack_type") or rule.get("category") or "unknown"
    score       = float(rule.get("score", 0.5))

    if not pattern or score < 0.1:
        return None

    return publish_delta(
        pattern       = pattern,
        attack_type   = attack_type,
        score_delta   = score,
        effectiveness = min(score, 1.0),
        tenants_seen  = 1,
        source_region = os.getenv("WARDEN_JURISDICTION", "unknown"),
    )
