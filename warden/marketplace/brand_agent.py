"""
warden/marketplace/brand_agent.py
──────────────────────────────────
Brand Agent — seller-side gateway filter (Stage 1 of the M2M 4-stage lifecycle).

In the M2M architecture, the Brand Agent intercepts every incoming buyer request
(send_proposal, send_offer, send_message, negotiate, buy) before it reaches the
seller's catalog or negotiation engine.  It enforces:

  1. Federation deny-list  — buyer DID in threat hash table → block
  2. TrustRank gate        — buyer reputation < BRAND_AGENT_MIN_TRUST → block
  3. Rate limit            — >BRAND_AGENT_MAX_RPM req/min per DID → throttle
  4. Capability gate       — buyer lacks 'marketplace_buy' capability → block

All checks are fail-open: if the underlying data source is unavailable the
request is allowed through and the failure is logged at DEBUG level.

Integration in dispatch_action():
    verdict = await BrandAgentFilter().validate(buyer_did, action_type, payload)
    if not verdict.allowed:
        return {"error": verdict.reason, "brand_agent_blocked": True}
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("warden.marketplace.brand_agent")

# Actions that route traffic TO a seller's catalog or negotiation channel.
# Only these pass through the Brand Agent gate.
_SELLER_FACING_ACTIONS = frozenset({
    "send_proposal", "send_offer", "send_message",
    "negotiate", "buy",
})

_MIN_TRUST = float(os.getenv("BRAND_AGENT_MIN_TRUST", "0.0"))   # 0 = gate off
_MAX_RPM   = int(os.getenv("BRAND_AGENT_MAX_RPM", "60"))         # req/min per DID
_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


@dataclass
class FilterVerdict:
    allowed:     bool
    reason:      str
    trust_score: float = 0.0
    action:      str   = ""
    checks:      dict  = field(default_factory=dict)


class BrandAgentFilter:
    """Seller-side gateway that validates buyer identity before routing proposals.

    Stateless except for the Redis client (lazy-init, one per filter instance).
    Instantiate once per request or reuse across requests safely.
    """

    def __init__(self, redis_url: str = _REDIS_URL) -> None:
        self._redis_url  = redis_url
        self._redis: Any = None
        self._use_memory = redis_url == "memory://"

    async def validate(
        self,
        buyer_did: str,
        action_type: str,
        payload: dict,
    ) -> FilterVerdict:
        """Run all gate checks in sequence.

        Short-circuits on first block.  Returns FilterVerdict(allowed=True) when
        buyer_did is empty or action is not seller-facing.
        """
        if not buyer_did or action_type not in _SELLER_FACING_ACTIONS:
            return FilterVerdict(
                allowed=True,
                reason="not_seller_facing",
                action=action_type,
            )

        checks: dict[str, Any] = {}

        # 1. Federation deny-list
        deny_ok = await self._check_deny_list(buyer_did)
        checks["deny_list"] = "pass" if deny_ok else "blocked"
        if not deny_ok:
            return FilterVerdict(
                allowed=False,
                reason="federation_deny_list: buyer DID is globally flagged",
                action=action_type,
                checks=checks,
            )

        # 2. TrustRank gate (only when threshold is set > 0)
        trust_score = self._get_trust_score(buyer_did)
        checks["trust_score"] = round(trust_score, 4)
        if _MIN_TRUST > 0 and trust_score < _MIN_TRUST:
            return FilterVerdict(
                allowed=False,
                reason=f"trust_too_low: score={trust_score:.3f} threshold={_MIN_TRUST}",
                trust_score=trust_score,
                action=action_type,
                checks=checks,
            )

        # 3. Rate limit (sliding window via Redis sorted set)
        rate_ok = await self._check_rate(buyer_did)
        checks["rate_limit"] = "pass" if rate_ok else "throttled"
        if not rate_ok:
            return FilterVerdict(
                allowed=False,
                reason=f"rate_limit: >{_MAX_RPM} requests/min for this DID",
                trust_score=trust_score,
                action=action_type,
                checks=checks,
            )

        # 4. Capability gate
        cap_ok = self._check_capability(buyer_did)
        checks["capability"] = "pass" if cap_ok else "missing"
        if not cap_ok:
            return FilterVerdict(
                allowed=False,
                reason="capability_missing: buyer lacks 'marketplace_buy'",
                trust_score=trust_score,
                action=action_type,
                checks=checks,
            )

        checks["result"] = "allowed"
        return FilterVerdict(
            allowed=True,
            reason="ok",
            trust_score=trust_score,
            action=action_type,
            checks=checks,
        )

    # ── Gate 1: Federation deny-list ──────────────────────────────────────────

    async def _check_deny_list(self, buyer_did: str) -> bool:
        """Return False if buyer DID is suspended in the marketplace agent registry."""
        try:
            from warden.marketplace.agent import get_agent  # noqa: PLC0415

            db = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
            agent = get_agent(buyer_did, db_path=db)
            if agent is not None and agent.status == "suspended":
                log.warning("BrandAgent: deny-list blocked suspended DID=%s...", buyer_did[:24])
                return False
        except Exception as exc:
            log.debug("BrandAgent._check_deny_list fail-open: %s", exc)
        return True

    # ── Gate 2: TrustRank ─────────────────────────────────────────────────────

    def _get_trust_score(self, buyer_did: str) -> float:
        """Return buyer's composite reputation score (0.0–1.0).  Fail-open → 1.0."""
        try:
            from warden.marketplace.reputation import ReputationEngine  # noqa: PLC0415

            db = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
            rep = ReputationEngine().get_score(buyer_did, db_path=db)
            return rep.score
        except Exception:
            return 1.0

    # ── Gate 3: Rate limit ────────────────────────────────────────────────────

    async def _check_rate(self, buyer_did: str) -> bool:
        """Sliding-window RPM check via Redis sorted set. Fail-open when no Redis."""
        if self._use_memory:
            return True
        try:
            r = await self._get_redis()
            if r is None:
                return True
            key   = f"brand_agent:rpm:{buyer_did}"
            now   = time.time()
            cutoff = now - 60.0
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, cutoff)
            pipe.zadd(key, {f"{now:.6f}": now})
            pipe.zcard(key)
            pipe.expire(key, 90)
            results = await pipe.execute()
            count = results[2]
            if count > _MAX_RPM:
                log.warning(
                    "BrandAgent: rate-limit hit DID=%s... count=%d limit=%d",
                    buyer_did[:24], count, _MAX_RPM,
                )
                return False
        except Exception as exc:
            log.debug("BrandAgent._check_rate fail-open: %s", exc)
        return True

    async def _get_redis(self) -> Any:
        if self._redis is None:
            try:
                import redis.asyncio as aioredis  # noqa: PLC0415

                client = aioredis.from_url(
                    self._redis_url,
                    socket_connect_timeout=5,
                    socket_timeout=3,
                    decode_responses=True,
                )
                await client.ping()  # type: ignore[misc]
                self._redis = client
            except Exception as exc:
                log.debug("BrandAgentFilter: Redis unavailable (%s)", exc)
        return self._redis

    # ── Gate 4: Capability ────────────────────────────────────────────────────

    def _check_capability(self, buyer_did: str) -> bool:
        """Return False if agent record exists but lacks 'marketplace_buy' cap."""
        try:
            from warden.marketplace.agent import get_agent  # noqa: PLC0415

            db = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
            agent = get_agent(buyer_did, db_path=db)
            if agent is None:
                return True  # unregistered agent passes (registration gate is separate)
            caps = agent.capabilities or []
            return "marketplace_buy" in caps
        except Exception:
            return True  # fail-open
