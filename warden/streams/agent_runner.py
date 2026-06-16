"""
warden/streams/agent_runner.py
────────────────────────────────
Simulated Flink agent runner — stateful stream processing for marketplace events.

Subscribes to marketplace.* and community.* Kafka topics.
Maintains per-community agent state in Redis.
Can be launched as a background asyncio task inside FastAPI lifespan.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import UTC, datetime, timedelta

log = logging.getLogger("warden.streams.agent_runner")

_REDIS_URL        = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_ESCROW_TIMEOUT_H = int(os.getenv("ESCROW_TIMEOUT_HOURS", "48"))


def _redis():
    try:
        import redis as _r  # noqa: PLC0415
        if _REDIS_URL.startswith("memory://"):
            return None
        return _r.from_url(_REDIS_URL, decode_responses=True)
    except Exception:
        return None


class FlinkAgentRunner:
    """
    Stateful event-driven agent runner.

    State key schema:
      agent_runner:{community_id}:state  — JSON dict with community-level counters
      agent_runner:escrow:{escrow_id}:ts — ISO timestamp of when escrow reached funded
    """

    def __init__(self) -> None:
        self._running = False
        self._tasks:  list[asyncio.Task] = []

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start background consumers. Safe to call multiple times."""
        if self._running:
            return
        self._running = True
        from warden.streams.event_bus import get_event_bus  # noqa: PLC0415
        bus = get_event_bus()
        await bus.start()

        self._tasks = [
            asyncio.create_task(
                bus.consume("marketplace.escrow", "runner-escrow", self._on_escrow),
                name="runner-escrow",
            ),
            asyncio.create_task(
                bus.consume("marketplace.listings", "runner-listings", self._on_listing),
                name="runner-listings",
            ),
            asyncio.create_task(
                self._watchdog_loop(),
                name="runner-watchdog",
            ),
        ]
        log.info("FlinkAgentRunner: started (%d tasks)", len(self._tasks))

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        log.info("FlinkAgentRunner: stopped.")

    # ── Event handlers ────────────────────────────────────────────────────────

    async def _on_escrow(self, key: str, value: dict) -> None:
        """Handle marketplace.escrow events."""
        escrow_id = key or value.get("escrow_id", "")
        status    = value.get("status", "")
        log.debug("FlinkAgentRunner: escrow %s → %s", escrow_id, status)

        if status == "funded":
            self._record_escrow_funded(escrow_id)
            self._update_state(value.get("community_id", ""), "escrows_funded", 1)

        elif status in ("confirmed", "cancelled", "resolved_buyer", "resolved_seller"):
            self._clear_escrow_watchdog(escrow_id)
            self._update_state(value.get("community_id", ""), f"escrows_{status}", 1)

    async def _on_listing(self, key: str, value: dict) -> None:
        """Handle marketplace.listings events."""
        status       = value.get("status", "")
        community_id = value.get("community_id", key)
        log.debug("FlinkAgentRunner: listing %s → %s", key, status)

        self._update_state(community_id, "listing_count", 1)
        if status == "published":
            self._update_state(community_id, "listings_published", 1)
        elif status == "purchased":
            self._update_state(community_id, "listings_purchased", 1)

    # ── Watchdog — auto-dispute stuck escrows ─────────────────────────────────

    async def _watchdog_loop(self) -> None:
        """Periodically check for funded escrows that have timed out."""
        while self._running:
            try:
                self._check_timed_out_escrows()
            except Exception as exc:
                log.debug("FlinkAgentRunner watchdog error: %s", exc)
            await asyncio.sleep(300)  # every 5 minutes

    def _check_timed_out_escrows(self) -> None:
        r = _redis()
        if not r:
            return
        threshold = datetime.now(UTC) - timedelta(hours=_ESCROW_TIMEOUT_H)
        keys = r.keys("agent_runner:escrow:*:ts")
        for key in keys:
            try:
                ts_str    = r.get(key)
                ts        = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
                if ts < threshold:
                    escrow_id = key.split(":")[2]
                    log.warning(
                        "FlinkAgentRunner: escrow %s timed out (%dh), raising auto-dispute.",
                        escrow_id, _ESCROW_TIMEOUT_H,
                    )
                    asyncio.create_task(self._auto_dispute("", escrow_id))
                    r.delete(key)
            except Exception as exc:
                log.debug("FlinkAgentRunner watchdog entry error: %s", exc)

    async def _auto_dispute(self, community_id: str, escrow_id: str) -> None:
        """Trigger an automatic dispute for a timed-out escrow (fail-open)."""
        try:
            from warden.marketplace.escrow import EscrowService  # noqa: PLC0415
            svc = EscrowService()
            svc.raise_dispute(escrow_id, reason="Escrow auto-dispute: timeout exceeded.")
            log.info("FlinkAgentRunner: auto-dispute raised for escrow %s", escrow_id)
        except Exception as exc:
            log.warning("FlinkAgentRunner: auto-dispute failed for %s: %s", escrow_id, exc)

    # ── State helpers ─────────────────────────────────────────────────────────

    _mem_state: dict[str, dict[str, int]] = {}  # in-process fallback when Redis unavailable

    def _update_state(self, community_id: str, counter: str, delta: int) -> None:
        if not community_id:
            return
        r = _redis()
        if r:
            try:
                key = f"agent_runner:{community_id}:state"
                r.hincrby(key, counter, delta)
                r.expire(key, 86_400 * 30)
                return
            except Exception:
                pass
        bucket = FlinkAgentRunner._mem_state.setdefault(community_id, {})
        bucket[counter] = bucket.get(counter, 0) + delta

    def get_state(self, community_id: str) -> dict:
        r = _redis()
        if r:
            try:
                return dict(r.hgetall(f"agent_runner:{community_id}:state"))
            except Exception:
                pass
        return dict(FlinkAgentRunner._mem_state.get(community_id, {}))

    def _record_escrow_funded(self, escrow_id: str) -> None:
        r = _redis()
        if r:
            try:
                key = f"agent_runner:escrow:{escrow_id}:ts"
                r.set(key, datetime.now(UTC).isoformat(), ex=86_400 * 7)
            except Exception:
                pass

    def _clear_escrow_watchdog(self, escrow_id: str) -> None:
        r = _redis()
        if r:
            with __import__("contextlib").suppress(Exception):
                r.delete(f"agent_runner:escrow:{escrow_id}:ts")


# ── Module-level singleton ─────────────────────────────────────────────────────

_runner: FlinkAgentRunner | None = None


def get_runner() -> FlinkAgentRunner:
    global _runner
    if _runner is None:
        _runner = FlinkAgentRunner()
    return _runner
