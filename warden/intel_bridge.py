"""
warden/intel_bridge.py
━━━━━━━━━━━━━━━━━━━━━
Auto-Evolution Bridge — connects Threat Intelligence to the Evolution Engine.

Workflow (synchronize_threats):
  1. WardenIntelOps.hunt_ai_threats()  — fetch latest ArXiv LLM-attack papers
  2. EvolutionEngine.synthesize_from_intel() — Claude Opus synthesises 5 attack
     examples per paper title (uses the same rate gate as normal evolution)
  3. SemanticGuard.add_examples()  — hot-reload: examples projected into Poincaré
     hyperbolic space immediately (no container restart required)

Activate from main.py lifespan:
    bridge = WardenIntelBridge(evolve_engine=_evolve, semantic_guard=_brain_guard)
    asyncio.create_task(bridge.run_loop())
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import UTC, datetime

import httpx

from warden.intel_ops import WardenIntelOps

log = logging.getLogger("warden.intel_bridge")

_SYNC_INTERVAL_HRS = float(os.getenv("INTEL_BRIDGE_INTERVAL_HRS", "6"))


class WardenIntelBridge:
    """
    Connects WardenIntelOps to EvolutionEngine + SemanticGuard.

    Parameters
    ----------
    evolve_engine   : EvolutionEngine instance (may be None in air-gapped mode)
    semantic_guard  : BrainSemanticGuard (SemanticGuard alias) instance
    """

    def __init__(self, evolve_engine, semantic_guard) -> None:  # type: ignore[annotation-unchecked]
        self.intel_ops     = WardenIntelOps()
        self.evolve        = evolve_engine
        self.semantic_guard = semantic_guard
        self._last_sync:  datetime | None = None
        self._synced_papers: set[str] = set()  # dedup by ArXiv link

    # ── One sync cycle ────────────────────────────────────────────────────────

    async def synchronize_threats(self) -> dict:
        """
        Run one synchronization cycle.

        Returns a summary dict::

            {
              "synced_at": "<iso>",
              "papers_found": 5,
              "papers_new": 3,
              "examples_added": 12,
            }
        """
        log.info("IntelBridge: starting threat synchronization cycle …")
        synced_at = datetime.now(UTC).isoformat()
        papers_new = 0
        examples_added = 0

        if self.evolve is None:
            log.warning(
                "IntelBridge: EvolutionEngine not available (air-gapped mode) — "
                "ArXiv papers fetched but synthesis skipped."
            )

        async with httpx.AsyncClient(timeout=20.0) as client:
            papers = await self.intel_ops.hunt_ai_threats(client)

        for paper in papers:
            link = paper.get("link", "")
            if link in self._synced_papers:
                log.debug("IntelBridge: already synced '%s' — skipping.", paper["title"][:60])
                continue
            self._synced_papers.add(link)
            papers_new += 1

            log.info("IntelBridge: synthesizing examples for '%s' …", paper["title"][:80])

            if self.evolve is not None:
                try:
                    new_examples = await self.evolve.synthesize_from_intel(
                        source=paper["source"],
                        title=paper["title"],
                        link=link,
                    )
                except Exception as exc:
                    log.warning("IntelBridge: synthesis error for '%s': %s", paper["title"][:60], exc)
                    new_examples = []

                if new_examples:
                    try:
                        self.semantic_guard.add_examples(new_examples)
                        examples_added += len(new_examples)
                        log.info(
                            "IntelBridge: +%d examples hot-loaded into SemanticGuard corpus.",
                            len(new_examples),
                        )
                    except Exception as exc:
                        log.warning("IntelBridge: add_examples error: %s", exc)

        self._last_sync = datetime.now(UTC)

        summary = {
            "synced_at":     synced_at,
            "papers_found":  len(papers),
            "papers_new":    papers_new,
            "examples_added": examples_added,
        }
        log.info(
            "IntelBridge: sync complete — %d new paper(s), %d example(s) added.",
            papers_new, examples_added,
        )
        return summary

    # ── Background loop ───────────────────────────────────────────────────────

    async def run_loop(self, interval_hrs: float = _SYNC_INTERVAL_HRS) -> None:
        """
        Background task: run synchronize_threats() every *interval_hrs* hours.
        Designed to be called via asyncio.create_task() from lifespan().
        """
        log.info(
            "IntelBridge: background loop started (interval=%.0fh).", interval_hrs
        )
        interval_s = interval_hrs * 3600
        while True:
            await asyncio.sleep(interval_s)
            try:
                await self.synchronize_threats()
            except Exception as exc:
                log.error("IntelBridge: unhandled error in sync loop: %s", exc)

    # ── Status ────────────────────────────────────────────────────────────────

    @property
    def status(self) -> dict:
        return {
            "last_sync":       self._last_sync.isoformat() if self._last_sync else None,
            "papers_deduped":  len(self._synced_papers),
            "engine_active":   self.evolve is not None,
            "interval_hrs":    _SYNC_INTERVAL_HRS,
        }
