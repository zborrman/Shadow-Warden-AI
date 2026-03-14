"""
warden/threat_intel/scheduler.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
asyncio background loop: collect → analyze → synthesize → activate.

Registered in main.py lifespan() as an asyncio.Task.  Mirrors the pattern
used by the ThreatFeedClient sync loop in main.py:

    asyncio.create_task(_threat_intel_scheduler.loop())

Blocking I/O (collect, process_analyzed_batch) is offloaded to the default
ThreadPoolExecutor via loop.run_in_executor() to avoid blocking the event loop.
The analysis step (analyze_pending) is natively async.

Fail-open: any exception within run_once() is caught, logged, and the loop
continues indefinitely.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field

from warden.threat_intel.analyzer import ThreatIntelAnalyzer
from warden.threat_intel.collector import ThreatIntelCollector
from warden.threat_intel.rule_factory import RuleFactory

log = logging.getLogger("warden.threat_intel.scheduler")

_SYNC_HRS      = float(os.getenv("THREAT_INTEL_SYNC_HRS", "6"))
_STARTUP_DELAY = int(os.getenv("THREAT_INTEL_STARTUP_DELAY_S", "120"))   # wait for gateway warm-up
_ENABLED       = os.getenv("THREAT_INTEL_ENABLED", "false").lower() == "true"


@dataclass
class RunResult:
    collected:     int = 0
    analyzed:      int = 0
    rules_created: int = 0
    errors:        list[str] = field(default_factory=list)
    duration_ms:   float = 0.0


class ThreatIntelScheduler:
    """
    Drives the full threat intel pipeline on a configurable schedule.

    Usage (main.py lifespan)::

        if _ENABLED:
            _ti_task = asyncio.create_task(_threat_intel_scheduler.loop())
    """

    def __init__(
        self,
        collector: ThreatIntelCollector,
        analyzer:  ThreatIntelAnalyzer,
        factory:   RuleFactory,
    ) -> None:
        self._collector = collector
        self._analyzer  = analyzer
        self._factory   = factory

    async def run_once(self) -> RunResult:
        """
        Execute one full collection + analysis + synthesis cycle.
        Blocking calls are offloaded to the default thread pool.
        """
        t0 = time.monotonic()
        result = RunResult()

        loop = asyncio.get_running_loop()

        # ── Stage 1: collect from all external sources ────────────────────
        try:
            coll_result = await loop.run_in_executor(None, self._collector.collect)
            result.collected = coll_result.new_items
            result.errors.extend(coll_result.errors)
            log.info(
                "ThreatIntelScheduler: collected %d new items (%d dupes, %d errors).",
                coll_result.new_items,
                coll_result.skipped_duplicates,
                len(coll_result.errors),
            )
        except Exception as exc:
            result.errors.append(f"collect: {exc}")
            log.error("ThreatIntelScheduler: collection error — %s", exc)

        # ── Stage 2: analyze NEW items with Claude Haiku ──────────────────
        try:
            result.analyzed = await self._analyzer.analyze_pending(batch_size=20)
            log.info("ThreatIntelScheduler: analyzed %d items.", result.analyzed)
        except Exception as exc:
            result.errors.append(f"analyze: {exc}")
            log.error("ThreatIntelScheduler: analysis error — %s", exc)

        # ── Stage 3: synthesize and activate rules ────────────────────────
        try:
            result.rules_created = await loop.run_in_executor(
                None, self._factory.process_analyzed_batch, 20
            )
            log.info(
                "ThreatIntelScheduler: generated rules for %d items.",
                result.rules_created,
            )
        except Exception as exc:
            result.errors.append(f"synthesize: {exc}")
            log.error("ThreatIntelScheduler: synthesis error — %s", exc)

        result.duration_ms = round((time.monotonic() - t0) * 1000, 1)
        log.info(
            "ThreatIntelScheduler: run_once complete in %.1f ms — "
            "collected=%d analyzed=%d rules=%d errors=%d",
            result.duration_ms,
            result.collected,
            result.analyzed,
            result.rules_created,
            len(result.errors),
        )
        return result

    async def loop(self) -> None:
        """
        Infinite background loop.  Runs run_once() every THREAT_INTEL_SYNC_HRS hours.
        A startup delay allows the gateway to fully warm before the first collection.
        """
        log.info(
            "ThreatIntelScheduler: starting (delay=%ds, interval=%.1fh).",
            _STARTUP_DELAY, _SYNC_HRS,
        )
        await asyncio.sleep(_STARTUP_DELAY)

        while True:
            try:
                await self.run_once()
            except Exception as exc:
                log.error("ThreatIntelScheduler: unhandled error in loop — %s", exc)
            await asyncio.sleep(_SYNC_HRS * 3600)
