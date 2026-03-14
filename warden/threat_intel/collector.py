"""
warden/threat_intel/collector.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Orchestrates all ThreatSources, deduplicates by SHA-256(url), and persists
new items to ThreatIntelStore.

Each source is instantiated fresh per collection run to avoid state leakage.
Errors in individual sources are fail-open: logged and skipped so the other
sources still run.
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from warden.schemas import ThreatIntelItem, ThreatIntelStatus
from warden.threat_intel.sources import ALL_SOURCES, RawThreatItem, ThreatSource
from warden.threat_intel.store import ThreatIntelStore

log = logging.getLogger("warden.threat_intel.collector")

_MAX_ITEMS_PER_RUN = int(os.getenv("THREAT_INTEL_MAX_ITEMS_PER_RUN", "20"))


@dataclass
class CollectionResult:
    new_items:          int = 0
    skipped_duplicates: int = 0
    errors:             list[str] = field(default_factory=list)
    sources_run:        int = 0


class ThreatIntelCollector:
    """
    Fetch threat intelligence from all registered sources and persist new items.

    Usage::

        collector = ThreatIntelCollector(store=store)
        result = collector.collect()
        print(f"New: {result.new_items}, Dupes: {result.skipped_duplicates}")
    """

    def __init__(
        self,
        store: ThreatIntelStore,
        sources: list[type[ThreatSource]] | None = None,
        max_items_per_source: int = _MAX_ITEMS_PER_RUN,
    ) -> None:
        self._store    = store
        self._sources  = sources if sources is not None else ALL_SOURCES
        self._max_items = max_items_per_source

    def collect(self) -> CollectionResult:
        """
        Run all sources and persist new items.  Thread-safe (delegates to store).
        """
        result = CollectionResult()
        # Pre-load existing hashes for O(1) dedup across all sources in this run
        existing_hashes = self._store.get_url_hashes()

        for source_cls in self._sources:
            source = source_cls()
            result.sources_run += 1
            try:
                raw_items: list[RawThreatItem] = source.fetch(self._max_items)
            except Exception as exc:
                msg = f"{source.name}: fetch error — {exc}"
                log.warning("ThreatIntelCollector: %s", msg)
                result.errors.append(msg)
                continue

            for raw in raw_items:
                url_hash = hashlib.sha256(raw.url.encode()).hexdigest()
                if url_hash in existing_hashes:
                    result.skipped_duplicates += 1
                    continue

                intel_item = ThreatIntelItem(
                    id=str(uuid.uuid4()),
                    source=raw.source,
                    title=raw.title[:500],
                    url=raw.url,
                    published_at=raw.published_at,
                    raw_description=raw.raw_description[:4000],
                    status=ThreatIntelStatus.NEW,
                    created_at=datetime.now(UTC).isoformat(),
                )

                inserted = self._store.upsert_item(intel_item)
                if inserted:
                    existing_hashes.add(url_hash)
                    result.new_items += 1
                    log.debug(
                        "ThreatIntelCollector: new item [%s] %s",
                        raw.source, raw.title[:60],
                    )
                else:
                    result.skipped_duplicates += 1

        log.info(
            "ThreatIntelCollector: collected %d new, %d dupes across %d sources. errors=%d",
            result.new_items,
            result.skipped_duplicates,
            result.sources_run,
            len(result.errors),
        )
        return result
