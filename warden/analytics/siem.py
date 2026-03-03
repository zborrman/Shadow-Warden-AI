"""
warden/analytics/siem.py
━━━━━━━━━━━━━━━━━━━━━━━━
SIEM integration: ship Warden filter events to Splunk or Elastic.

Both functions are async and designed to be called from analytics/logger.py
as a post-write hook, or directly from main.py as a BackgroundTask.

Splunk HEC (HTTP Event Collector):
  Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN to enable.
  Example:  SPLUNK_HEC_URL=https://splunk.corp.com:8088

Elastic (ECS format):
  Set ELASTIC_URL and ELASTIC_API_KEY to enable.
  Events are indexed into ELASTIC_INDEX (default: warden-events).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime

import httpx

log = logging.getLogger("warden.analytics.siem")

_SPLUNK_HEC_URL   = os.getenv("SPLUNK_HEC_URL", "")
_SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
_ELASTIC_URL      = os.getenv("ELASTIC_URL", "")
_ELASTIC_API_KEY  = os.getenv("ELASTIC_API_KEY", "")
_ELASTIC_INDEX    = os.getenv("ELASTIC_INDEX", "warden-events")


async def ship_event(entry: dict) -> None:
    """
    Ship a log entry to all configured SIEM backends.
    Fire-and-forget — errors are logged but never raised to the caller.
    """
    if _SPLUNK_HEC_URL and _SPLUNK_HEC_TOKEN:
        try:
            await ship_to_splunk(entry)
        except Exception as exc:
            log.warning("Splunk HEC write failed: %s", exc)

    if _ELASTIC_URL and _ELASTIC_API_KEY:
        try:
            await ship_to_elastic(entry)
        except Exception as exc:
            log.warning("Elastic write failed: %s", exc)


async def ship_to_splunk(entry: dict) -> None:
    """Send one event to Splunk HEC."""
    try:
        ts = datetime.fromisoformat(entry["ts"]).timestamp()
    except (KeyError, ValueError):
        ts = None

    hec_event = {
        "source":     "shadow_warden_ai",
        "sourcetype": "warden:filter",
        "event":      entry,
    }
    if ts is not None:
        hec_event["time"] = ts

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            f"{_SPLUNK_HEC_URL}/services/collector/event",
            headers={"Authorization": f"Splunk {_SPLUNK_HEC_TOKEN}"},
            json=hec_event,
        )
        resp.raise_for_status()
    log.debug("Splunk HEC event shipped: request_id=%s", entry.get("request_id"))


async def ship_to_elastic(entry: dict) -> None:
    """Index one event in Elastic using the ECS schema."""
    ecs_event = {
        "@timestamp": entry.get("ts"),
        "event": {
            "kind":     "event",
            "category": "intrusion_detection",
            "type":     "denied" if not entry.get("allowed") else "allowed",
            "outcome":  "failure" if not entry.get("allowed") else "success",
        },
        "warden": {
            "risk_level":   entry.get("risk_level"),
            "flags":        entry.get("flags", []),
            "content_len":  entry.get("content_len"),
            "elapsed_ms":   entry.get("elapsed_ms"),
            "strict":       entry.get("strict", False),
            "secrets_found": entry.get("secrets_found", []),
        },
        "event.id": entry.get("request_id"),
    }

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            f"{_ELASTIC_URL}/{_ELASTIC_INDEX}/_doc",
            headers={
                "Authorization": f"ApiKey {_ELASTIC_API_KEY}",
                "Content-Type": "application/json",
            },
            json=ecs_event,
        )
        resp.raise_for_status()
    log.debug("Elastic event indexed: request_id=%s", entry.get("request_id"))
