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

Sourcetypes (Splunk)
────────────────────
  warden:filter     — normal filter decisions (allowed / blocked)
  warden:uncertain  — ML gray-zone events (ml_uncertain flag present)
  warden:bypass     — fail-open bypass events (timeout or circuit breaker)

Indices (Elastic)
─────────────────
  ELASTIC_INDEX            (default: warden-events)  — all events
  ELASTIC_BYPASS_INDEX     (default: warden-bypass-alerts) — bypass events only;
                            set a shorter ILM retention and attach an alert rule here.

Alert rule guidance
───────────────────
  Splunk:  index=warden sourcetype=warden:bypass | stats count by tenant_id
  Elastic: index pattern "warden-bypass-alerts-*", alert on doc count > 0 per 5 min
"""
from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

import httpx

log = logging.getLogger("warden.analytics.siem")

_SPLUNK_HEC_URL   = os.getenv("SPLUNK_HEC_URL", "")
_SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
_ELASTIC_URL      = os.getenv("ELASTIC_URL", "")
_ELASTIC_API_KEY  = os.getenv("ELASTIC_API_KEY", "")
_ELASTIC_INDEX    = os.getenv("ELASTIC_INDEX", "warden-events")
_ELASTIC_BYPASS_INDEX = os.getenv("ELASTIC_BYPASS_INDEX", "warden-bypass-alerts")

# ── Sourcetype routing ────────────────────────────────────────────────────────

_SOURCETYPE_FILTER    = "warden:filter"
_SOURCETYPE_UNCERTAIN = "warden:uncertain"
_SOURCETYPE_BYPASS    = "warden:bypass"

_BYPASS_REASONS = frozenset({
    "emergency_bypass:timeout",
    "circuit_breaker:open",
})


def _sourcetype_for(entry: dict) -> str:
    """Return the Splunk sourcetype that best describes this entry."""
    reason = entry.get("reason", "")
    if reason in _BYPASS_REASONS:
        return _SOURCETYPE_BYPASS
    if "ml_uncertain" in entry.get("flags", []):
        return _SOURCETYPE_UNCERTAIN
    return _SOURCETYPE_FILTER


def _resilience_fields(entry: dict) -> dict[str, Any]:
    """Build the warden.resilience sub-object for ECS events."""
    reason = entry.get("reason", "")
    flags  = entry.get("flags", [])
    return {
        "bypass":          reason in _BYPASS_REASONS,
        "bypass_reason":   reason if reason in _BYPASS_REASONS else None,
        "uncertain":       "ml_uncertain" in flags,
        "circuit_breaker": reason == "circuit_breaker:open",
    }


# ── Public API ────────────────────────────────────────────────────────────────

async def ship_event(entry: dict) -> None:
    """Ship a filter log entry to all configured SIEM backends.

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


async def ship_bypass_alert(entry: dict) -> None:
    """Ship a bypass event to SIEM with elevated priority routing.

    Called directly from the bypass paths in main.py (timeout + circuit breaker)
    since those paths return before the normal analytics log + ship_event flow.

    Splunk: sourcetype=warden:bypass (distinct from warden:filter — easy to alert on)
    Elastic: dual-indexed to both ELASTIC_INDEX and ELASTIC_BYPASS_INDEX so bypass
             events appear in the main index AND in the dedicated alert index.
    """
    if _SPLUNK_HEC_URL and _SPLUNK_HEC_TOKEN:
        try:
            await ship_to_splunk(entry)   # _sourcetype_for() picks warden:bypass
        except Exception as exc:
            log.warning("Splunk bypass alert failed: %s", exc)

    if _ELASTIC_URL and _ELASTIC_API_KEY:
        try:
            await ship_to_elastic(entry)   # → ELASTIC_INDEX
        except Exception as exc:
            log.warning("Elastic bypass event failed: %s", exc)
        try:
            await _ship_to_elastic_index(entry, _ELASTIC_BYPASS_INDEX)   # → alert index
        except Exception as exc:
            log.warning("Elastic bypass alert index failed: %s", exc)


# ── Backend implementations ───────────────────────────────────────────────────

async def ship_to_splunk(entry: dict) -> None:
    """Send one event to Splunk HEC with dynamic sourcetype routing."""
    try:
        ts = datetime.fromisoformat(entry["ts"]).timestamp()
    except (KeyError, ValueError):
        ts = None

    hec_event: dict[str, Any] = {
        "source":     "shadow_warden_ai",
        "sourcetype": _sourcetype_for(entry),
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
    log.debug("Splunk HEC event shipped: request_id=%s sourcetype=%s",
              entry.get("request_id"), _sourcetype_for(entry))


async def ship_to_elastic(entry: dict) -> None:
    """Index one event in Elastic using the ECS schema."""
    await _ship_to_elastic_index(entry, _ELASTIC_INDEX)


async def _ship_to_elastic_index(entry: dict, index: str) -> None:
    """Index one ECS event into *index*."""
    ecs_event = {
        "@timestamp": entry.get("ts") or datetime.now(UTC).isoformat(),
        "event": {
            "kind":     "event",
            "category": "intrusion_detection",
            "type":     "denied" if not entry.get("allowed") else "allowed",
            "outcome":  "failure" if not entry.get("allowed") else "success",
        },
        "warden": {
            "risk_level":    entry.get("risk_level"),
            "flags":         entry.get("flags", []),
            "payload_len":   entry.get("payload_len"),
            "elapsed_ms":    entry.get("elapsed_ms"),
            "strict":        entry.get("strict", False),
            "secrets_found": entry.get("secrets_found", []),
            "tenant_id":     entry.get("tenant_id"),
            "reason":        entry.get("reason", ""),
            "resilience":    _resilience_fields(entry),
        },
        "event.id": entry.get("request_id"),
    }

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            f"{_ELASTIC_URL}/{index}/_doc",
            headers={
                "Authorization": f"ApiKey {_ELASTIC_API_KEY}",
                "Content-Type": "application/json",
            },
            json=ecs_event,
        )
        resp.raise_for_status()
    log.debug("Elastic event indexed: request_id=%s index=%s",
              entry.get("request_id"), index)
