"""
warden/integrations/taxii.py  (IN-19)
──────────────────────────────────────
STIX/TAXII 2.1 feed consumer.

Discovers collections from a TAXII server, pulls STIX 2.1 bundles, and
synthesises attack examples into the EvolutionEngine via
`synthesize_from_intel()`.

Configuration (env vars)
────────────────────────
  TAXII_SERVER_URL     — TAXII discovery URL, e.g. https://taxii.oasis.org/taxii/
  TAXII_USERNAME       — HTTP Basic auth username (optional)
  TAXII_PASSWORD       — HTTP Basic auth password (optional)
  TAXII_API_KEY        — Bearer token (preferred over Basic, optional)
  TAXII_COLLECTIONS    — comma-sep collection IDs to poll (default: all)
  TAXII_POLL_INTERVAL  — seconds between polls (default 3600)
  TAXII_MAX_OBJECTS    — max STIX objects per pull (default 200)
  TAXII_TENANT_ID      — tenant to credit synthesised rules to

Supported STIX object types ingested
─────────────────────────────────────
  attack-pattern, malware, tool, threat-actor, course-of-action,
  indicator (with pattern field), intrusion-set
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

log = logging.getLogger("warden.integrations.taxii")

_SERVER_URL   = os.getenv("TAXII_SERVER_URL", "")
_USERNAME     = os.getenv("TAXII_USERNAME", "")
_PASSWORD     = os.getenv("TAXII_PASSWORD", "")
_API_KEY      = os.getenv("TAXII_API_KEY", "")
_COLLECTIONS  = [c.strip() for c in os.getenv("TAXII_COLLECTIONS", "").split(",") if c.strip()]
_POLL_INTERVAL = int(os.getenv("TAXII_POLL_INTERVAL", "3600"))
_MAX_OBJECTS  = int(os.getenv("TAXII_MAX_OBJECTS", "200"))
_TENANT_ID    = os.getenv("TAXII_TENANT_ID", "default")

_INGESTIBLE_TYPES = {
    "attack-pattern",
    "malware",
    "tool",
    "threat-actor",
    "course-of-action",
    "indicator",
    "intrusion-set",
}


# ── HTTP client helpers ───────────────────────────────────────────────────────

def _headers() -> dict[str, str]:
    h = {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1",
    }
    if _API_KEY:
        h["Authorization"] = f"Bearer {_API_KEY}"
    return h


def _auth() -> httpx.BasicAuth | None:
    if _USERNAME and _PASSWORD and not _API_KEY:
        return httpx.BasicAuth(_USERNAME, _PASSWORD)
    return None


async def _get(url: str, params: dict | None = None) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=30, auth=_auth()) as client:
            r = await client.get(url, headers=_headers(), params=params or {})
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("taxii _get %s failed: %s", url, exc)
        return None


# ── Discovery & collection listing ───────────────────────────────────────────

async def discover() -> dict | None:
    """Fetch TAXII server discovery document."""
    if not _SERVER_URL:
        return None
    return await _get(_SERVER_URL)


async def list_api_roots(discovery: dict) -> list[str]:
    roots = discovery.get("api_roots", [])
    return [str(r) for r in roots]


async def list_collections(api_root: str) -> list[dict]:
    base = api_root.rstrip("/")
    data = await _get(f"{base}/collections/")
    return data.get("collections", []) if data else []


async def get_objects(api_root: str, collection_id: str, added_after: str | None = None) -> list[dict]:
    """Pull STIX objects from a collection, with optional incremental filter."""
    base  = api_root.rstrip("/")
    url   = f"{base}/collections/{collection_id}/objects/"
    params: dict[str, Any] = {"limit": _MAX_OBJECTS}
    if added_after:
        params["added_after"] = added_after
    data = await _get(url, params=params)
    if not data:
        return []
    objects = data.get("objects", [])
    log.info("taxii: fetched %d objects from collection=%s", len(objects), collection_id)
    return objects


# ── STIX → EvolutionEngine synthesis ─────────────────────────────────────────

def _stix_to_intel(obj: dict) -> str | None:
    """Convert a STIX 2.1 object to a plain-English description for synthesis."""
    t = obj.get("type", "")
    name = obj.get("name", "") or obj.get("id", "")

    if t == "attack-pattern":
        desc = obj.get("description", "")
        kill_chain = ""
        for kc in obj.get("kill_chain_phases", []):
            kill_chain = f" ({kc.get('kill_chain_name','')}: {kc.get('phase_name','')})"
            break
        return f"AI attack pattern: {name}{kill_chain}. {desc}"

    if t == "indicator":
        pattern = obj.get("pattern", "")
        if pattern:
            return f"Threat indicator pattern: {pattern}. Name: {name}"

    if t in ("malware", "tool"):
        desc = obj.get("description", "")
        return f"Malicious {t}: {name}. {desc}"

    if t == "threat-actor":
        desc = obj.get("description", "")
        aliases = ", ".join(obj.get("aliases", []))
        return f"Threat actor: {name} (aliases: {aliases}). {desc}"

    if t == "course-of-action":
        desc = obj.get("description", "")
        return f"Defensive course of action: {name}. {desc}"

    if t == "intrusion-set":
        desc = obj.get("description", "")
        return f"Intrusion set: {name}. {desc}"

    return None


async def synthesise_objects(objects: list[dict]) -> int:
    """Push STIX objects through EvolutionEngine synthesis. Returns count ingested."""
    try:
        from warden.brain.evolve import EvolutionEngine  # noqa: PLC0415
    except ImportError:
        log.warning("taxii: EvolutionEngine not available, skipping synthesis")
        return 0

    engine   = EvolutionEngine()
    ingested = 0

    for obj in objects:
        if obj.get("type") not in _INGESTIBLE_TYPES:
            continue
        intel_text = _stix_to_intel(obj)
        if not intel_text or len(intel_text) < 20:
            continue
        try:
            await engine.synthesize_from_intel(intel_text)
            ingested += 1
        except Exception as exc:
            log.debug("taxii: synthesize error for %s: %s", obj.get("id"), exc)

    log.info("taxii: synthesised %d/%d objects into EvolutionEngine", ingested, len(objects))
    return ingested


# ── Full sync ─────────────────────────────────────────────────────────────────

async def sync(added_after: str | None = None) -> dict:
    """
    Full TAXII sync: discover → list collections → pull objects → synthesise.
    Returns summary dict.
    """
    if not _SERVER_URL:
        return {"status": "skip", "reason": "TAXII_SERVER_URL not set"}

    discovery = await discover()
    if not discovery:
        return {"status": "error", "reason": "discovery failed"}

    api_roots = await list_api_roots(discovery)
    if not api_roots:
        return {"status": "error", "reason": "no api_roots in discovery"}

    total_objects  = 0
    total_ingested = 0

    for api_root in api_roots:
        collections = await list_collections(api_root)

        for col in collections:
            col_id = col.get("id", "")
            if _COLLECTIONS and col_id not in _COLLECTIONS:
                continue
            objects = await get_objects(api_root, col_id, added_after=added_after)
            if not objects:
                continue
            total_objects  += len(objects)
            total_ingested += await synthesise_objects(objects)

    return {
        "status":          "ok",
        "ts":              datetime.now(UTC).isoformat(),
        "api_roots":       len(api_roots),
        "objects_fetched": total_objects,
        "synthesised":     total_ingested,
    }


# ── Background polling loop ───────────────────────────────────────────────────

async def taxii_poll_loop() -> None:
    """
    Continuous TAXII polling loop.  Run as a FastAPI lifespan background task.
    Only starts when TAXII_SERVER_URL is set.
    """
    if not _SERVER_URL:
        return

    log.info("taxii: poll loop started (interval=%ds)", _POLL_INTERVAL)
    last_sync: str | None = None

    while True:
        try:
            result = await sync(added_after=last_sync)
            last_sync = datetime.now(UTC).isoformat()
            log.info("taxii: poll %s", result)
        except Exception as exc:
            log.error("taxii: poll error: %s", exc)

        await asyncio.sleep(_POLL_INTERVAL)
