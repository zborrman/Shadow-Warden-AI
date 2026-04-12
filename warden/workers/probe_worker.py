"""
warden/workers/probe_worker.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Async probe scheduler — runs all active monitors concurrently.

Each monitor is checked on its own interval (interval_s).
Results are written to probe_results (TimescaleDB hypertable) and
published to Redis Pub/Sub for real-time WebSocket push.

Check types:
  http  — GET request, checks status_code < 500
  ssl   — TLS handshake, returns days_until_expiry as status_code
  dns   — DNS resolution, latency in ms
  tcp   — TCP connect, checks port is open

Fails open: any probe exception is stored as is_up=False with error text.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from datetime import UTC, datetime

import httpx

log = logging.getLogger("warden.probe_worker")

_SCHEDULER_TICK_S = 5   # how often to check for due monitors
_PROBE_TIMEOUT_S  = 10  # per-probe HTTP/TCP timeout


# ── Probe implementations ─────────────────────────────────────────────────────

async def _probe_http(url: str) -> dict:
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=_PROBE_TIMEOUT_S,
            verify=True,
        ) as client:
            resp = await client.get(url)
        return {
            "is_up":       resp.status_code < 500,
            "status_code": resp.status_code,
            "latency_ms":  round((time.perf_counter() - t0) * 1000, 2),
            "error":       None,
        }
    except Exception as exc:
        return {
            "is_up":       False,
            "status_code": None,
            "latency_ms":  round((time.perf_counter() - t0) * 1000, 2),
            "error":       str(exc)[:200],
        }


async def _probe_ssl(host: str, port: int = 443) -> dict:
    t0 = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_running_loop()

        def _connect() -> int:
            with socket.create_connection((host, port), timeout=_PROBE_TIMEOUT_S) as sock, \
                 ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            return (expiry - datetime.now(UTC)).days

        days_left = await loop.run_in_executor(None, _connect)
        return {
            "is_up":       days_left > 0,
            "status_code": days_left,
            "latency_ms":  round((time.perf_counter() - t0) * 1000, 2),
            "error":       f"Expires in {days_left}d" if days_left < 14 else None,
        }
    except Exception as exc:
        return {
            "is_up":       False,
            "status_code": None,
            "latency_ms":  round((time.perf_counter() - t0) * 1000, 2),
            "error":       str(exc)[:200],
        }


async def _probe_dns(host: str) -> dict:
    t0 = time.perf_counter()
    try:
        loop = asyncio.get_running_loop()
        await loop.getaddrinfo(host, None)
        return {
            "is_up":       True,
            "status_code": 200,
            "latency_ms":  round((time.perf_counter() - t0) * 1000, 2),
            "error":       None,
        }
    except Exception as exc:
        return {
            "is_up":       False,
            "status_code": None,
            "latency_ms":  round((time.perf_counter() - t0) * 1000, 2),
            "error":       str(exc)[:200],
        }


async def _probe_tcp(host: str, port: int) -> dict:
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_PROBE_TIMEOUT_S,
        )
        writer.close()
        await writer.wait_closed()
        return {
            "is_up":       True,
            "status_code": 200,
            "latency_ms":  round((time.perf_counter() - t0) * 1000, 2),
            "error":       None,
        }
    except Exception as exc:
        return {
            "is_up":       False,
            "status_code": None,
            "latency_ms":  round((time.perf_counter() - t0) * 1000, 2),
            "error":       str(exc)[:200],
        }


async def _dispatch_probe(monitor: dict) -> dict:
    """Route to the correct probe based on check_type."""
    from urllib.parse import urlparse
    url        = monitor["url"]
    check_type = monitor.get("check_type", "http")
    parsed     = urlparse(url)
    host       = parsed.hostname or url

    if check_type == "ssl":
        return await _probe_ssl(host, parsed.port or 443)
    elif check_type == "dns":
        return await _probe_dns(host)
    elif check_type == "tcp":
        return await _probe_tcp(host, parsed.port or 80)
    else:
        return await _probe_http(url)


# ── Result persistence + pub/sub ──────────────────────────────────────────────

async def _save_result(monitor: dict, result: dict) -> None:
    """Write probe result to TimescaleDB and publish to Redis."""
    import json
    now = datetime.now(UTC)

    try:
        from sqlalchemy import text

        from warden.db.connection import get_async_engine

        async with get_async_engine().begin() as conn:
            await conn.execute(
                text("""
                    INSERT INTO warden_core.probe_results
                        (time, monitor_id, tenant_id, is_up, status_code, latency_ms, error)
                    VALUES
                        (:time, :mid, :tid, :up, :sc, :lat, :err)
                """),
                {
                    "time": now,
                    "mid":  str(monitor["id"]),
                    "tid":  monitor["tenant_id"],
                    "up":   result["is_up"],
                    "sc":   result["status_code"],
                    "lat":  result["latency_ms"],
                    "err":  result["error"],
                },
            )
    except Exception as exc:
        log.warning("probe_worker: DB write failed for %s — %s", monitor["id"], exc)

    # Publish to Redis for WebSocket push (fail-open, sync client via executor)
    try:
        from warden.cache import _get_client as _get_redis  # noqa: PLC0415
        redis = _get_redis()
        if redis is not None:
            payload = json.dumps({
                "monitor_id":  str(monitor["id"]),
                "is_up":       result["is_up"],
                "latency_ms":  result["latency_ms"],
                "status_code": result["status_code"],
                "error":       result["error"],
                "ts":          now.isoformat(),
            })
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: redis.publish(f"monitor:{monitor['id']}:result", payload),
            )
    except Exception as exc:
        log.debug("probe_worker: Redis publish failed — %s", exc)


async def _run_probe(monitor: dict) -> None:
    result = await _dispatch_probe(monitor)
    await _save_result(monitor, result)

    status = "UP" if result["is_up"] else "DOWN"
    log.debug(
        "probe %s [%s] %s  %sms",
        monitor.get("name") or monitor["url"],
        monitor["check_type"],
        status,
        result["latency_ms"],
    )


# ── Scheduler ─────────────────────────────────────────────────────────────────

_last_run: dict[str, float] = {}   # monitor_id → last run epoch


async def _load_monitors() -> list[dict]:
    """Fetch all active monitors from DB."""
    try:
        from sqlalchemy import text

        from warden.db.connection import get_async_engine

        async with get_async_engine().connect() as conn:
            rows = await conn.execute(
                text("SELECT id, tenant_id, name, url, interval_s, check_type "
                     "FROM warden_core.monitors WHERE is_active = TRUE")
            )
            return [dict(r._mapping) for r in rows]
    except Exception as exc:
        log.warning("probe_worker: failed to load monitors — %s", exc)
        return []


async def probe_scheduler() -> None:
    """
    Main scheduler loop.

    Every SCHEDULER_TICK_S seconds, loads active monitors and launches
    probes that are due (last_run + interval_s <= now).
    Each probe runs in its own Task — concurrency is bounded by the number
    of active monitors.
    """
    log.info("probe_scheduler: starting (tick=%ds)", _SCHEDULER_TICK_S)
    while True:
        try:
            monitors = await _load_monitors()
            now = time.monotonic()
            due = [
                m for m in monitors
                if now - _last_run.get(str(m["id"]), 0) >= m["interval_s"]
            ]
            if due:
                tasks = [asyncio.create_task(_run_probe(m)) for m in due]
                for m in due:
                    _last_run[str(m["id"])] = now
                await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as exc:
            log.warning("probe_scheduler: tick error — %s", exc)

        await asyncio.sleep(_SCHEDULER_TICK_S)
