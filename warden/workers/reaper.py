"""
warden/workers/reaper.py
────────────────────────
The Reaper — ARQ background tasks for Warden Syndicates TTL enforcement.

Tasks
─────
  reap_expired_tunnels          — runs every 5 minutes
      Scans syndicate_links for ACTIVE tunnels past their expires_at.
      For each expired tunnel:
        1. Crypto-shredding: deletes the AES key from Redis.
           Without the key, any in-flight encrypted packets are unreadable.
        2. Marks the link EXPIRED in Postgres (audit trail).
        3. Logs a structured event for SOC 2 / GDPR evidence.

  notify_impending_expiration   — runs every 15 minutes
      Finds ACTIVE ephemeral tunnels expiring within the next hour.
      Sends a Slack alert (and logs a warning) to the initiating tenant.
      Sets last_notified_at so admins are not spammed on every cycle.

Design decisions
────────────────
  • Double safety net:
      - Redis native EXPIRE (set at handshake time) ensures the key
        self-destructs even if the ARQ worker crashes.
      - The Reaper provides the authoritative Postgres state update and
        human-readable notifications.

  • Fail-open per tunnel: if one tunnel fails to reap (DB error, etc.)
    the loop continues so all other expired tunnels are still processed.

  • The Reaper never sends email directly — it uses Slack webhooks
    (same channel as alert_block_event) for ops-team visibility.
    Future: POST to the initiating tenant's portal webhook.

Environment variables (inherited from warden container via ARQ worker)
──────────────────────────────────────────────────────────────────────
  REDIS_URL            — Redis connection string
  DATABASE_URL         — PostgreSQL connection string
  SLACK_WEBHOOK_URL    — optional; Slack alert on expiration (reuses alerting.py channel)
"""
from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime, timedelta

log = logging.getLogger("warden.workers.reaper")


# ── Redis helper ──────────────────────────────────────────────────────────────

def _get_sync_redis():
    """Return a synchronous redis.Redis client (ARQ worker context is sync-friendly)."""
    import redis as _redis
    url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    client = _redis.from_url(url, decode_responses=False, socket_connect_timeout=3)
    client.ping()
    return client


# ── DB helper ─────────────────────────────────────────────────────────────────

async def _fetch_all(sql: str, params: dict) -> list:
    from sqlalchemy import text

    from warden.db.connection import get_async_engine
    async with get_async_engine().connect() as conn:
        result = await conn.execute(text(sql), params)
        return result.fetchall()


async def _execute(sql: str, params: dict) -> None:
    from sqlalchemy import text

    from warden.db.connection import get_async_engine
    async with get_async_engine().begin() as conn:
        await conn.execute(text(sql), params)


# ── Slack notification ────────────────────────────────────────────────────────

async def _slack_notify(message: str) -> None:
    """Fire-and-forget Slack message via webhook (reuses SLACK_WEBHOOK_URL)."""
    webhook = os.getenv("SLACK_WEBHOOK_URL", "")
    if not webhook:
        return
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(webhook, json={"text": message})
    except Exception as exc:
        log.debug("Slack notify failed (non-fatal): %s", exc)


# ── Task 1: Reap expired tunnels ──────────────────────────────────────────────

async def reap_expired_tunnels(ctx: dict) -> dict:
    """
    ARQ task — crypto-shred and expire tunnels past their TTL.

    Runs every 5 minutes via cron.  Returns a summary dict for ARQ result store.
    """
    now = datetime.now(UTC)
    log.info("Reaper: scanning for expired tunnels at %s", now.isoformat())

    try:
        expired = await _fetch_all(
            """
            SELECT link_id, initiator_sid, responder_sid, expires_at
            FROM   warden_core.syndicate_links
            WHERE  status       = 'ACTIVE'
              AND  is_ephemeral = TRUE
              AND  expires_at  <= :now
            """,
            {"now": now},
        )
    except Exception as exc:
        log.error("Reaper: DB query failed: %s", exc)
        return {"reaped": 0, "error": str(exc)}

    reaped = 0
    errors = 0

    try:
        redis = _get_sync_redis()
    except Exception as exc:
        log.error("Reaper: Redis unavailable — skipping crypto-shredding: %s", exc)
        redis = None

    for row in expired:
        tunnel_id = str(row[0])
        initiator  = row[1]
        responder  = row[2]

        try:
            # 1. Crypto-shredding — delete AES key from Redis
            if redis:
                deleted = redis.delete(f"warden:tunnels:active:{tunnel_id}")
                log.info(
                    "Reaper: crypto-shredded tunnel %s (key_existed=%s)",
                    tunnel_id, bool(deleted),
                )

            # 2. Mark EXPIRED in Postgres
            await _execute(
                """
                UPDATE warden_core.syndicate_links
                SET    status = 'EXPIRED'
                WHERE  link_id = :lid
                  AND  status  = 'ACTIVE'
                """,
                {"lid": tunnel_id},
            )

            # 3. Structured audit log
            log.info(
                json.dumps({
                    "event": "TUNNEL_AUTO_EXPIRED",
                    "tunnel_id": tunnel_id,
                    "initiator_sid": initiator,
                    "responder_sid": responder,
                    "expired_at": now.isoformat(),
                })
            )

            reaped += 1

        except Exception as exc:
            log.error("Reaper: failed to reap tunnel %s: %s", tunnel_id, exc)
            errors += 1

    if reaped:
        await _slack_notify(
            f":hourglass_flowing_sand: *Warden Reaper*: {reaped} tunnel(s) expired and crypto-shredded."
        )

    log.info("Reaper: done — reaped=%d errors=%d", reaped, errors)
    return {"reaped": reaped, "errors": errors, "checked_at": now.isoformat()}


# ── Task 2: Warn before expiration ────────────────────────────────────────────

async def notify_impending_expiration(ctx: dict) -> dict:
    """
    ARQ task — warn admins 1 hour before their tunnel expires.

    Runs every 15 minutes.  Sets last_notified_at to prevent repeat spam.
    """
    now = datetime.now(UTC)
    warning_threshold = now + timedelta(hours=1)

    log.debug("Reaper: checking for tunnels expiring before %s", warning_threshold.isoformat())

    try:
        pending = await _fetch_all(
            """
            SELECT link_id, initiator_sid, responder_sid, expires_at, ttl_hours
            FROM   warden_core.syndicate_links
            WHERE  status            = 'ACTIVE'
              AND  is_ephemeral      = TRUE
              AND  expires_at       <= :threshold
              AND  last_notified_at  IS NULL
            """,
            {"threshold": warning_threshold},
        )
    except Exception as exc:
        log.error("Reaper notify: DB query failed: %s", exc)
        return {"notified": 0, "error": str(exc)}

    notified = 0

    for row in pending:
        tunnel_id  = str(row[0])
        initiator  = row[1]
        responder  = row[2]
        expires_at = row[3]
        ttl_hours  = row[4]

        # Time remaining
        remaining = expires_at - now if hasattr(expires_at, "tzinfo") else \
            expires_at.replace(tzinfo=UTC) - now
        mins_remaining = max(0, int(remaining.total_seconds() / 60))

        message = (
            f":warning: *Warden Syndicates — Tunnel Expiring Soon*\n"
            f"Tunnel `{tunnel_id}` between *{initiator}* ↔ *{responder or 'pending'}* "
            f"will auto-expire in *{mins_remaining} minutes* "
            f"(TTL was {ttl_hours}h).\n"
            f"To extend: `POST /tunnels/handshake/init` with a new TTL."
        )

        await _slack_notify(message)
        log.warning(
            "Tunnel expiration warning: tunnel=%s initiator=%s expires_in=%dm",
            tunnel_id, initiator, mins_remaining,
        )

        # Mark as notified so we don't spam on the next cycle
        try:
            await _execute(
                "UPDATE warden_core.syndicate_links SET last_notified_at = :now WHERE link_id = :lid",
                {"now": now, "lid": tunnel_id},
            )
            notified += 1
        except Exception as exc:
            log.error("Reaper notify: failed to mark notified for %s: %s", tunnel_id, exc)

    log.debug("Reaper notify: done — notified=%d", notified)
    return {"notified": notified, "checked_at": now.isoformat()}
