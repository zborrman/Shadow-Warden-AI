"""
warden/telegram_alert.py
────────────────────────
Telegram Bot alert channel for Shadow Warden AI.

Complements the existing Slack and PagerDuty channels in alerting.py.
Designed for SMB owners who prefer Telegram (common in EU and Israel markets).

Per-tenant routing
──────────────────
Each tenant can have its own Telegram chat_id stored in the key file
via OnboardingEngine.update_telegram().  Block events for that tenant
are delivered to the tenant's chat *and* to the global MSP channel.

Alert types
───────────
  • block_alert      — fired on every BLOCK/HIGH event
  • quota_warning    — fired at 80% and 100% of monthly quota
  • daily_digest     — summary of the previous day (call from scheduler)
  • test_connection  — verify bot token and chat_id are working

Environment variables
─────────────────────
  TELEGRAM_BOT_TOKEN   Bot token from @BotFather (required to enable)
  TELEGRAM_CHAT_ID     Global MSP operations chat_id (optional fallback)
  TELEGRAM_MIN_RISK    Minimum risk level to alert (default: high)
                       Values: medium | high | block

Usage::

    from warden import telegram_alert

    await telegram_alert.send_block_alert(
        tenant_id      = "acme-dental",
        risk_level     = "block",
        attack_type    = "PROMPT_INJECTION",
        detail         = "SSN pattern in prompt",
        request_id     = "req-abc123",
        tenant_chat_id = "-1001234567890",
    )
"""
from __future__ import annotations

import logging
import os
from datetime import UTC, datetime

import httpx

log = logging.getLogger("warden.telegram_alert")

_BOT_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN", "")
_GLOBAL_CHAT = os.getenv("TELEGRAM_CHAT_ID", "")
_MIN_RISK    = os.getenv("TELEGRAM_MIN_RISK", "high").lower()

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "block": 3}
_THRESHOLD  = _RISK_ORDER.get(_MIN_RISK, 2)

_RISK_EMOJI = {
    "low":    "🟡",
    "medium": "🟠",
    "high":   "🔴",
    "block":  "🚫",
}

_TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


# ── Internal helpers ──────────────────────────────────────────────────────────

def is_enabled() -> bool:
    """Return True if a bot token is configured."""
    return bool(_BOT_TOKEN)


def _below_threshold(risk_level: str) -> bool:
    return _RISK_ORDER.get(risk_level.lower(), 0) < _THRESHOLD


def _escape(text: str) -> str:
    """Escape special Markdown chars that break Telegram's MarkdownV1 parser."""
    # Only escape chars that cause parse errors in MarkdownV1
    for ch in ("_", "*", "`", "["):
        text = text.replace(ch, f"\\{ch}")
    return text


async def _send(chat_id: str, text: str) -> bool:
    """
    Send a Telegram message to chat_id.
    Returns True on success, False on any failure (never raises).
    """
    if not _BOT_TOKEN or not chat_id:
        return False

    url = _TELEGRAM_API.format(token=_BOT_TOKEN)
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, json={
                "chat_id":                  chat_id,
                "text":                     text,
                "parse_mode":               "Markdown",
                "disable_web_page_preview": True,
            })
        if resp.status_code != 200:
            log.warning(
                "TelegramAlert: HTTP %s — %s",
                resp.status_code, resp.text[:300],
            )
            return False
        return True
    except Exception as exc:
        log.warning("TelegramAlert: send failed — %s", exc)
        return False


async def _send_to_chats(text: str, tenant_chat_id: str | None) -> None:
    """Deliver text to tenant chat and (if distinct) global MSP chat."""
    sent_to: set[str] = set()

    if tenant_chat_id:
        await _send(tenant_chat_id, text)
        sent_to.add(tenant_chat_id)

    if _GLOBAL_CHAT and _GLOBAL_CHAT not in sent_to:
        await _send(_GLOBAL_CHAT, text)


# ── Public alert functions ────────────────────────────────────────────────────

async def send_block_alert(
    *,
    tenant_id:      str,
    risk_level:     str,
    attack_type:    str,
    detail:         str        = "",
    request_id:     str        = "-",
    tenant_chat_id: str | None = None,
) -> None:
    """
    Send a block-event alert.

    Designed to run as a FastAPI BackgroundTask::

        background_tasks.add_task(
            telegram_alert.send_block_alert,
            tenant_id      = tenant_id,
            risk_level     = risk_level,
            attack_type    = attack_type,
            detail         = detail,
            request_id     = rid,
            tenant_chat_id = _onboarding.get_telegram_chat_id(tenant_id),
        )
    """
    if not is_enabled() or _below_threshold(risk_level):
        return

    emoji = _RISK_EMOJI.get(risk_level.lower(), "⚠️")
    ts    = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    text = (
        f"{emoji} *Shadow Warden AI — Block Event*\n\n"
        f"🏢 *Tenant:* `{tenant_id}`\n"
        f"⚡ *Risk:* `{risk_level.upper()}`\n"
        f"🎯 *Type:* `{attack_type}`\n"
        f"📝 *Detail:* {detail[:200]}\n"
        f"🆔 *Request:* `{request_id}`\n"
        f"🕐 *Time:* `{ts}`"
    )

    await _send_to_chats(text, tenant_chat_id)
    log.debug(
        "TelegramAlert: block_alert sent tenant=%s risk=%s",
        tenant_id, risk_level,
    )


async def send_quota_warning(
    *,
    tenant_id:      str,
    used_usd:       float,
    quota_usd:      float,
    tenant_chat_id: str | None = None,
) -> None:
    """
    Send a quota warning when tenant reaches 80% or 100% of their monthly cap.

    Typically called from the billing aggregation loop after each update::

        if used >= quota * 0.80:
            await telegram_alert.send_quota_warning(...)
    """
    if not is_enabled():
        return

    percent = (used_usd / quota_usd * 100) if quota_usd > 0 else 100.0
    icon    = "🔴" if percent >= 100 else "🟠"

    text = (
        f"{icon} *Shadow Warden AI — Quota Warning*\n\n"
        f"🏢 *Tenant:* `{tenant_id}`\n"
        f"💰 *Used:* `${used_usd:.4f}` / `${quota_usd:.2f}` ({percent:.0f}%)\n"
        f"📅 *Period:* current calendar month\n\n"
        f"{'_Quota exceeded — new requests will be rejected._' if percent >= 100 else '_Approaching monthly limit._'}"
    )

    await _send_to_chats(text, tenant_chat_id)


async def send_daily_digest(
    *,
    tenant_id:      str,
    requests:       int,
    blocked:        int,
    cost_usd:       float,
    top_attack:     str        = "",
    tenant_chat_id: str | None = None,
) -> None:
    """
    Send a daily summary digest to the tenant's Telegram chat.
    Call this from a nightly scheduled task.
    Only sent to the *tenant's* chat, not the global MSP channel.
    """
    if not is_enabled() or not tenant_chat_id:
        return

    block_rate = (blocked / requests * 100) if requests > 0 else 0.0
    date_str   = datetime.now(UTC).strftime("%Y-%m-%d")

    text = (
        f"📊 *Shadow Warden AI — Daily Digest*\n\n"
        f"🏢 *Tenant:* `{tenant_id}`\n"
        f"📅 *Date:* `{date_str}`\n\n"
        f"✅ *Requests:* {requests}\n"
        f"🚫 *Blocked:* {blocked} ({block_rate:.1f}%)\n"
        f"💰 *Cost today:* `${cost_usd:.5f}`\n"
        f"🎯 *Top threat:* `{top_attack or 'none'}`"
    )

    await _send(tenant_chat_id, text)


async def send_test_message(chat_id: str) -> bool:
    """
    Send a test message to verify the bot token and chat_id are working.
    Returns True if the message was delivered.

    Usage (setup verification endpoint)::

        ok = await telegram_alert.send_test_message(chat_id)
    """
    if not is_enabled():
        log.warning("TelegramAlert: TELEGRAM_BOT_TOKEN is not set.")
        return False

    text = (
        "✅ *Shadow Warden AI — Connection Test*\n\n"
        "Bot is configured correctly.\n"
        "You will receive security alerts in this chat."
    )
    return await _send(chat_id, text)
