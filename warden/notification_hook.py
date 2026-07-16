"""
warden/notification_hook.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Stage 5: Business Notification Hook.

When OutputGuard (Stage 4) detects a business-critical violation in an LLM
response — price manipulation, unauthorized commitment — this hook notifies
the shop manager in real-time so they can review the conversation.

This is intentionally separate from warden/alerting.py:
  • alerting.py  →  security team  (Slack/PagerDuty, technical language)
  • notification_hook.py → shop manager (Telegram DM / CRM webhook, plain language)

Channels
────────
  Telegram  — Direct message to the manager's personal chat.
  Webhook   — POST to any HTTPS endpoint (CRM, n8n, Zapier, custom API).
              Payload is signed with HMAC-SHA256 so the receiver can verify
              the request came from Warden.

Environment variables
─────────────────────
  NOTIFY_OUTPUT_RISKS       Comma-separated risk types that trigger a notification.
                            Default: price_manipulation,unauthorized_commitment
  NOTIFY_TELEGRAM_TOKEN     Telegram Bot token (can be the same as TELEGRAM_BOT_TOKEN).
  NOTIFY_TELEGRAM_CHAT_ID   Chat ID for the shop manager (NOT the security channel).
  NOTIFY_WEBHOOK_URL        HTTPS endpoint to POST the event JSON to (CRM / n8n / Zapier).
  NOTIFY_WEBHOOK_SECRET     HMAC-SHA256 signing secret (min 16 chars). Sent as
                            X-Warden-Signature: sha256=<hex> on every webhook POST.

Usage — called automatically from openai_proxy.py after OutputGuard fires:

    from warden.notification_hook import get_notification_hook
    asyncio.create_task(
        get_notification_hook().fire(
            finding    = finding,
            session_id = session_id,
            tenant_id  = tenant_id,
            user_id    = user_id,
        )
    )
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime

import httpx

from warden.config import settings
from warden.output_guard import BusinessFinding, BusinessRisk

log = logging.getLogger("warden.notification_hook")

# ── Config ────────────────────────────────────────────────────────────────────

# Risk types that trigger a manager notification (subset of all BusinessRisk values)
_NOTIFY_RISKS: frozenset[str] = frozenset(
    r.strip()
    for r in settings.notify_output_risks.split(",")
    if r.strip()
)

_TELEGRAM_TOKEN   = settings.notify_telegram_token or settings.telegram_bot_token
_TELEGRAM_CHAT_ID = settings.notify_telegram_chat_id
_WEBHOOK_URL      = settings.notify_webhook_url
_WEBHOOK_SECRET   = settings.notify_webhook_secret.encode()

_HOOK_ENABLED = bool(_TELEGRAM_CHAT_ID or _WEBHOOK_URL)


# ── Human-readable risk labels ────────────────────────────────────────────────

_RISK_EMOJI: dict[str, str] = {
    BusinessRisk.PRICE_MANIPULATION:  "💸",
    BusinessRisk.UNAUTHORIZED_COMMIT: "📋",
    BusinessRisk.COMPETITOR_MENTION:  "🏷",
    BusinessRisk.POLICY_VIOLATION:    "⚖️",
}

_RISK_DESCRIPTION: dict[str, str] = {
    BusinessRisk.PRICE_MANIPULATION:  (
        "The bot offered a price or discount that violates your pricing rules."
    ),
    BusinessRisk.UNAUTHORIZED_COMMIT: (
        "The bot made a commitment on the store's behalf without authorization "
        "(\"I guarantee\", \"you will receive\", \"we will deliver\")."
    ),
    BusinessRisk.COMPETITOR_MENTION:  (
        "The bot mentioned a competitor in its reply to the customer."
    ),
    BusinessRisk.POLICY_VIOLATION:    (
        "The bot cited a store policy (returns, warranty) it is not authorized to state."
    ),
}


# ── Notification payload ──────────────────────────────────────────────────────

def _build_payload(
    finding:    BusinessFinding,
    session_id: str | None,
    tenant_id:  str,
    user_id:    str,
) -> dict:
    return {
        "event":      "output_guard_violation",
        "risk":       finding.risk.value,
        "detail":     finding.detail,
        "snippet":    finding.snippet,
        "owasp":      finding.owasp,
        "session_id": session_id or "—",
        "tenant_id":  tenant_id,
        "user_id":    user_id,
        "timestamp":  datetime.now(UTC).isoformat(),
    }


def _telegram_text(
    finding:    BusinessFinding,
    session_id: str | None,
    tenant_id:  str,
    user_id:    str,
) -> str:
    emoji = _RISK_EMOJI.get(finding.risk.value, "⚠️")
    desc  = _RISK_DESCRIPTION.get(finding.risk.value, finding.detail)
    sid   = session_id or "—"
    return (
        f"🛒 *Shadow Warden — Warning*\n\n"
        f"{emoji} *Violation:* `{finding.risk.value}`\n"
        f"📝 *Description:* {desc}\n\n"
        f"💬 *Bot response snippet:*\n"
        f"```\n{finding.snippet[:200]}\n```\n\n"
        f"👤 *User:* `{user_id}`\n"
        f"🔗 *Session:* `{sid}`\n"
        f"🏢 *Tenant:* `{tenant_id}`\n\n"
        f"_The customer reply was automatically corrected. "
        f"We recommend reviewing this conversation._"
    )


# ── Dispatch ──────────────────────────────────────────────────────────────────

class NotificationHook:
    """
    Fire-and-forget manager notification dispatcher.

    Designed to be called via asyncio.create_task() — never blocks the proxy
    response and never raises exceptions to the caller.
    """

    async def fire(
        self,
        *,
        finding:    BusinessFinding,
        session_id: str | None = None,
        tenant_id:  str = "default",
        user_id:    str = "anonymous",
    ) -> None:
        """Dispatch Telegram + webhook notifications concurrently. Never raises."""
        if finding.risk.value not in _NOTIFY_RISKS:
            return

        tasks = []
        if _TELEGRAM_TOKEN and _TELEGRAM_CHAT_ID:
            tasks.append(self._send_telegram(finding, session_id, tenant_id, user_id))
        if _WEBHOOK_URL:
            tasks.append(self._send_webhook(finding, session_id, tenant_id, user_id))

        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                log.warning("notification_hook dispatch error: %s", r)

    # ── Telegram ──────────────────────────────────────────────────────────────

    async def _send_telegram(
        self,
        finding:    BusinessFinding,
        session_id: str | None,
        tenant_id:  str,
        user_id:    str,
    ) -> None:
        text = _telegram_text(finding, session_id, tenant_id, user_id)
        url  = f"https://api.telegram.org/bot{_TELEGRAM_TOKEN}/sendMessage"
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, json={
                "chat_id":    _TELEGRAM_CHAT_ID,
                "text":       text,
                "parse_mode": "Markdown",
            })
            resp.raise_for_status()
        log.debug("notification_hook: Telegram sent for risk=%s", finding.risk.value)

    # ── Webhook ───────────────────────────────────────────────────────────────

    async def _send_webhook(
        self,
        finding:    BusinessFinding,
        session_id: str | None,
        tenant_id:  str,
        user_id:    str,
    ) -> None:
        payload    = _build_payload(finding, session_id, tenant_id, user_id)
        body_bytes = json.dumps(payload, ensure_ascii=False).encode()
        headers    = {"Content-Type": "application/json; charset=utf-8"}

        if _WEBHOOK_SECRET:
            sig = hmac.new(_WEBHOOK_SECRET, body_bytes, hashlib.sha256).hexdigest()
            headers["X-Warden-Signature"] = f"sha256={sig}"

        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(_WEBHOOK_URL, content=body_bytes, headers=headers)
            resp.raise_for_status()
        log.debug(
            "notification_hook: webhook sent to %s for risk=%s",
            _WEBHOOK_URL[:40], finding.risk.value,
        )


# ── Module-level singleton ────────────────────────────────────────────────────

_hook: NotificationHook | None = None


def get_notification_hook() -> NotificationHook:
    global _hook
    if _hook is None:
        _hook = NotificationHook()
    return _hook
