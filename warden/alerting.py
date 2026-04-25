"""
warden/alerting.py
━━━━━━━━━━━━━━━━━━
Real-time alerting for high-severity Warden block events.

Supported channels:
  • Slack (Incoming Webhook)
  • PagerDuty (Events API v2) — triggered only for BLOCK risk level
  • Telegram Bot — poisoning alerts + corpus rollback events

Environment variables:
  SLACK_WEBHOOK_URL         Slack incoming webhook URL
  PAGERDUTY_ROUTING_KEY     PagerDuty Events API v2 routing key
  ALERT_MIN_RISK_LEVEL      Minimum risk level to alert (default: high)
                            Values: medium | high | block
  TELEGRAM_BOT_TOKEN        Telegram Bot API token (from @BotFather)
  TELEGRAM_CHAT_ID          Telegram chat/channel ID to send alerts to

Usage — called from main.py after a block decision::

    from warden import alerting

    if not allowed and guard_result.risk_level in (RiskLevel.HIGH, RiskLevel.BLOCK):
        background_tasks.add_task(
            alerting.alert_block_event,
            attack_type  = top_flag.flag.value if top_flag else "unknown",
            risk_level   = guard_result.risk_level.value,
            rule_summary = top_flag.detail if top_flag else "",
            request_id   = rid,
        )

    # For data poisoning attacks:
    if _pr.poisoning_score > 0.85:
        background_tasks.add_task(
            alerting.alert_poisoning_event,
            attack_vector  = _pr.attack_vector,
            poisoning_score = _pr.poisoning_score,
            detail         = _pr.detail,
            tenant_id      = tenant_id,
        )
"""
from __future__ import annotations

import logging

import httpx

from warden.config import settings
from warden.retry import ALERT_RETRY, async_retry

log = logging.getLogger("warden.alerting")

_SLACK_WEBHOOK    = settings.slack_webhook_url
_PAGERDUTY_KEY    = settings.pagerduty_routing_key
_TELEGRAM_TOKEN   = settings.telegram_bot_token
_TELEGRAM_CHAT_ID = settings.telegram_chat_id

# Risk level numeric order — only alert if risk >= threshold
_RISK_NUM = {"low": 0, "medium": 1, "high": 2, "block": 3}
_ALERT_THRESHOLD = _RISK_NUM.get(settings.alert_min_risk_level, 2)  # default: high


async def alert_block_event(
    *,
    attack_type:  str,
    risk_level:   str,
    rule_summary: str,
    request_id:   str = "-",
) -> None:
    """
    Fire-and-forget alert for a blocked request.
    Designed to run as a FastAPI BackgroundTask.
    """
    if _RISK_NUM.get(risk_level.lower(), 0) < _ALERT_THRESHOLD:
        return

    if _SLACK_WEBHOOK:
        try:
            await _slack_alert(attack_type, risk_level, rule_summary, request_id)
        except Exception as exc:
            log.warning("Slack alert failed: %s", exc)

    if _PAGERDUTY_KEY and risk_level.lower() == "block":
        try:
            await _pagerduty_trigger(attack_type, rule_summary, request_id)
        except Exception as exc:
            log.warning("PagerDuty alert failed: %s", exc)


async def alert_poisoning_event(
    *,
    attack_vector:   str,
    poisoning_score: float,
    detail:          str,
    tenant_id:       str = "default",
    rollback_done:   bool = False,
) -> None:
    """
    Fire-and-forget alert for a data poisoning detection event.

    Called when poisoning_score > 0.85 (Stage 2c) or when CorpusHealthMonitor
    triggers a corpus rollback.  Sends to Telegram (primary) + Slack (secondary).
    """
    if _TELEGRAM_TOKEN and _TELEGRAM_CHAT_ID:
        try:
            await _telegram_poisoning_alert(
                attack_vector, poisoning_score, detail, tenant_id, rollback_done
            )
        except Exception as exc:
            log.warning("Telegram alert failed: %s", exc)

    if _SLACK_WEBHOOK:
        try:
            rollback_note = " • Corpus автоматически восстановлен из снимка." if rollback_done else ""
            await _slack_alert(
                attack_type  = f"data_poisoning:{attack_vector}",
                risk_level   = "block",
                summary      = f"poisoning_score={poisoning_score:.3f} tenant={tenant_id} — {detail[:120]}{rollback_note}",
                request_id   = "-",
            )
        except Exception as exc:
            log.warning("Slack poisoning alert failed: %s", exc)


async def alert_corpus_rollback(
    *,
    tenant_id:       str   = "default",
    failing_canaries: int  = 0,
    drift:           float = 0.0,
    detail:          str   = "",
) -> None:
    """
    Alert sent by CorpusHealthMonitor when a corpus rollback is triggered.
    """
    if _TELEGRAM_TOKEN and _TELEGRAM_CHAT_ID:
        try:
            await _telegram_rollback_alert(tenant_id, failing_canaries, drift, detail)
        except Exception as exc:
            log.warning("Telegram rollback alert failed: %s", exc)

    if _SLACK_WEBHOOK:
        try:
            await _slack_alert(
                attack_type  = "corpus_rollback",
                risk_level   = "block",
                summary      = (
                    f"Corpus poisoning detected — auto-rollback executed. "
                    f"failing_canaries={failing_canaries} drift={drift:.4f} tenant={tenant_id}"
                ),
                request_id   = "-",
            )
        except Exception as exc:
            log.warning("Slack rollback alert failed: %s", exc)


@async_retry(ALERT_RETRY)
async def _slack_alert(
    attack_type: str,
    risk_level: str,
    summary: str,
    request_id: str,
) -> None:
    emoji = {"medium": "🟡", "high": "🔴", "block": "🚨"}.get(risk_level.lower(), "⚠️")
    payload = {
        "text": (
            f"{emoji} *Shadow Warden* — `{risk_level.upper()}` attack blocked\n"
            f"*Type:* `{attack_type}`\n"
            f"*Rule:* {summary}\n"
            f"*Request ID:* `{request_id}`"
        )
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(_SLACK_WEBHOOK, json=payload)
        resp.raise_for_status()
    log.debug("Slack alert sent for %s %s", risk_level, attack_type)


@async_retry(ALERT_RETRY)
async def _pagerduty_trigger(
    attack_type: str,
    summary: str,
    request_id: str,
) -> None:
    payload = {
        "routing_key": _PAGERDUTY_KEY,
        "event_action": "trigger",
        "dedup_key": f"warden-{request_id}",
        "payload": {
            "summary": f"Shadow Warden BLOCK: {attack_type}",
            "severity": "critical",
            "source": "shadow-warden-ai",
            "custom_details": {
                "attack_type": attack_type,
                "rule": summary,
                "request_id": request_id,
            },
        },
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            "https://events.pagerduty.com/v2/enqueue", json=payload
        )
        resp.raise_for_status()
    log.debug("PagerDuty event sent for request %s", request_id)


async def _telegram_poisoning_alert(
    attack_vector:   str,
    poisoning_score: float,
    detail:          str,
    tenant_id:       str,
    rollback_done:   bool,
) -> None:
    """Send a Telegram Bot message for a high-confidence poisoning detection."""
    score_pct = int(poisoning_score * 100)
    rollback_line = (
        "\n\n✅ *Corpus автоматически восстановлен из снимка.* Self-Healing сработал."
        if rollback_done
        else ""
    )
    text = (
        f"🚨 *Shadow Warden — Атака обнаружена!*\n\n"
        f"Кто-то пытался отравить мой ИИ — но Варден всё поймал.\n\n"
        f"🔬 *Вектор атаки:* `{attack_vector}`\n"
        f"📊 *Уверенность:* {score_pct}%\n"
        f"🏢 *Тенант:* `{tenant_id}`\n"
        f"📝 *Детали:* {detail[:200]}"
        f"{rollback_line}"
    )
    await _send_telegram(text)


async def _telegram_rollback_alert(
    tenant_id:        str,
    failing_canaries: int,
    drift:            float,
    detail:           str,
) -> None:
    """Send a Telegram Bot message when corpus auto-rollback is triggered."""
    text = (
        f"🛡 *Shadow Warden — Self-Healing активирован!*\n\n"
        f"Corpus ИИ был частично отравлен. Warden автоматически откатился к "
        f"последнему здоровому снимку.\n\n"
        f"🏢 *Тенант:* `{tenant_id}`\n"
        f"🕯 *Упавших canary:* {failing_canaries}\n"
        f"📐 *Дрейф центроида:* {drift:.4f}\n"
        f"📝 *Детали:* {detail[:200]}\n\n"
        f"✅ Corpus восстановлен. Система работает в штатном режиме."
    )
    await _send_telegram(text)


def send_alert(message: str, *, level: str = "warning") -> None:
    """Fire-and-forget a plain Slack message. Safe to call from sync code inside FastAPI."""
    if not _SLACK_WEBHOOK:
        return
    import asyncio
    payload = {"text": message}
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(_send_slack_raw(payload))
        else:
            loop.run_until_complete(_send_slack_raw(payload))
    except Exception as exc:
        log.debug("send_alert skipped: %s", exc)


@async_retry(ALERT_RETRY)
async def _send_slack_raw(payload: dict) -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(_SLACK_WEBHOOK, json=payload)
        resp.raise_for_status()


@async_retry(ALERT_RETRY)
async def _send_telegram(text: str) -> None:
    """POST a message to the Telegram Bot API."""
    if not _TELEGRAM_TOKEN or not _TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{_TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id":    _TELEGRAM_CHAT_ID,
        "text":       text,
        "parse_mode": "Markdown",
    }
    async with httpx.AsyncClient(timeout=8.0) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
    log.debug("Telegram alert sent")
