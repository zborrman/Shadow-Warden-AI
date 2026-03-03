"""
warden/alerting.py
━━━━━━━━━━━━━━━━━━
Real-time alerting for high-severity Warden block events.

Supported channels:
  • Slack (Incoming Webhook)
  • PagerDuty (Events API v2) — triggered only for BLOCK risk level

Environment variables:
  SLACK_WEBHOOK_URL         Slack incoming webhook URL
  PAGERDUTY_ROUTING_KEY     PagerDuty Events API v2 routing key
  ALERT_MIN_RISK_LEVEL      Minimum risk level to alert (default: high)
                            Values: medium | high | block

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
"""
from __future__ import annotations

import logging
import os

import httpx

log = logging.getLogger("warden.alerting")

_SLACK_WEBHOOK       = os.getenv("SLACK_WEBHOOK_URL", "")
_PAGERDUTY_KEY       = os.getenv("PAGERDUTY_ROUTING_KEY", "")
_ALERT_MIN_RISK      = os.getenv("ALERT_MIN_RISK_LEVEL", "high").lower()

# Risk level numeric order — only alert if risk >= threshold
_RISK_NUM = {"low": 0, "medium": 1, "high": 2, "block": 3}
_ALERT_THRESHOLD = _RISK_NUM.get(_ALERT_MIN_RISK, 2)  # default: high


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
