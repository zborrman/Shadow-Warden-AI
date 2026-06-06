"""
warden/push/service.py
────────────────────────
Firebase Cloud Messaging (FCM) push notification service for Mobile SOC alerts.

Sends HIGH/BLOCK verdict push notifications to registered SOC mobile devices.
Uses firebase-admin (Python SDK) which handles both FCM (Android) and APNs (iOS)
through a single API.

Required env vars (one of):
  FIREBASE_CREDENTIALS_JSON  — JSON string of the service account credentials
  FIREBASE_CREDENTIALS_FILE  — Path to service account JSON file

Fail-open: if firebase-admin is not installed or credentials are missing,
push notifications are silently skipped — the filter pipeline is never blocked.

Install: pip install firebase-admin
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

log = logging.getLogger("warden.push.service")

_RISK_EMOJI = {"high": "🔴", "block": "🚨", "medium": "🟡"}


def _init_firebase() -> Any | None:
    """Initialise the firebase-admin app singleton. Returns the app or None."""
    try:
        import firebase_admin  # type: ignore[import]
        from firebase_admin import credentials  # type: ignore[import]

        if firebase_admin._apps:  # already initialised
            return firebase_admin.get_app()

        cred_json = os.getenv("FIREBASE_CREDENTIALS_JSON", "")
        cred_file = os.getenv("FIREBASE_CREDENTIALS_FILE", "")

        if cred_json:
            cred = credentials.Certificate(json.loads(cred_json))
        elif cred_file and os.path.exists(cred_file):
            cred = credentials.Certificate(cred_file)
        else:
            log.debug("push: no Firebase credentials configured — push disabled")
            return None

        return firebase_admin.initialize_app(cred)
    except Exception as exc:
        log.debug("push: firebase-admin init failed (fail-open): %s", exc)
        return None


class FCMPushService:
    """Send verdict alerts to multiple device tokens via FCM v1 API."""

    def __init__(self) -> None:
        self._app = _init_firebase()

    @property
    def available(self) -> bool:
        return self._app is not None

    def send_verdict_alert(
        self,
        device_tokens: list[str],
        payload: dict,
    ) -> int:
        """Send push to all tokens. Returns success count (0 if push unavailable)."""
        if not self._app or not device_tokens:
            return 0

        try:
            from firebase_admin import messaging  # type: ignore[import]

            risk  = payload.get("risk_level", "high").lower()
            emoji = _RISK_EMOJI.get(risk, "⚠️")
            atk   = payload.get("attack_type", "unknown").replace("_", " ").title()

            msg = messaging.MulticastMessage(
                tokens=device_tokens[:500],  # FCM hard limit
                notification=messaging.Notification(
                    title=f"{emoji} {risk.upper()} verdict — Shadow Warden",
                    body=f"{atk} · {payload.get('request_id', '')[:12]}",
                ),
                data={
                    "risk_level":  risk,
                    "attack_type": payload.get("attack_type", "unknown"),
                    "request_id":  payload.get("request_id", ""),
                    "tenant_id":   payload.get("tenant_id", "default"),
                    "rule_summary": payload.get("rule_summary", "")[:200],
                    "screen":      "AlertDetail",
                },
                android=messaging.AndroidConfig(
                    priority="high",
                    notification=messaging.AndroidNotification(
                        sound="default",
                        channel_id="soc_alerts",
                    ),
                ),
                apns=messaging.APNSConfig(
                    headers={"apns-priority": "10"},
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(sound="default", badge=1)
                    ),
                ),
            )

            resp = messaging.send_each_for_multicast(msg, app=self._app)
            log.info(
                "push: sent %d/%d notifications (risk=%s tenant=%s)",
                resp.success_count, len(device_tokens), risk, payload.get("tenant_id"),
            )

            try:
                from warden.metrics import PUSH_NOTIFICATIONS_SENT
                PUSH_NOTIFICATIONS_SENT.labels(risk_level=risk).inc(resp.success_count)
            except Exception:
                pass

            return resp.success_count

        except Exception as exc:
            log.warning("push: FCM send failed (fail-open): %s", exc)
            return 0


_svc: FCMPushService | None = None


def get_push_service() -> FCMPushService:
    global _svc
    if _svc is None:
        _svc = FCMPushService()
    return _svc
