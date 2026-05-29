"""
warden/settings/service.py
───────────────────────────
SettingsService — central read/write hub for all tenant settings.

Storage layout (Redis keys, prefix = settings:{tenant_id}:)
  agents          → JSON blob (AgentSettings)
  notifications   → JSON list of NotificationChannel
  commerce        → JSON blob (CommerceSettings)
  semantic        → JSON blob (SemanticSettings)

All keys have no TTL (persistent tenant config).
Falls back to defaults when Redis is unavailable.
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from warden.settings.models import (
    AgentSettings,
    AgentSettingsPatch,
    AllSettings,
    CommerceSettings,
    CommerceSettingsPatch,
    NotificationChannel,
    NotificationChannelPatch,
    SemanticSettings,
    SemanticSettingsPatch,
)

log = logging.getLogger("warden.settings")

# In-process fallback store (used when Redis is unavailable)
_mem: dict[str, str] = {}


def _redis():
    try:
        import os

        import redis as _redis_lib
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url == "memory://":
            return None
        return _redis_lib.from_url(url, decode_responses=True, socket_connect_timeout=1)
    except Exception:
        return None


def _key(tenant_id: str, section: str) -> str:
    return f"settings:{tenant_id}:{section}"


def _get(tenant_id: str, section: str) -> dict | list | None:
    k = _key(tenant_id, section)
    r = _redis()
    if r is not None:
        try:
            raw = r.get(k)
            return json.loads(raw) if raw else None
        except Exception:
            pass
    raw = _mem.get(k)
    return json.loads(raw) if raw else None


def _set(tenant_id: str, section: str, value: dict | list) -> None:
    k = _key(tenant_id, section)
    encoded = json.dumps(value)
    r = _redis()
    if r is not None:
        try:
            r.set(k, encoded)
            return
        except Exception as exc:
            log.warning("settings.redis.set failed: %s", exc)
    _mem[k] = encoded


class SettingsService:

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_all(self, tenant_id: str) -> AllSettings:
        return AllSettings(
            tenant_id=tenant_id,
            agents=self.get_agents(tenant_id),
            notifications=self.list_notifications(tenant_id),
            commerce=self.get_commerce(tenant_id),
            semantic=self.get_semantic(tenant_id),
            meta={"source": "redis"},
        )

    # ── Agents ────────────────────────────────────────────────────────────────

    def get_agents(self, tenant_id: str) -> AgentSettings:
        raw = _get(tenant_id, "agents")
        if raw:
            return AgentSettings(**raw)
        return AgentSettings()

    def update_agents(self, tenant_id: str, patch: AgentSettingsPatch) -> AgentSettings:
        current = self.get_agents(tenant_id)
        updated = current.model_copy(update={k: v for k, v in patch.model_dump().items() if v is not None})
        _set(tenant_id, "agents", updated.model_dump())
        return updated

    # ── Notifications ─────────────────────────────────────────────────────────

    def list_notifications(self, tenant_id: str) -> list[NotificationChannel]:
        raw = _get(tenant_id, "notifications")
        if isinstance(raw, list):
            return [NotificationChannel(**c) for c in raw]
        return []

    def add_notification(self, tenant_id: str, channel: NotificationChannel) -> NotificationChannel:
        channels = self.list_notifications(tenant_id)
        channel.id = str(uuid.uuid4())
        channels.append(channel)
        _set(tenant_id, "notifications", [c.model_dump() for c in channels])
        return channel

    def update_notification(
        self, tenant_id: str, channel_id: str, patch: NotificationChannelPatch
    ) -> NotificationChannel:
        channels = self.list_notifications(tenant_id)
        for i, c in enumerate(channels):
            if c.id == channel_id:
                updated = c.model_copy(update={k: v for k, v in patch.model_dump().items() if v is not None})
                channels[i] = updated
                _set(tenant_id, "notifications", [ch.model_dump() for ch in channels])
                return updated
        raise KeyError(f"Channel {channel_id!r} not found")

    def delete_notification(self, tenant_id: str, channel_id: str) -> None:
        channels = self.list_notifications(tenant_id)
        channels = [c for c in channels if c.id != channel_id]
        _set(tenant_id, "notifications", [c.model_dump() for c in channels])

    def test_notification(self, tenant_id: str, channel_id: str) -> dict[str, Any]:
        channels = self.list_notifications(tenant_id)
        ch = next((c for c in channels if c.id == channel_id), None)
        if ch is None:
            raise KeyError(f"Channel {channel_id!r} not found")
        try:
            if ch.kind == "slack" and ch.url:
                import httpx
                r = httpx.post(ch.url, json={"text": "🧪 Shadow Warden Settings test — channel is working."}, timeout=5)
                return {"ok": r.status_code < 300, "status": r.status_code}
            return {"ok": True, "status": "no-op", "note": f"{ch.kind} test not implemented server-side"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ── Commerce ──────────────────────────────────────────────────────────────

    def get_commerce(self, tenant_id: str) -> CommerceSettings:
        raw = _get(tenant_id, "commerce")
        if raw:
            return CommerceSettings(**raw)
        return CommerceSettings()

    def update_commerce(self, tenant_id: str, patch: CommerceSettingsPatch) -> CommerceSettings:
        current = self.get_commerce(tenant_id)
        updated = current.model_copy(update={k: v for k, v in patch.model_dump().items() if v is not None})
        _set(tenant_id, "commerce", updated.model_dump())
        return updated

    # ── Semantic Layer ────────────────────────────────────────────────────────

    def get_semantic(self, tenant_id: str) -> SemanticSettings:
        raw = _get(tenant_id, "semantic")
        if raw:
            return SemanticSettings(**raw)
        return SemanticSettings()

    def update_semantic(self, tenant_id: str, patch: SemanticSettingsPatch) -> SemanticSettings:
        current = self.get_semantic(tenant_id)
        updated = current.model_copy(update={k: v for k, v in patch.model_dump().items() if v is not None})
        _set(tenant_id, "semantic", updated.model_dump())
        return updated


_svc = SettingsService()


def get_service() -> SettingsService:
    return _svc
