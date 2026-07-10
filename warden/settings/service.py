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
import os
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

# ── Secret value encryption at rest ───────────────────────────────────────────
# Secret values must never be persisted in plaintext. Encrypt with a Fernet key
# derived from VAULT_MASTER_KEY (persistent) or, when unset (dev/test), an
# ephemeral per-process key so nothing plaintext ever reaches Redis / _mem.
_SECRETS_FERNET: Any = None


def _secrets_fernet():
    global _SECRETS_FERNET
    if _SECRETS_FERNET is None:
        from cryptography.fernet import Fernet
        key = os.getenv("VAULT_MASTER_KEY", "").encode()
        try:
            _SECRETS_FERNET = Fernet(key) if key else Fernet(Fernet.generate_key())
            if not key:
                log.warning(
                    "settings: VAULT_MASTER_KEY unset — using an ephemeral key for "
                    "secret encryption (values won't survive a restart; dev only)."
                )
        except Exception:  # noqa: BLE001 — malformed key → ephemeral, never plaintext
            _SECRETS_FERNET = Fernet(Fernet.generate_key())
            log.warning("settings: invalid VAULT_MASTER_KEY — using an ephemeral encryption key.")
    return _SECRETS_FERNET


def _encrypt_value(value: str) -> str:
    return _secrets_fernet().encrypt(value.encode()).decode()


def _decrypt_value(ciphertext: str) -> str:
    return _secrets_fernet().decrypt(ciphertext.encode()).decode()


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
        if isinstance(raw, dict):
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
        if isinstance(raw, dict):
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
        if isinstance(raw, dict):
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


# ── Module-level shims used by warden/api/settings.py ────────────────────────

def get_settings_summary(tenant_id: str) -> dict[str, Any]:
    all_s = _svc.get_all(tenant_id)
    return {
        "tenant_id": tenant_id,
        "api_key_count": 0,
        "secret_count": 0,
        "channel_count": len(all_s.notifications),
        "agents": all_s.agents.model_dump(),
    }


def get_api_keys(tenant_id: str) -> list[dict[str, Any]]:
    raw = _get(tenant_id, "api_keys")
    return raw if isinstance(raw, list) else []


def create_api_key(tenant_id: str, label: str) -> dict[str, Any]:
    import hashlib
    import secrets as _secrets
    import uuid
    from datetime import UTC, datetime
    raw_key = f"sw_{_secrets.token_urlsafe(32)}"
    record: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "label": label,
        "prefix": raw_key[:10],
        "key_hash": hashlib.sha256(raw_key.encode()).hexdigest(),
        "active": True,
        "created_at": datetime.now(UTC).isoformat(),
        "last_used_at": None,
        "request_count": 0,
    }
    keys = get_api_keys(tenant_id)
    keys.append(record)
    _set(tenant_id, "api_keys", keys)
    return {**record, "key": raw_key}


def revoke_api_key(tenant_id: str, key_id: str) -> bool:
    keys = get_api_keys(tenant_id)
    for k in keys:
        if k.get("id") == key_id:
            k["active"] = False
            _set(tenant_id, "api_keys", keys)
            return True
    return False


def get_secrets(tenant_id: str) -> list[dict[str, Any]]:
    raw = _get(tenant_id, "secrets")
    if not isinstance(raw, list):
        return []
    return [{k: v for k, v in s.items() if k != "value"} for s in raw]


def reveal_secret_value(tenant_id: str, secret_id: str) -> str | None:
    """Decrypt and return a stored secret's plaintext value (server-side only).

    Values are stored Fernet-encrypted; this is the only path that decrypts them.
    Returns None if the secret is missing or cannot be decrypted.
    """
    raw = _get(tenant_id, "secrets")
    if not isinstance(raw, list):
        return None
    for s in raw:
        if s.get("id") == secret_id and s.get("value"):
            try:
                return _decrypt_value(s["value"])
            except Exception as exc:  # noqa: BLE001
                log.warning("settings: could not decrypt secret %s: %s", secret_id, exc)
                return None
    return None


def create_secret(
    tenant_id: str,
    name: str,
    value: str,
    description: str = "",
    expires_at: str | None = None,
) -> dict[str, Any]:
    import uuid
    from datetime import UTC, datetime
    record: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "name": name,
        "description": description,
        "value": _encrypt_value(value),  # encrypted at rest — never plaintext
        "created_at": datetime.now(UTC).isoformat(),
        "expires_at": expires_at,
        "active": True,
    }
    raw = _get(tenant_id, "secrets")
    secrets_list: list[dict[str, Any]] = raw if isinstance(raw, list) else []
    secrets_list.append(record)
    _set(tenant_id, "secrets", secrets_list)
    return {k: v for k, v in record.items() if k != "value"}


def update_secret(
    tenant_id: str,
    secret_id: str,
    value: str | None,
    description: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any] | None:
    raw = _get(tenant_id, "secrets")
    secrets_list: list[dict[str, Any]] = raw if isinstance(raw, list) else []
    for s in secrets_list:
        if s.get("id") == secret_id:
            if value is not None:
                s["value"] = _encrypt_value(value)  # encrypted at rest — never plaintext
            if description is not None:
                s["description"] = description
            if expires_at is not None:
                s["expires_at"] = expires_at
            _set(tenant_id, "secrets", secrets_list)
            return {k: v for k, v in s.items() if k != "value"}
    return None


def delete_secret(tenant_id: str, secret_id: str) -> bool:
    raw = _get(tenant_id, "secrets")
    secrets_list: list[dict[str, Any]] = raw if isinstance(raw, list) else []
    new_list = [s for s in secrets_list if s.get("id") != secret_id]
    if len(new_list) == len(secrets_list):
        return False
    _set(tenant_id, "secrets", new_list)
    return True


def get_agent_config(tenant_id: str) -> dict[str, Any]:
    return _svc.get_agents(tenant_id).model_dump()


def update_agent_config(tenant_id: str, data: dict[str, Any]) -> dict[str, Any]:
    from warden.settings.models import AgentSettingsPatch
    patch = AgentSettingsPatch(**{k: v for k, v in data.items() if v is not None})
    return _svc.update_agents(tenant_id, patch).model_dump()


def get_notification_channels(tenant_id: str) -> list[dict[str, Any]]:
    return [c.model_dump() for c in _svc.list_notifications(tenant_id)]


def add_notification_channel(
    tenant_id: str, channel_type: str, label: str, config: dict[str, Any]
) -> dict[str, Any]:
    from warden.settings.models import NotificationChannel
    ch = NotificationChannel(
        kind=channel_type if channel_type in ("slack", "teams", "email", "webhook") else "webhook",
        label=label,
        url=config.get("url"),
        email=config.get("email"),
    )
    return _svc.add_notification(tenant_id, ch).model_dump()


def test_notification_channel(tenant_id: str, channel_id: str) -> dict[str, Any]:
    try:
        return _svc.test_notification(tenant_id, channel_id)
    except KeyError:
        return {"ok": False, "error": "Channel not found"}


def delete_notification_channel(tenant_id: str, channel_id: str) -> bool:
    channels_before = _svc.list_notifications(tenant_id)
    _svc.delete_notification(tenant_id, channel_id)
    return len(_svc.list_notifications(tenant_id)) < len(channels_before)
