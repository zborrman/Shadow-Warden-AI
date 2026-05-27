"""Settings service — Redis-backed with in-memory fallback.

All settings are stored per-tenant:
  Redis key schema:
    settings:apikeys:{tenant_id}    → hash of key_id → JSON
    settings:secrets:{tenant_id}    → hash of secret_id → JSON (value Fernet-encrypted)
    settings:agent:{tenant_id}      → JSON blob
    settings:channels:{tenant_id}   → hash of channel_id → JSON
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

log = logging.getLogger("warden.settings")

# ── Fernet encryption for secret values ──────────────────────────────────────

def _fernet():
    try:
        from cryptography.fernet import Fernet
        key = os.getenv("VAULT_MASTER_KEY", "")
        if key:
            return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        pass
    return None


def _encrypt(plaintext: str) -> str:
    f = _fernet()
    if f:
        return f.encrypt(plaintext.encode()).decode()
    return plaintext  # fallback: store as-is (dev mode)


def _decrypt(ciphertext: str) -> str:
    f = _fernet()
    if f:
        try:
            return f.decrypt(ciphertext.encode()).decode()
        except Exception:
            return ciphertext
    return ciphertext


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


# In-memory fallback stores (keyed by tenant_id)
_MEM_KEYS:     dict[str, dict[str, str]] = {}
_MEM_SECRETS:  dict[str, dict[str, str]] = {}
_MEM_AGENTS:   dict[str, str] = {}
_MEM_CHANNELS: dict[str, dict[str, str]] = {}


def _hgetall(rkey: str, mem: dict[str, dict[str, str]], tid: str) -> dict[str, str]:
    r = _redis()
    if r:
        try:
            return r.hgetall(rkey) or {}
        except Exception:
            pass
    return mem.get(tid, {})


def _hset(rkey: str, mem: dict[str, dict[str, str]], tid: str, field: str, val: str) -> None:
    r = _redis()
    if r:
        try:
            r.hset(rkey, field, val)
            return
        except Exception:
            pass
    mem.setdefault(tid, {})[field] = val


def _hdel(rkey: str, mem: dict[str, dict[str, str]], tid: str, field: str) -> None:
    r = _redis()
    if r:
        try:
            r.hdel(rkey, field)
            return
        except Exception:
            pass
    mem.get(tid, {}).pop(field, None)


def _get_str(rkey: str, mem_dict: dict[str, str], tid: str) -> str | None:
    r = _redis()
    if r:
        try:
            return r.get(rkey)
        except Exception:
            pass
    return mem_dict.get(tid)


def _set_str(rkey: str, mem_dict: dict[str, str], tid: str, val: str) -> None:
    r = _redis()
    if r:
        try:
            r.set(rkey, val)
            return
        except Exception:
            pass
    mem_dict[tid] = val


# ── API Keys ──────────────────────────────────────────────────────────────────

def _apikeys_rkey(tid: str) -> str:
    return f"settings:apikeys:{tid}"


def get_api_keys(tenant_id: str) -> list[dict[str, Any]]:
    rows = _hgetall(_apikeys_rkey(tenant_id), _MEM_KEYS, tenant_id)
    result = []
    for v in rows.values():
        try:
            result.append(json.loads(v))
        except Exception:
            pass
    result.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return result


def create_api_key(tenant_id: str, label: str) -> dict[str, Any]:
    """Generate a new API key. Returns the full key once — never stored in plaintext."""
    raw_key = f"sw_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    record = {
        "id": key_id,
        "label": label,
        "key_hash": key_hash,
        "prefix": raw_key[:10],
        "created_at": now,
        "last_used_at": None,
        "request_count": 0,
        "active": True,
    }
    _hset(_apikeys_rkey(tenant_id), _MEM_KEYS, tenant_id, key_id, json.dumps(record))
    log.info("API key created tenant=%s id=%s label=%s", tenant_id, key_id, label)
    return {**record, "key": raw_key}


def revoke_api_key(tenant_id: str, key_id: str) -> bool:
    rows = _hgetall(_apikeys_rkey(tenant_id), _MEM_KEYS, tenant_id)
    raw = rows.get(key_id)
    if not raw:
        return False
    try:
        record = json.loads(raw)
    except Exception:
        return False
    record["active"] = False
    _hset(_apikeys_rkey(tenant_id), _MEM_KEYS, tenant_id, key_id, json.dumps(record))
    log.info("API key revoked tenant=%s id=%s", tenant_id, key_id)
    return True


# ── Secrets ───────────────────────────────────────────────────────────────────

def _secrets_rkey(tid: str) -> str:
    return f"settings:secrets:{tid}"


def get_secrets(tenant_id: str) -> list[dict[str, Any]]:
    rows = _hgetall(_secrets_rkey(tenant_id), _MEM_SECRETS, tenant_id)
    result = []
    for v in rows.values():
        try:
            r = json.loads(v)
            r.pop("encrypted_value", None)   # never send value
            result.append(r)
        except Exception:
            pass
    result.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return result


def create_secret(
    tenant_id: str,
    name: str,
    value: str,
    description: str = "",
    expires_at: str | None = None,
) -> dict[str, Any]:
    secret_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    record = {
        "id": secret_id,
        "name": name,
        "description": description,
        "created_at": now,
        "updated_at": now,
        "expires_at": expires_at,
        "encrypted_value": _encrypt(value),
    }
    _hset(_secrets_rkey(tenant_id), _MEM_SECRETS, tenant_id, secret_id, json.dumps(record))
    log.info("Secret created tenant=%s id=%s name=%s", tenant_id, secret_id, name)
    out = {k: v for k, v in record.items() if k != "encrypted_value"}
    return out


def update_secret(
    tenant_id: str,
    secret_id: str,
    value: str | None = None,
    description: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any] | None:
    rows = _hgetall(_secrets_rkey(tenant_id), _MEM_SECRETS, tenant_id)
    raw = rows.get(secret_id)
    if not raw:
        return None
    try:
        record = json.loads(raw)
    except Exception:
        return None
    if value is not None:
        record["encrypted_value"] = _encrypt(value)
    if description is not None:
        record["description"] = description
    if expires_at is not None:
        record["expires_at"] = expires_at
    record["updated_at"] = datetime.now(UTC).isoformat()
    _hset(_secrets_rkey(tenant_id), _MEM_SECRETS, tenant_id, secret_id, json.dumps(record))
    log.info("Secret updated tenant=%s id=%s", tenant_id, secret_id)
    return {k: v for k, v in record.items() if k != "encrypted_value"}


def delete_secret(tenant_id: str, secret_id: str) -> bool:
    rows = _hgetall(_secrets_rkey(tenant_id), _MEM_SECRETS, tenant_id)
    if secret_id not in rows:
        return False
    _hdel(_secrets_rkey(tenant_id), _MEM_SECRETS, tenant_id, secret_id)
    log.info("Secret deleted tenant=%s id=%s", tenant_id, secret_id)
    return True


def get_secret_value(tenant_id: str, secret_id: str) -> str | None:
    """Return decrypted value — only for internal use (agent config injection)."""
    rows = _hgetall(_secrets_rkey(tenant_id), _MEM_SECRETS, tenant_id)
    raw = rows.get(secret_id)
    if not raw:
        return None
    try:
        record = json.loads(raw)
        return _decrypt(record.get("encrypted_value", ""))
    except Exception:
        return None


# ── Agent Config ──────────────────────────────────────────────────────────────

_DEFAULT_AGENT_CONFIG: dict[str, Any] = {
    "high_risk_threshold": 0.72,
    "block_threshold": 0.90,
    "sova_max_iterations": 10,
    "sova_enabled": True,
    "master_agent_enabled": False,
    "evolution_engine_enabled": False,
    "scan_interval_minutes": 5,
    "causal_arbiter_enabled": True,
    "phish_guard_enabled": True,
}


def _agent_rkey(tid: str) -> str:
    return f"settings:agent:{tid}"


def get_agent_config(tenant_id: str) -> dict[str, Any]:
    raw = _get_str(_agent_rkey(tenant_id), _MEM_AGENTS, tenant_id)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return dict(_DEFAULT_AGENT_CONFIG)


def update_agent_config(tenant_id: str, config: dict[str, Any]) -> dict[str, Any]:
    current = get_agent_config(tenant_id)
    current.update(config)
    _set_str(_agent_rkey(tenant_id), _MEM_AGENTS, tenant_id, json.dumps(current))

    # Hot-reload: push relevant thresholds to env so running agents pick them up
    os.environ["SEMANTIC_THRESHOLD"] = str(current.get("high_risk_threshold", 0.72))
    os.environ["BLOCK_THRESHOLD"] = str(current.get("block_threshold", 0.90))

    log.info("Agent config updated tenant=%s", tenant_id)
    return current


# ── Notification Channels ─────────────────────────────────────────────────────

def _channels_rkey(tid: str) -> str:
    return f"settings:channels:{tid}"


def _mask_config(config: dict[str, Any]) -> dict[str, Any]:
    masked = {}
    for k, v in config.items():
        if k in ("url", "email") and isinstance(v, str) and len(v) > 8:
            masked[k] = v[:6] + "***" + v[-4:]
        elif k in ("bot_token", "routing_key") and isinstance(v, str):
            masked[k] = "***" + v[-4:] if len(v) > 4 else "****"
        else:
            masked[k] = v
    return masked


def get_notification_channels(tenant_id: str) -> list[dict[str, Any]]:
    rows = _hgetall(_channels_rkey(tenant_id), _MEM_CHANNELS, tenant_id)
    result = []
    for v in rows.values():
        try:
            ch = json.loads(v)
            ch["config"] = _mask_config(ch.get("config", {}))
            result.append(ch)
        except Exception:
            pass
    result.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return result


def add_notification_channel(
    tenant_id: str,
    ch_type: str,
    label: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    channel_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    record = {
        "id": channel_id,
        "type": ch_type,
        "label": label,
        "config": config,
        "enabled": True,
        "created_at": now,
        "verified": False,
    }
    _hset(_channels_rkey(tenant_id), _MEM_CHANNELS, tenant_id, channel_id, json.dumps(record))
    log.info("Notification channel added tenant=%s id=%s type=%s", tenant_id, channel_id, ch_type)
    out = dict(record)
    out["config"] = _mask_config(config)
    return out


def test_notification_channel(tenant_id: str, channel_id: str) -> dict[str, Any]:
    """Send a test notification. Returns {ok, message, latency_ms}."""
    import time
    rows = _hgetall(_channels_rkey(tenant_id), _MEM_CHANNELS, tenant_id)
    raw = rows.get(channel_id)
    if not raw:
        return {"ok": False, "message": "Channel not found", "latency_ms": None}
    try:
        record = json.loads(raw)
    except Exception:
        return {"ok": False, "message": "Corrupt channel record", "latency_ms": None}

    ch_type = record.get("type")
    config = record.get("config", {})
    start = time.time()

    try:
        if ch_type in ("slack", "teams", "webhook"):
            import httpx
            url = config.get("url", "")
            payload = {
                "text": "✅ Shadow Warden AI — test notification",
                "blocks": [{"type": "section", "text": {"type": "mrkdwn",
                    "text": "🔔 *Shadow Warden AI* test notification from tenant `" + tenant_id + "`"}}],
            }
            resp = httpx.post(url, json=payload, timeout=8.0)
            ok = resp.status_code < 300
            msg = "Test sent successfully" if ok else f"HTTP {resp.status_code}"
        elif ch_type == "pagerduty":
            import httpx
            rk = config.get("routing_key", "")
            payload = {
                "routing_key": rk,
                "event_action": "trigger",
                "payload": {
                    "summary": "Shadow Warden AI test alert",
                    "severity": "info",
                    "source": f"shadow-warden/{tenant_id}",
                },
            }
            resp = httpx.post("https://events.pagerduty.com/v2/enqueue", json=payload, timeout=8.0)
            ok = resp.status_code < 300
            msg = "PagerDuty test triggered" if ok else f"HTTP {resp.status_code}"
        else:
            ok, msg = True, f"Test skipped for channel type '{ch_type}' (no live send in dev mode)"

        if ok:
            record["verified"] = True
            _hset(_channels_rkey(tenant_id), _MEM_CHANNELS, tenant_id, channel_id, json.dumps(record))

    except Exception as exc:
        ok = False
        msg = str(exc)

    latency_ms = round((time.time() - start) * 1000, 1)
    return {"ok": ok, "message": msg, "latency_ms": latency_ms}


def delete_notification_channel(tenant_id: str, channel_id: str) -> bool:
    rows = _hgetall(_channels_rkey(tenant_id), _MEM_CHANNELS, tenant_id)
    if channel_id not in rows:
        return False
    _hdel(_channels_rkey(tenant_id), _MEM_CHANNELS, tenant_id, channel_id)
    log.info("Notification channel deleted tenant=%s id=%s", tenant_id, channel_id)
    return True


# ── Summary ───────────────────────────────────────────────────────────────────

def get_settings_summary(tenant_id: str) -> dict[str, Any]:
    keys = get_api_keys(tenant_id)
    secs = get_secrets(tenant_id)
    channels = get_notification_channels(tenant_id)
    now = datetime.now(UTC)

    expiring_secrets = sum(
        1 for s in secs
        if s.get("expires_at") and
           datetime.fromisoformat(s["expires_at"]).replace(tzinfo=UTC) < now + timedelta(days=30)
    )
    unverified = sum(1 for c in channels if not c.get("verified"))

    return {
        "api_key_count": sum(1 for k in keys if k.get("active")),
        "secret_count": len(secs),
        "channel_count": len(channels),
        "agent_config": get_agent_config(tenant_id),
        "has_expiring_keys": False,
        "has_expiring_secrets": expiring_secrets > 0,
        "unverified_channels": unverified,
    }
