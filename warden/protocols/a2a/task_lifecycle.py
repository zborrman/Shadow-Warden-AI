"""
warden/protocols/a2a/task_lifecycle.py
────────────────────────────────────────
A2A v1.0 Task state machine.

States (A2A spec):
  submitted      → task received, not yet started
  working        → agent is processing
  input-required → agent needs more information from caller
  completed      → task finished successfully
  failed         → task finished with error
  canceled       → task was explicitly canceled

Persistence: Redis (a2a:task:{task_id} JSON, 24h TTL).
Falls back to in-process dict when Redis is unavailable.

Dispatch: each task type maps to a handler coroutine.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import time
import uuid
from collections.abc import Callable
from typing import Any

log = logging.getLogger("warden.protocols.a2a.task")

_TTL         = 86_400   # 24 hours in seconds
_MAX_HISTORY = 20       # max messages stored per task

# ── E2E encryption constants ──────────────────────────────────────────────────
E2E_CONTENT_TYPE = "application/warden-a2a-encrypted"

# Server-side ephemeral X25519 keypair — generated once per process, published
# in the agent card so callers can encrypt task inputs before sending.
_e2e_server_key: tuple[str, str] | None = None  # (priv_b64, pub_b64)


def _get_server_e2e_key() -> tuple[str, str]:
    """Return the server's X25519 keypair, generating it lazily on first call."""
    global _e2e_server_key
    if _e2e_server_key is None:
        try:
            from warden.syndicates.crypto import TunnelCrypto
            _e2e_server_key = TunnelCrypto.generate_keypair()
            log.info("A2A: E2E server keypair initialised (ephemeral per process)")
        except Exception as exc:
            log.warning("A2A: E2E keypair generation failed (%s) — E2E disabled", exc)
            _e2e_server_key = ("", "")
    return _e2e_server_key


def get_server_e2e_pubkey() -> str:
    """Return the server's X25519 public key (base64url) for caller-side encryption."""
    return _get_server_e2e_key()[1]


def _decrypt_e2e_input(
    encrypted_input: dict,
    caller_pub_key: str,
    task_id: str,
) -> dict:
    """
    Decrypt an E2E-encrypted task input.

    The caller performed ECDH(caller_priv, server_pub) to derive the AES key;
    we mirror that with ECDH(server_priv, caller_pub).  task_id is used as the
    HKDF info tag to bind the key to this specific task.

    Raises ValueError on decryption failure.
    """
    from warden.syndicates.crypto import DecryptionError, TunnelCrypto

    server_priv, _ = _get_server_e2e_key()
    if not server_priv:
        raise ValueError("E2E encryption not available on this server")
    try:
        aes_key = TunnelCrypto.derive_shared_key(server_priv, caller_pub_key, task_id)
        plaintext = TunnelCrypto.decrypt(encrypted_input, aes_key)
        return json.loads(plaintext)
    except DecryptionError as exc:
        raise ValueError(f"E2E decryption failed (wrong key or tampered payload): {exc}") from exc
    except Exception as exc:
        raise ValueError(f"E2E decryption error: {exc}") from exc

# ── In-process fallback store ─────────────────────────────────────────────────
_mem_store: dict[str, dict] = {}


def _redis():
    try:
        import redis as _redis_lib
        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        if url.startswith("memory://"):
            return None
        return _redis_lib.from_url(url, decode_responses=True)
    except Exception:
        return None


def _save(task: dict) -> None:
    r = _redis()
    key = f"a2a:task:{task['task_id']}"
    payload = json.dumps(task)
    if r:
        try:
            r.setex(key, _TTL, payload)
            return
        except Exception:
            pass
    _mem_store[key] = task


def _load(task_id: str) -> dict | None:
    r = _redis()
    key = f"a2a:task:{task_id}"
    if r:
        try:
            raw = r.get(key)
            if raw:
                return json.loads(raw)
        except Exception:
            pass
    return _mem_store.get(key)


def _delete(task_id: str) -> None:
    r = _redis()
    key = f"a2a:task:{task_id}"
    if r:
        with contextlib.suppress(Exception):
            r.delete(key)
    _mem_store.pop(key, None)


# ── Handler registry ─────────────────────────────────────────────────────────
_HANDLERS: dict[str, Callable] = {}


def register_handler(task_type: str):
    """Decorator to register a coroutine as handler for *task_type*."""
    def _dec(fn: Callable) -> Callable:
        _HANDLERS[task_type] = fn
        return fn
    return _dec


# ── CRUD ─────────────────────────────────────────────────────────────────────

def create_task(
    task_type:   str,
    input_data:  dict,
    caller_did:  str  = "",
    tenant_id:   str  = "default",
    *,
    e2e_caller_pub_key: str = "",
    e2e_encrypted_input: dict | None = None,
) -> dict:
    """
    Create a new A2A task in 'submitted' state and return the task record.

    E2E encryption (optional)
    ─────────────────────────
    Pass *e2e_caller_pub_key* (caller's ephemeral X25519 public key, base64url)
    and *e2e_encrypted_input* (``{"nonce": ..., "ciphertext": ...}`` from
    ``TunnelCrypto.encrypt``) to have the server decrypt the task input before
    running the handler.  The shared AES-256-GCM key is derived via
    ECDH(server_priv, caller_pub) + HKDF-SHA256 keyed on the task_id.

    Raises ValueError if E2E decryption fails.
    """
    task_id = str(uuid.uuid4())

    if e2e_caller_pub_key and e2e_encrypted_input:
        input_data = _decrypt_e2e_input(e2e_encrypted_input, e2e_caller_pub_key, task_id)
        log.debug("A2A task %s: E2E input decrypted successfully", task_id)

    task = {
        "task_id":    task_id,
        "task_type":  task_type,
        "state":      "submitted",
        "caller_did": caller_did,
        "tenant_id":  tenant_id,
        "input":      input_data,
        "output":     None,
        "error":      None,
        "messages":   [],
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    _save(task)
    return task


def get_task(task_id: str) -> dict | None:
    return _load(task_id)


def _update(task: dict, **kwargs: Any) -> dict:
    task.update(kwargs)
    task["updated_at"] = time.time()
    _save(task)
    return task


def append_message(task_id: str, role: str, content: str) -> bool:
    """Append a message to the task conversation history."""
    task = _load(task_id)
    if not task:
        return False
    msgs = task.get("messages", [])
    msgs.append({"role": role, "content": content, "ts": time.time()})
    if len(msgs) > _MAX_HISTORY:
        msgs = msgs[-_MAX_HISTORY:]
    task["messages"] = msgs
    _update(task)
    return True


def cancel_task(task_id: str) -> dict | None:
    task = _load(task_id)
    if not task:
        return None
    if task["state"] in ("completed", "failed", "canceled"):
        return task
    return _update(task, state="canceled")


# ── Execution ─────────────────────────────────────────────────────────────────

async def run_task(task_id: str) -> dict:
    """
    Transition task to 'working', dispatch to handler, then mark completed/failed.

    Handlers may set state to 'input-required' themselves and return early;
    `resume_task()` re-enters the handler with additional input.
    """
    task = _load(task_id)
    if not task:
        return {"error": "task_not_found", "task_id": task_id}

    if task["state"] not in ("submitted", "input-required"):
        return task

    _update(task, state="working")

    handler = _HANDLERS.get(task["task_type"])
    if not handler:
        return _update(
            task,
            state="failed",
            error=f"No handler registered for task type '{task['task_type']}'.",
        )

    try:
        result = await handler(task)
        if task["state"] == "working":
            _update(task, state="completed", output=result)
    except Exception as exc:
        log.exception("A2A task %s failed: %s", task_id, exc)
        _update(task, state="failed", error=str(exc))

    return _load(task_id) or task


async def resume_task(task_id: str, additional_input: dict) -> dict:
    """Provide additional input to a task that is in 'input-required' state."""
    task = _load(task_id)
    if not task:
        return {"error": "task_not_found", "task_id": task_id}
    if task["state"] != "input-required":
        return {"error": "task_not_waiting_for_input", "state": task["state"], "task_id": task_id}
    inp = task.get("input", {})
    inp.update(additional_input)
    _update(task, input=inp, state="submitted")
    return await run_task(task_id)


# ── Built-in handlers ─────────────────────────────────────────────────────────

@register_handler("security_filter")
async def _handle_security_filter(task: dict) -> dict:
    """Proxy the task input through the /filter pipeline."""
    import httpx
    content   = task["input"].get("content", "")
    tenant_id = task.get("tenant_id", "default")
    api_key   = os.getenv("WARDEN_API_KEY", "")
    base_url  = os.getenv("A2A_BASE_URL", "http://localhost:8001")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{base_url}/filter",
                json={"content": content, "tenant_id": tenant_id},
                headers={"X-API-Key": api_key},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        raise RuntimeError(f"Filter call failed: {exc}") from exc


@register_handler("threat_analysis")
async def _handle_threat_analysis(task: dict) -> dict:
    """Delegate to SOVA agent for threat analysis."""
    import httpx
    query     = task["input"].get("query", "")
    session   = task["input"].get("session_id", task["task_id"])
    api_key   = os.getenv("WARDEN_API_KEY", "")
    base_url  = os.getenv("A2A_BASE_URL", "http://localhost:8001")
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{base_url}/agent/sova",
                json={"query": query, "session_id": session},
                headers={"X-API-Key": api_key},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        raise RuntimeError(f"SOVA call failed: {exc}") from exc


@register_handler("marketplace_search")
async def _handle_marketplace_search(task: dict) -> dict:
    """Search the marketplace listings."""
    import httpx
    q         = task["input"].get("query", "")
    max_price = task["input"].get("max_price", 1_000_000.0)
    asset_type = task["input"].get("asset_type", "")
    api_key   = os.getenv("WARDEN_API_KEY", "")
    base_url  = os.getenv("A2A_BASE_URL", "http://localhost:8001")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{base_url}/marketplace/listings",
                params={"q": q, "max_price": max_price, "asset_type": asset_type},
                headers={"X-API-Key": api_key},
            )
            resp.raise_for_status()
            return {"listings": resp.json()}
    except Exception as exc:
        raise RuntimeError(f"Marketplace search failed: {exc}") from exc


@register_handler("compliance_report")
async def _handle_compliance_report(task: dict) -> dict:
    """Fetch compliance posture from the compliance API."""
    import httpx
    framework = task["input"].get("framework", "")
    api_key   = os.getenv("WARDEN_API_KEY", "")
    base_url  = os.getenv("A2A_BASE_URL", "http://localhost:8001")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            path = f"/compliance/posture/{framework}" if framework else "/compliance/posture"
            resp = await client.get(
                f"{base_url}{path}",
                headers={"X-API-Key": api_key},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        raise RuntimeError(f"Compliance report failed: {exc}") from exc
