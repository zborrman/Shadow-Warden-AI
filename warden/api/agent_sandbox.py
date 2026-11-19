"""
warden/api/agent_sandbox.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Zero-Trust Agent Sandbox REST API — capability-manifest management and
behavioral-attestation verification.

Endpoints (all under ``/api/agent``)
────────────────────────────────────
  GET    /api/agent/manifests                     — list registered manifests
  GET    /api/agent/manifest/{agent_id}           — manifest detail
  POST   /api/agent/manifest/reload               — hot-reload from disk
  GET    /api/agent/session/{session_id}/verify   — verify attestation chain
  GET    /api/agent/session/{session_id}          — session metadata + events
  DELETE /api/agent/session/{session_id}          — kill-switch: revoke session

Extracted from ``warden/main.py`` (Phase 3). The AgentMonitor singleton is
published to ``warden.runtime`` in the app lifespan and resolved here; the
sandbox registry is a module-level singleton imported directly.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Header, HTTPException, status

from warden.agent_sandbox import get_registry as _get_sandbox_registry
from warden.auth_guard import AuthResult, _is_operator, require_api_key, tier_header_trusted
from warden.runtime import runtime as _runtime


def owned_session(
    session_id: str,
    auth: AuthResult = Depends(require_api_key),
    x_admin_key: str | None = Header(default=None),
) -> str:
    """The session must be the caller's tenant's, or the caller the operator.

    An agent session records the tenant that opened it. These routes took the
    id from the path and served (or killed) any tenant's session to any key -
    its tool timeline, its evidence bundle, or a kill-switch on it. Another
    tenant's session reads as not found, so ids cannot be probed.
    """
    if tier_header_trusted() or _is_operator(auth, x_admin_key):
        return session_id
    monitor = _runtime.get("agent_monitor")
    if monitor is None:
        return session_id  # the handler answers 503
    sess = monitor.get_session(session_id)
    if not sess or sess.get("tenant_id") != auth.tenant_id:
        raise HTTPException(status_code=404, detail=f"Session {session_id!r} not found.")
    return session_id

router = APIRouter(prefix="/api/agent", tags=["agent-sandbox"])


# ── Capability-manifest management ────────────────────────────────────────────

@router.get(
    "/manifests",
    summary="List all registered agent capability manifests",
    dependencies=[Depends(require_api_key)],
)
async def list_agent_manifests():
    """Return the list of all registered agent manifests (agent_id, tools, egress flag)."""
    return {"manifests": _get_sandbox_registry().list_agents()}


@router.get(
    "/manifest/{agent_id}",
    summary="Get capability manifest for a specific agent",
    dependencies=[Depends(require_api_key)],
)
async def get_agent_manifest(agent_id: str):
    """Return full manifest detail for *agent_id*, or 404 if not registered."""
    m = _get_sandbox_registry().get_manifest(agent_id)
    if m is None:
        raise HTTPException(status_code=404, detail=f"No manifest for agent_id={agent_id!r}.")
    return {
        "agent_id":               m.agent_id,
        "description":            m.description,
        "network_egress_allowed": m.network_egress_allowed,
        "default_deny":           m.default_deny,
        "capabilities": [
            {
                "tool_name":             c.tool_name,
                "allowed_params":        c.allowed_params,
                "max_calls_per_session": c.max_calls_per_session,
                "required_approval":     c.required_approval,
            }
            for c in m.capabilities
        ],
    }


@router.post(
    "/manifest/reload",
    summary="Hot-reload agent manifests from AGENT_SANDBOX_PATH",
    dependencies=[Depends(require_api_key)],
)
async def reload_agent_manifests():
    """Force-reload all manifests from the JSON file on disk."""
    count = await asyncio.to_thread(_get_sandbox_registry().reload)
    return {"loaded": count, "message": f"Reloaded {count} manifest(s) from disk."}


# ── Behavioral attestation ────────────────────────────────────────────────────

@router.get(
    "/session/{session_id}/verify",
    summary="Verify cryptographic attestation chain for an agent session",
    dependencies=[Depends(owned_session)],
)
async def verify_session_attestation(session_id: str):
    """
    Replay stored tool events and recompute the SHA-256 attestation chain.

    Returns ``valid=true`` when the stored token matches the computed token —
    confirming the session history has not been tampered with.
    """
    agent_monitor = _runtime.get("agent_monitor")
    if agent_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AgentMonitor not available.",
        )
    result = await asyncio.to_thread(agent_monitor.verify_attestation, session_id)
    if result.get("error") == "session_not_found":
        raise HTTPException(status_code=404, detail=f"Session {session_id!r} not found.")
    return result


@router.get(
    "/session/{session_id}",
    summary="Get metadata and events for an agent session",
    dependencies=[Depends(owned_session)],
)
async def get_agent_session(session_id: str):
    """Return full session metadata + tool event list for *session_id*."""
    agent_monitor = _runtime.get("agent_monitor")
    if agent_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AgentMonitor not available.",
        )
    sess = await asyncio.to_thread(agent_monitor.get_session, session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id!r} not found.")
    return sess


@router.delete(
    "/session/{session_id}",
    summary="Kill-switch: immediately revoke an agent session",
    dependencies=[Depends(owned_session)],
)
async def revoke_agent_session(
    session_id: str,
    reason: str = "admin_kill_switch",
):
    """
    Terminate an agent session immediately.

    Any subsequent ``/v1/chat/completions`` request carrying
    ``X-Session-ID: {session_id}`` will receive HTTP 403 until the session TTL
    expires.  The revocation is also recorded in session metadata for audit.
    """
    agent_monitor = _runtime.get("agent_monitor")
    if agent_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AgentMonitor not available.",
        )
    result = await asyncio.to_thread(agent_monitor.revoke_session, session_id, reason)
    return result
