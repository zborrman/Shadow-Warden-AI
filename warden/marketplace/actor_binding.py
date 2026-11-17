"""
An agent named in a request body is bound to the tenant whose key made the call.

`warden/marketplace/CLAUDE.md` rule #25: an API key authenticates a tenant, not
an agent. Thirteen write routes took ``buyer_agent_id`` / ``seller_agent_id`` /
``agent_id`` / ``caller_did`` from the body and acted on it, so any tenant could
buy, list, clear, open escrow or check out a cart *as another tenant's agent*
by naming it (H-2, measured 2026-10-03; closed after the 2026-11-16 re-audit).

The binding is ownership, not a signature: the agent must not be registered to
a different tenant in either registry that records an owner
(``marketplace_agents.tenant_id``, ``kya_agent_profiles.owner_tenant_id``).
An id neither registry knows is let through - it belongs to nobody, so naming
it takes nothing from anyone - and the routes that move money still run their
own KYA / autonomy checks on it. Only the *acting* side is bound; a
counterparty (the seller a buyer opens escrow against) is named on purpose and
normally belongs to someone else.

Usage, mirroring :class:`warden.auth_guard.CallerTenant`::

    agent: CallerAgent = Depends(caller_agent_binding)
    ...
    body.buyer_agent_id = agent.bind(body.buyer_agent_id)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException

from warden.auth_guard import (
    AuthResult,
    _is_operator,
    require_api_key,
    tier_header_trusted,
)
from warden.kya.profile import get_profile
from warden.marketplace.agent import get_agent

log = logging.getLogger("warden.marketplace.actor_binding")


def agent_owners(agent_id: str) -> set[str]:
    """Every tenant either registry records as this agent's owner."""
    owners: set[str] = set()
    try:
        agent = get_agent(agent_id)
        if agent is not None and agent.tenant_id:
            owners.add(str(agent.tenant_id))
    except Exception as exc:  # registry unreadable: refuse below, never assume
        log.warning("actor_binding: marketplace registry unreadable: %s", type(exc).__name__)
        raise
    try:
        profile = get_profile(agent_id)
        if profile is not None and profile.owner_tenant_id:
            owners.add(str(profile.owner_tenant_id))
    except Exception as exc:
        log.warning("actor_binding: KYA registry unreadable: %s", type(exc).__name__)
        raise
    return owners


@dataclass(frozen=True)
class CallerAgent:
    auth: AuthResult
    x_admin_key: str | None = None

    def bind(self, agent_id: str | None) -> str:
        claimed = (agent_id or "").strip()
        if not claimed:
            return agent_id or ""
        # Dev/test (auth off) and the operator act for any agent.
        if tier_header_trusted() or _is_operator(self.auth, self.x_admin_key):
            return claimed
        try:
            owners = agent_owners(claimed)
        except Exception:
            # Fail closed: an ownership check that cannot run must not read as
            # "nobody owns it".
            raise HTTPException(
                status_code=503, detail="Agent ownership could not be verified."
            ) from None
        if owners and self.auth.tenant_id not in owners:
            raise HTTPException(
                status_code=403,
                detail="This agent is registered to another tenant.",
            )
        return claimed


def caller_agent_binding(
    auth: AuthResult = Depends(require_api_key),
    x_admin_key: str | None = Header(default=None),
) -> CallerAgent:
    """Dependency for a route whose body names the agent it acts as."""
    return CallerAgent(auth, x_admin_key)
