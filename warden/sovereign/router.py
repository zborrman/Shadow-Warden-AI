"""
warden/sovereign/router.py
────────────────────────────
Sovereign routing engine — select the correct MASQUE tunnel for a request.

The router is called before every proxied AI API call to determine:
  1. Which jurisdiction is appropriate for this request
  2. Which MASQUE tunnel to use (prefer ACTIVE, lowest latency)
  3. Whether the routing is compliant with the tenant's policy
  4. A routing decision record for attestation

RouteDecision fields:
  tunnel_id        Selected tunnel (None if DIRECT or BLOCKED)
  jurisdiction     Selected jurisdiction code
  compliant        Whether this routing satisfies the tenant's policy
  action           "TUNNEL" | "DIRECT" | "BLOCK"
  reason           Plain-English explanation
  frameworks       Compliance frameworks satisfied by this route
  latency_hint_ms  Expected additional latency from tunneling (from tunnel.latency_ms)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger("warden.sovereign.router")


@dataclass
class RouteDecision:
    tunnel_id:      str | None
    jurisdiction:   str
    compliant:      bool
    action:         str          # "TUNNEL" | "DIRECT" | "BLOCK"
    reason:         str
    frameworks:     list[str]
    latency_hint_ms: float | None


def route(
    tenant_id:   str,
    data_class:  str = "GENERAL",
    destination: str = "",        # destination AI provider domain (optional hint)
) -> RouteDecision:
    """
    Select the best MASQUE tunnel for *tenant_id* given *data_class*.

    Algorithm:
      1. Load tenant policy → allowed jurisdictions for data_class
      2. Query all ACTIVE tunnels in allowed jurisdictions
      3. Pick the tunnel with the lowest latency_ms (ties: prefer home_jurisdiction)
      4. If no ACTIVE tunnel: apply fallback_mode (BLOCK or DIRECT)
    """
    from warden.sovereign.jurisdictions import get_jurisdiction
    from warden.sovereign.policy import allowed_jurisdictions_for, get_policy
    from warden.sovereign.tunnel import list_tunnels

    pol         = get_policy(tenant_id)
    home_j      = pol.get("home_jurisdiction", "EU")
    fallback    = pol.get("fallback_mode", "BLOCK")
    preferred   = pol.get("preferred_tunnel_id")

    allowed_js = allowed_jurisdictions_for(data_class, tenant_id)
    if not allowed_js:
        return RouteDecision(
            tunnel_id     = None,
            jurisdiction  = home_j,
            compliant     = False,
            action        = "BLOCK",
            reason        = f"No jurisdictions allowed for data class {data_class!r}.",
            frameworks    = [],
            latency_hint_ms = None,
        )

    # Collect ACTIVE tunnels in allowed jurisdictions
    candidates = [
        t for t in list_tunnels()
        if t.status == "ACTIVE"
        and t.jurisdiction in allowed_js
        and (t.tenant_id is None or t.tenant_id == tenant_id)
    ]

    # Honour preferred tunnel if it's among candidates
    if preferred:
        pref = next((t for t in candidates if t.tunnel_id == preferred), None)
        if pref:
            j = get_jurisdiction(pref.jurisdiction)
            return RouteDecision(
                tunnel_id     = pref.tunnel_id,
                jurisdiction  = pref.jurisdiction,
                compliant     = True,
                action        = "TUNNEL",
                reason        = f"Using preferred tunnel {pref.tunnel_id} → {pref.jurisdiction}.",
                frameworks    = list(j.frameworks) if j else [],
                latency_hint_ms = pref.latency_ms,
            )

    if not candidates:
        # No tunnels — apply fallback
        if fallback == "DIRECT":
            log.warning(
                "sovereign.router: no ACTIVE tunnel for tenant=%s dc=%s — routing DIRECT (compliance warning)",
                tenant_id, data_class,
            )
            j = get_jurisdiction(home_j)
            return RouteDecision(
                tunnel_id     = None,
                jurisdiction  = home_j,
                compliant     = False,
                action        = "DIRECT",
                reason        = "No ACTIVE tunnel available. Routing DIRECT per fallback policy. COMPLIANCE WARNING.",
                frameworks    = list(j.frameworks) if j else [],
                latency_hint_ms = None,
            )
        else:
            return RouteDecision(
                tunnel_id     = None,
                jurisdiction  = home_j,
                compliant     = False,
                action        = "BLOCK",
                reason        = f"No ACTIVE MASQUE tunnel available for jurisdictions {allowed_js}. Request blocked.",
                frameworks    = [],
                latency_hint_ms = None,
            )

    # Pick best: prefer home_jurisdiction, then lowest latency
    def _rank(t) -> tuple[int, float]:
        is_home    = 0 if t.jurisdiction == home_j else 1
        lat        = t.latency_ms if t.latency_ms is not None else 9999.0
        return (is_home, lat)

    best = min(candidates, key=_rank)
    j    = get_jurisdiction(best.jurisdiction)

    return RouteDecision(
        tunnel_id     = best.tunnel_id,
        jurisdiction  = best.jurisdiction,
        compliant     = True,
        action        = "TUNNEL",
        reason        = (
            f"Routing via MASQUE tunnel {best.tunnel_id} "
            f"({best.jurisdiction} / {best.region}) "
            f"latency≈{best.latency_ms or '?'}ms."
        ),
        frameworks    = list(j.frameworks) if j else [],
        latency_hint_ms = best.latency_ms,
    )


def check_compliance(
    tenant_id:        str,
    from_jurisdiction: str,
    to_jurisdiction:   str,
    data_class:        str = "GENERAL",
) -> dict:
    """
    Check whether a specific cross-border transfer is compliant.

    Returns:
        allowed:     bool
        reason:      str
        frameworks:  list[str] — applicable compliance frameworks
        adequacy:    bool — adequacy decision exists between the two jurisdictions
    """
    from warden.sovereign.jurisdictions import (
        get_jurisdiction,
        is_transfer_allowed,
        jurisdictions_with_adequacy,
    )
    from warden.sovereign.policy import is_jurisdiction_allowed

    if not is_jurisdiction_allowed(to_jurisdiction, tenant_id):
        return {
            "allowed":    False,
            "reason":     f"Jurisdiction {to_jurisdiction!r} is blocked by tenant policy.",
            "frameworks": [],
            "adequacy":   False,
        }

    allowed = is_transfer_allowed(data_class, from_jurisdiction, to_jurisdiction)
    from_j  = get_jurisdiction(from_jurisdiction)
    adequacy = to_jurisdiction in jurisdictions_with_adequacy(from_jurisdiction)

    if not allowed:
        return {
            "allowed":    False,
            "reason":     (
                f"Transfer of {data_class} data from {from_jurisdiction} to "
                f"{to_jurisdiction} is restricted. No adequacy decision: {not adequacy}."
            ),
            "frameworks": list(from_j.frameworks) if from_j else [],
            "adequacy":   adequacy,
        }

    return {
        "allowed":    True,
        "reason":     f"Transfer compliant. Adequacy decision: {adequacy}.",
        "frameworks": list(from_j.frameworks) if from_j else [],
        "adequacy":   adequacy,
    }
