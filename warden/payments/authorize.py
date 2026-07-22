"""
warden/payments/authorize.py
──────────────────────────────
Single money-authorization chokepoint (FT-6) — mirrors the `agentic_gate()`
precedent (`warden/agent/gate.py`) for tool calls, but for money movement.

Before this, every money-moving marketplace endpoint (listing purchase,
clearing, credits purchase) ran ZERO of the checks that already exist
elsewhere in the codebase for exactly this purpose: autonomy level
(`marketplace/autonomy.py::check_action()`), the Budget Guardian
(`business_community/agentic_commerce/semantic_budget.py::check_budget()`),
and AP2 mandate verification. Each check already existed; nothing composed
them into one place a new money endpoint could call without having to
rediscover all three.

`authorize_payment()` composes autonomy + budget unconditionally — both
apply to any tenant/agent-attributed spend — and mandate verification only
when a ``mandate_id`` is supplied (AP2-specific; most money flows, e.g.
marketplace listing purchases, have no mandate at all). The x402 gate is
deliberately NOT folded in here: it already performs its own
deduction/settlement side effect (not just verification) and runs at a
different layer (HTTP request pre-flight, before an endpoint even knows the
final amount) — composing it would mean double-charging or restructuring
its call sites, out of scope for this slice.

Verdict precedence (most restrictive wins): DENY > REQUIRE_APPROVAL > ALLOW.
Opt-in via ``AUTHORIZE_PAYMENT_ENFORCED`` (default false) — matches every
other FT-5/FT-6 gate (KYB, sanctions, AML): existing deployments see zero
behavior change until an operator opts in. Fail-soft: a single check's own
failure degrades to REQUIRE_APPROVAL for that check's contribution alone
(never silently ALLOW, never hard-DENY on an infra error) — matching
`autonomy.check_action()`'s own error-degradation contract.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Literal

log = logging.getLogger("warden.payments.authorize")

Verdict = Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]

_PRECEDENCE: dict[str, int] = {"ALLOW": 0, "REQUIRE_APPROVAL": 1, "DENY": 2}


@dataclass
class AuthorizationResult:
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    checks: dict[str, str] = field(default_factory=dict)


def enforcement_enabled() -> bool:
    """True when authorize_payment() actually evaluates checks.

    Off by default so wiring this into a new call site cannot retroactively
    change behavior for deployments that haven't opted in.
    """
    return os.getenv("AUTHORIZE_PAYMENT_ENFORCED", "false").lower() == "true"


def _merge(current: Verdict, new: Verdict) -> Verdict:
    return new if _PRECEDENCE[new] > _PRECEDENCE[current] else current


def _check_autonomy(agent_id: str, action: str, amount_usd: float) -> tuple[Verdict, str]:
    try:
        from warden.marketplace.autonomy import check_action
        raw = check_action(agent_id, action, amount_usd)
        if raw == "BLOCK":
            return "DENY", "autonomy=BLOCK"
        if raw == "REQUIRE_APPROVAL":
            return "REQUIRE_APPROVAL", "autonomy=REQUIRE_APPROVAL"
        return "ALLOW", "autonomy=ALLOW"
    except Exception as exc:
        log.warning("authorize_payment: autonomy check failed (fail-soft): %s", exc)
        return "REQUIRE_APPROVAL", f"autonomy_error={exc}"


def _check_budget(tenant_id: str, amount_usd: float, merchant: str) -> tuple[Verdict, str]:
    try:
        from warden.business_community.agentic_commerce.semantic_budget import check_budget
        decision = check_budget(tenant_id, amount_usd, merchant=merchant)
        if not decision.allowed:
            return "DENY", f"budget={decision.action}:{decision.reason}"
        if decision.action == "require_approval":
            return "REQUIRE_APPROVAL", f"budget={decision.action}:{decision.reason}"
        return "ALLOW", "budget=allow"
    except Exception as exc:
        log.warning("authorize_payment: budget check failed (fail-soft): %s", exc)
        return "REQUIRE_APPROVAL", f"budget_error={exc}"


def _check_mandate(mandate_id: str, tenant_id: str) -> tuple[Verdict, str]:
    try:
        from warden.business_community.agentic_commerce.ap2 import AP2Processor
        result = AP2Processor().verify_mandate(mandate_id, tenant_id)
        if not result.get("valid"):
            return "DENY", f"mandate_invalid:{result.get('reason')}"
        return "ALLOW", "mandate=valid"
    except Exception as exc:
        log.warning("authorize_payment: mandate check failed (fail-soft): %s", exc)
        return "REQUIRE_APPROVAL", f"mandate_error={exc}"


def authorize_payment(
    tenant_id: str,
    agent_id: str,
    action: str,
    amount_usd: float,
    *,
    merchant: str = "",
    mandate_id: str | None = None,
) -> AuthorizationResult:
    """The chokepoint every money-moving action should pass through (FT-6).

    No-op ALLOW unless ``AUTHORIZE_PAYMENT_ENFORCED=true``. When enabled,
    composes the autonomy check + Budget Guardian (always) and mandate
    verification (only when ``mandate_id`` is given). The most restrictive
    verdict across all evaluated checks wins.
    """
    if not enforcement_enabled():
        return AuthorizationResult(verdict="ALLOW", reasons=["enforcement_disabled"])

    verdict: Verdict = "ALLOW"
    reasons: list[str] = []
    checks: dict[str, str] = {}

    autonomy_verdict, autonomy_reason = _check_autonomy(agent_id, action, amount_usd)
    verdict = _merge(verdict, autonomy_verdict)
    reasons.append(autonomy_reason)
    checks["autonomy"] = autonomy_verdict

    budget_verdict, budget_reason = _check_budget(tenant_id, amount_usd, merchant)
    verdict = _merge(verdict, budget_verdict)
    reasons.append(budget_reason)
    checks["budget"] = budget_verdict

    if mandate_id:
        mandate_verdict, mandate_reason = _check_mandate(mandate_id, tenant_id)
        verdict = _merge(verdict, mandate_verdict)
        reasons.append(mandate_reason)
        checks["mandate"] = mandate_verdict

    return AuthorizationResult(verdict=verdict, reasons=reasons, checks=checks)
