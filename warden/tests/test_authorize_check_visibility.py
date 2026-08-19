"""warden/tests/test_authorize_check_visibility.py — P1 chokepoint honesty.

`authorize_payment()` composes an autonomy check and a Budget Guardian check,
and reports one merged verdict. Measured against production on 2026-08-19 with
enforcement forced on:

    $5    verdict=REQUIRE_APPROVAL  checks={'autonomy': 'REQUIRE_APPROVAL', 'budget': 'ALLOW'}
    $500  verdict=REQUIRE_APPROVAL  checks={'autonomy': 'REQUIRE_APPROVAL', 'budget': 'ALLOW'}

The Budget Guardian allowed five hundred dollars — not because five hundred was
within a budget, but because `semantic_budget.check_budget()` short-circuits to
``agentic_commerce_not_enabled`` for any tenant that has not enabled agentic
commerce, which on production is every tenant. So the two-check chokepoint is a
one-check chokepoint, and nothing in the verdict, the checks dict or the metric
said so.

That is the same distinction the `enforced` label already draws one level up
(MP-6: allowed-because-checked versus allowed-because-switched-off), one layer
deeper. These tests pin it so the reporting cannot quietly regress to a uniform
ALLOW before somebody flips `AUTHORIZE_PAYMENT_ENFORCED` on the strength of a
gate that is half inert.
"""

from __future__ import annotations

from typing import Any

import pytest

from warden.payments import authorize as auth


class _Decision:
    """Stand-in for semantic_budget.BudgetDecision."""

    def __init__(self, allowed: bool, action: str, reason: str) -> None:
        self.allowed = allowed
        self.action = action
        self.reason = reason


def _patch_budget(monkeypatch: pytest.MonkeyPatch, decision: _Decision) -> None:
    import warden.business_community.agentic_commerce.semantic_budget as sb

    monkeypatch.setattr(sb, "check_budget", lambda *a, **kw: decision, raising=True)


# ── the reason string the whole file hinges on ────────────────────────────────
def test_sentinel_matches_the_budget_module() -> None:
    """If semantic_budget renames its reason, this file must fail, not drift.

    The distinction is carried by a string literal shared across two modules.
    A rename there would silently turn every `not_evaluated` back into a plain
    `allow` — the exact blindness this slice removes.
    """
    import inspect

    import warden.business_community.agentic_commerce.semantic_budget as sb

    assert auth._BUDGET_NOT_CONFIGURED in inspect.getsource(sb), (
        f"{auth._BUDGET_NOT_CONFIGURED!r} no longer appears in semantic_budget — "
        "the not_evaluated signal is dead. Update _BUDGET_NOT_CONFIGURED."
    )


# ── reasons ───────────────────────────────────────────────────────────────────
def test_unconfigured_budget_reports_not_evaluated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_budget(
        monkeypatch, _Decision(True, "allow", auth._BUDGET_NOT_CONFIGURED)
    )
    verdict, reason = auth._check_budget("t", 500.0, "m")
    assert verdict == "ALLOW", "an unconfigured budget must not start denying"
    assert reason.startswith("budget=not_evaluated"), reason


def test_configured_budget_that_passes_reports_a_plain_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_budget(monkeypatch, _Decision(True, "allow", "within_budget"))
    verdict, reason = auth._check_budget("t", 5.0, "m")
    assert (verdict, reason) == ("ALLOW", "budget=allow")


def test_configured_budget_still_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_budget(monkeypatch, _Decision(False, "block", "over_monthly_budget"))
    verdict, reason = auth._check_budget("t", 5000.0, "m")
    assert verdict == "DENY"
    assert "over_monthly_budget" in reason


# ── metric labelling ──────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("reason", "verdict", "expected"),
    [
        ("budget=not_evaluated:agentic_commerce_not_enabled", "ALLOW", "not_evaluated"),
        ("budget=allow", "ALLOW", "allow"),
        ("autonomy=REQUIRE_APPROVAL", "REQUIRE_APPROVAL", "require_approval"),
        ("autonomy_error=boom", "REQUIRE_APPROVAL", "error"),
        ("budget_error=redis down", "REQUIRE_APPROVAL", "error"),
        ("budget=block:over_monthly_budget", "DENY", "deny"),
    ],
)
def test_check_outcome_labels(reason: str, verdict: Any, expected: str) -> None:
    assert auth._check_outcome(reason, verdict) == expected


def test_an_allowing_but_inert_check_is_not_labelled_allow() -> None:
    """The regression that matters: `not_evaluated` collapsing back to `allow`.

    Both are ALLOW verdicts, so nothing in the composite output distinguishes
    them — the metric label is the only place the difference survives.
    """
    inert = auth._check_outcome(
        f"budget=not_evaluated:{auth._BUDGET_NOT_CONFIGURED}", "ALLOW"
    )
    passed = auth._check_outcome("budget=allow", "ALLOW")
    assert inert != passed, (
        "a check that allowed without evaluating anything must not share a label "
        "with one that evaluated and passed"
    )


# ── composition ───────────────────────────────────────────────────────────────
def test_full_authorization_surfaces_the_inert_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reproduces the production reading, and asserts the reason now says why."""
    monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
    _patch_budget(
        monkeypatch, _Decision(True, "allow", auth._BUDGET_NOT_CONFIGURED)
    )
    monkeypatch.setattr(
        auth, "_check_autonomy", lambda *a: ("REQUIRE_APPROVAL", "autonomy=REQUIRE_APPROVAL")
    )

    result = auth.authorize_payment("default", "did:shadow:nobody", "purchase", 500.0)

    assert result.verdict == "REQUIRE_APPROVAL"
    assert result.checks["budget"] == "ALLOW"
    assert any("not_evaluated" in r for r in result.reasons), result.reasons


def test_recording_a_check_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Telemetry must not block money, including when the metric is missing."""
    import warden.metrics as metrics

    monkeypatch.delattr(metrics, "PAYMENT_AUTHORIZATION_CHECK_TOTAL", raising=False)
    auth._record_check("budget", "budget=allow", "ALLOW")  # must not raise
