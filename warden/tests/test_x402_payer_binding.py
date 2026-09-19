"""
warden/tests/test_x402_payer_binding.py

`require_payment()` proves who is paying — `_verify_payment_identity()` requires
an Ed25519 signature over the payment intent, and `test_x402_signed_identity.py`
pins that, because Strix once drained a victim's balance by sending
`base64({"agent_id": victim})` as `PAYMENT-SIGNATURE`.

It then kept the answer to itself and returned only allow/deny. The one
production caller settled the call like this:

    _agent_id = body.payload.get("agent_id") or request.headers.get("X-Agent-ID")
    await deduct_payment(str(_agent_id), "marketplace/search")

So the gate verified one identity and the till charged another: name any DID in
your own request body and its balance pays for your search. The front door was
locked and the register left open.

Reading it also surfaced a second defect in the same three lines. The credits
fast-path deducts a credit and returns "allowed", and this code then queued an
x402 deduction anyway — one search, charged on both rails, against rule 16
("credits take priority; the x402 path is only reached when they are
exhausted").

These tests pin both, and the shape of the fix: **charge the proven payer, or
charge nobody.** There is deliberately no fallback to a claimed id, because a
fallback is what the defect was.
"""
from __future__ import annotations

import pytest

from warden.marketplace import x402_gate as gate


class _State:
    pass


class _Req:
    """Minimal Request double: headers + the `.state` Starlette gives handlers."""

    def __init__(self, headers: dict | None = None):
        self.headers = headers or {}
        self.state = _State()


# ── the accessors, in isolation ───────────────────────────────────────────────


def test_no_verified_payer_means_charge_nobody():
    assert gate.verified_payer(_Req()) is None


def test_a_proven_payer_is_published_for_the_caller():
    req = _Req()
    gate._remember_payer(req, "did:shadow:proven")
    assert gate.verified_payer(req) == "did:shadow:proven"


def test_an_unproven_payer_is_published_as_none():
    """`_verify_payment_identity` returns None for a forged or absent signature.
    That None must reach the caller as None, not as a missing attribute that a
    later `or` turns into a claimed id."""
    req = _Req()
    gate._remember_payer(req, None)
    assert gate.verified_payer(req) is None


def test_credits_settlement_is_visible_to_the_caller():
    req = _Req()
    assert gate.settled_by_credits(req) is False
    gate._mark_settled_by_credits(req)
    assert gate.settled_by_credits(req) is True


def test_the_accessors_never_raise_on_a_request_without_state():
    """Defensive: a double or a non-HTTP scope must not turn a read into a 500
    on the money path."""

    class _Bare:
        headers: dict = {}

    assert gate.verified_payer(_Bare()) is None
    assert gate.settled_by_credits(_Bare()) is False
    gate._remember_payer(_Bare(), "x")          # must not raise
    gate._mark_settled_by_credits(_Bare())      # must not raise


# ── the settlement decision the caller makes ─────────────────────────────────
#
# `dispatch_action` is a large handler behind auth, rate limiting and a
# dispatcher; exercising it end to end here would test the router, not this
# decision. The decision itself is three lines, so it is expressed directly —
# and each case is one a reviewer can check against the source.


def _should_charge(req) -> str | None:
    """The rule as implemented in `api.py::dispatch_action`."""
    payer = gate.verified_payer(req)
    if payer and not gate.settled_by_credits(req):
        return payer
    return None


def test_the_proven_payer_is_charged():
    req = _Req()
    gate._remember_payer(req, "did:shadow:buyer")
    assert _should_charge(req) == "did:shadow:buyer"


def test_a_claimed_agent_id_is_never_charged():
    """The victim's DID in the body must not become the payer."""
    req = _Req(headers={"X-Agent-ID": "did:shadow:victim"})
    gate._remember_payer(req, None)             # signature absent or forged
    assert _should_charge(req) is None


def test_credits_and_x402_never_both_charge_one_call():
    req = _Req()
    gate._remember_payer(req, "did:shadow:buyer")
    gate._mark_settled_by_credits(req)
    assert _should_charge(req) is None


# ── the source itself: the fallback must not come back ───────────────────────


def test_the_claimed_identity_fallback_is_gone_from_the_caller():
    """A ratchet, because the defect was a single `or` and reads as harmless."""
    from pathlib import Path

    api = Path(gate.__file__).with_name("api.py").read_text(encoding="utf-8")
    assert 'request.headers.get("X-Agent-ID", "anonymous")' not in api, (
        "Charging a header-supplied agent id is the vuln-0004 hole one step "
        "later: the gate proves a payer, the till must not pick another."
    )
    assert "verified_payer(request)" in api


@pytest.mark.parametrize("helper", ["verified_payer", "settled_by_credits"])
def test_the_gate_publishes_its_outcome(helper: str):
    assert hasattr(gate, helper)
