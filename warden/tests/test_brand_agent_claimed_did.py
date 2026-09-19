"""
warden/tests/test_brand_agent_claimed_did.py

`dispatch_action` reads `buyer_did` out of the request payload — or the
`X-Agent-ID` header — and handed it to `BrandAgentFilter.validate()` as though
it were an identity. Nothing had verified a signature at that point; the
handlers do that later, via `negotiation._assert_actor`.

An unproven DID is worse than no DID, because the gate uses it in both
directions:

  * `_get_trust_score(buyer_did)` — name a reputable agent and **borrow its
    standing** past a `BRAND_AGENT_MIN_TRUST` threshold.
  * `_check_rate(buyer_did)` — keyed per DID, so naming a victim **spends their
    budget**, and naming a fresh DID evades your own.

Only the deny-list is safe against a claim: claiming a different DID can only
make that check stricter.

The fix does not invent proof that is not there. It stops an unproven claim from
*granting* anything: trust scores 0, and the rate limit is charged to something
the caller cannot choose.
"""
from __future__ import annotations

import pytest
from starlette.requests import Request

from warden.marketplace import api as api_mod
from warden.marketplace.brand_agent import BrandAgentFilter


def _request(headers: dict | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/marketplace/action",
            "query_string": b"",
            "headers": [
                (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
            ],
            "client": ("10.0.0.7", 1234),
        }
    )


# ── trust is not borrowable ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_unproven_did_does_not_borrow_reputation(monkeypatch):
    f = BrandAgentFilter()
    monkeypatch.setattr(f, "_get_trust_score", lambda _did: 0.99)

    v = await f.validate("did:shadow:reputable", "send_offer", {}, did_proven=False)

    assert v.trust_score == 0.0, "a named DID must not lend its standing"
    assert v.checks.get("did_proven") is False


@pytest.mark.asyncio
async def test_a_proven_did_keeps_its_reputation(monkeypatch):
    f = BrandAgentFilter()
    monkeypatch.setattr(f, "_get_trust_score", lambda _did: 0.99)

    v = await f.validate("did:shadow:reputable", "send_offer", {}, did_proven=True)

    assert v.trust_score == pytest.approx(0.99)
    assert v.checks.get("did_proven") is True


@pytest.mark.asyncio
async def test_an_unproven_did_is_denied_when_a_trust_floor_is_set(monkeypatch):
    """With the gate armed, borrowed trust must fail closed rather than admit."""
    import warden.marketplace.brand_agent as ba

    monkeypatch.setattr(ba, "_MIN_TRUST", 0.5)
    f = BrandAgentFilter()
    monkeypatch.setattr(f, "_get_trust_score", lambda _did: 0.99)

    v = await f.validate("did:shadow:reputable", "send_offer", {}, did_proven=False)

    assert v.allowed is False
    assert "trust_too_low" in v.reason


# ── the rate limit is not someone else's to spend ────────────────────────────


@pytest.mark.asyncio
async def test_an_unproven_caller_does_not_spend_the_named_dids_budget(monkeypatch):
    seen: list[str] = []
    f = BrandAgentFilter()

    async def fake_rate(subject: str) -> bool:
        seen.append(subject)
        return True

    monkeypatch.setattr(f, "_check_rate", fake_rate)
    await f.validate(
        "did:shadow:victim", "send_offer", {},
        did_proven=False, rate_subject="tenant:t-caller",
    )

    assert seen == ["tenant:t-caller"]
    assert "did:shadow:victim" not in seen


@pytest.mark.asyncio
async def test_a_proven_did_is_rate_limited_as_itself(monkeypatch):
    seen: list[str] = []
    f = BrandAgentFilter()

    async def fake_rate(subject: str) -> bool:
        seen.append(subject)
        return True

    monkeypatch.setattr(f, "_check_rate", fake_rate)
    await f.validate(
        "did:shadow:buyer", "send_offer", {},
        did_proven=True, rate_subject="tenant:t-caller",
    )

    assert seen == ["did:shadow:buyer"]


@pytest.mark.asyncio
async def test_a_missing_subject_never_falls_back_to_the_claimed_did(monkeypatch):
    seen: list[str] = []
    f = BrandAgentFilter()

    async def fake_rate(subject: str) -> bool:
        seen.append(subject)
        return True

    monkeypatch.setattr(f, "_check_rate", fake_rate)
    await f.validate("did:shadow:victim", "send_offer", {}, did_proven=False)

    assert seen == ["unproven:anonymous"]


# ── the subject the caller cannot choose ─────────────────────────────────────


def test_the_subject_prefers_the_authenticated_tenant(monkeypatch):
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "resolve_tenant_id", lambda k: "t-real" if k == "k" else None)
    assert api_mod._unforgeable_subject(_request({"X-API-Key": "k"})) == "tenant:t-real"


def test_the_subject_falls_back_to_the_real_client_ip(monkeypatch):
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "resolve_tenant_id", lambda _k: None)
    subject = api_mod._unforgeable_subject(_request({"X-Tenant-ID": "t-victim"}))

    assert subject.startswith("ip:")
    assert "t-victim" not in subject, "a header claim must not become the subject"


def test_the_caller_passes_did_proven_false():
    """Ratchet: `dispatch_action` has no signature to check at that point, so
    it must say so. A future caller that proves the DID may pass True — but it
    has to prove it first."""
    from pathlib import Path

    src = Path(api_mod.__file__).read_text(encoding="utf-8")
    assert "did_proven=False" in src
    assert "rate_subject=_unforgeable_subject(request)" in src
