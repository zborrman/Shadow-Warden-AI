"""
warden/tests/test_marketplace_owner_binding.py

`POST /marketplace/register` is unauthenticated by design — Stage 1 first
contact, D-5 — and it wrote `body.tenant_id` straight into the KYA record as
`owner_tenant_id`.

That field decides who pays. `listing.py::_resolve_owner_tenant_id` and
`clearing.py` read it to name the tenant that `authorize_payment()` charges, and
`autonomy.py::_owner_kyb_unverified()` asks KYB about it. So anyone could
register an agent declaring someone else's tenant as its owner, and that agent's
spend would be authorised against the victim's policy and budget — while, with
`KYB_ENFORCEMENT_ENABLED` on, inheriting the victim's VERIFIED compliance status.

Third instance today of one shape: a claimed identity used where a proven one
was meant. The others were the x402 payer (#509) and the Brand Agent gate.

Ownership now comes from the credential or not at all. Empty was already the
handled case everywhere downstream, and it fails conservative — the purchase
path falls back to the agent's *own* DID, which is self-scoped.
"""
from __future__ import annotations

import pytest
from starlette.requests import Request

from warden.marketplace import api as api_mod


def _request(headers: dict | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/marketplace/register",
            "query_string": b"",
            "headers": [
                (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
            ],
            "client": ("127.0.0.1", 1234),
        }
    )


def test_no_credential_means_no_owner():
    assert api_mod._authenticated_owner(_request()) == ""


def test_an_unknown_key_claims_nothing(monkeypatch):
    monkeypatch.setattr(api_mod, "log", api_mod.log)
    assert api_mod._authenticated_owner(_request({"X-API-Key": "not-a-real-key"})) == ""


def test_the_owner_is_the_tenant_the_credential_resolves(monkeypatch):
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "resolve_tenant_id", lambda key: "t-real" if key == "k" else None)
    assert api_mod._authenticated_owner(_request({"X-API-Key": "k"})) == "t-real"


def test_a_body_supplied_tenant_can_never_become_the_owner(monkeypatch):
    """The defect, stated directly: the victim is named in the body and the
    caller holds no credential for it."""
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "resolve_tenant_id", lambda _key: None)
    owner = api_mod._authenticated_owner(
        _request({"X-API-Key": "attacker-key", "X-Tenant-ID": "t-victim"})
    )
    assert owner == "", "a header or body claim must not confer ownership"


def test_a_resolver_failure_leaves_the_agent_unowned(monkeypatch):
    """Fail-safe direction: an error resolving the credential must not fall back
    to the claim it was there to replace."""
    import warden.auth_guard as ag

    def boom(_key):
        raise RuntimeError("key store unavailable")

    monkeypatch.setattr(ag, "resolve_tenant_id", boom)
    assert api_mod._authenticated_owner(_request({"X-API-Key": "k"})) == ""


def test_the_route_no_longer_reads_the_body_for_ownership():
    """Ratchet. The defect was one argument and read as obviously correct."""
    from pathlib import Path

    src = Path(api_mod.__file__).read_text(encoding="utf-8")
    assert "owner_tenant_id=body.tenant_id" not in src, (
        "Ownership must come from the credential. `body.tenant_id` is a claim, "
        "and this field decides which tenant a purchase is authorised against."
    )
    assert "_authenticated_owner(request)" in src


@pytest.mark.parametrize(
    "consumer",
    ["warden/marketplace/listing.py", "warden/marketplace/clearing.py"],
)
def test_consumers_still_guard_the_empty_owner(consumer: str):
    """Empty ownership is only safe because every reader already handles it.
    If a reader stops guarding, this fix starts writing an empty tenant into a
    money decision — so the guard is pinned here rather than assumed."""
    from pathlib import Path

    src = Path(api_mod.__file__).parents[2].joinpath(consumer).read_text(encoding="utf-8")
    assert "record and record.owner_tenant_id" in src
