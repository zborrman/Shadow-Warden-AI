"""
Anonymous money and identity writes (2026-07-29).

Third slice of the write-method audit, after test_write_method_audit.py (empty
bodies) and test_security_control_writes_auth.py (security controls). Re-probing
the 422 bucket with valid bodies found 26 routes that execute for an anonymous
caller; these fourteen move money or mint identity.

Every one of them takes the parties from the request body, so there was nothing
tying the caller to the agents they were transacting on behalf of:

  POST /marketplace/listings            publish under any seller_agent_id/tenant_id
  POST /marketplace/listings/{id}/purchase, /sponsor
  POST /marketplace/escrow (+ fund/deliver/confirm/dispute/resolve)
  POST /marketplace/clear               auto-rejects a buyer's other negotiations
  POST /marketplace/action              unified lifecycle dispatcher
  POST|DELETE /marketplace/agents/{id}/certificate   mint or revoke an ANS X.509
  POST /payments/usdc/intent            pay an attacker-chosen merchant_wallet

The escrow, listings and certificate routers each carried
`dependencies=[Depends(marketplace_rate_limit)]` and nothing else — the same
limiter-read-as-auth shape found on data_lifecycle in PR #244.

Reads are deliberately NOT gated. docs/anonymous-route-audit-2026-07-29.md
decided unauthenticated agent-to-agent discovery is the premise of the
marketplace, and test_anonymous_route_audit.py pins that half. This file pins the
complement: writes closed, discovery open.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def _client(monkeypatch):
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", "money-key", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app, raise_server_exceptions=False)


KEY = {"X-API-Key": "money-key"}

WRITES = [
    (
        "post",
        "/marketplace/listings",
        {
            "asset_id": "a",
            "seller_agent_id": "s",
            "community_id": "c",
            "tenant_id": "t",
            "price_usd": 1.0,
        },
    ),
    ("post", "/marketplace/listings/L1/purchase", {"buyer_agent_id": "b"}),
    ("post", "/marketplace/listings/L1/sponsor", {}),
    (
        "post",
        "/marketplace/escrow",
        {
            "listing_id": "l",
            "buyer_agent_id": "b",
            "seller_agent_id": "s",
            "amount_usd": 1.0,
        },
    ),
    ("post", "/marketplace/escrow/E1/fund", {}),
    ("post", "/marketplace/escrow/E1/deliver", {}),
    ("post", "/marketplace/escrow/E1/confirm", {}),
    ("post", "/marketplace/escrow/E1/dispute", {}),
    ("post", "/marketplace/escrow/E1/resolve", {}),
    ("post", "/marketplace/agents/A1/certificate", {"community_id": "c"}),
    ("delete", "/marketplace/agents/A1/certificate", None),
    ("post", "/payments/usdc/intent", {"amount_usd": 1.0, "merchant_wallet": "0x1"}),
    ("post", "/marketplace/clear", {"winner_negotiation_id": "n", "buyer_agent_id": "b"}),
    ("post", "/marketplace/action", {"action_type": "buy"}),
]


@pytest.mark.parametrize("verb,path,body", WRITES)
def test_money_and_identity_writes_require_auth(_client, verb, path, body):
    kwargs = {"json": body} if body is not None else {}
    assert getattr(_client, verb)(path, **kwargs).status_code == 401, (
        f"{verb.upper()} {path} executed without credentials."
    )


def test_certificate_cannot_be_minted_for_an_arbitrary_agent(_client):
    """
    An ANS X.509 certificate is the agent's identity in the marketplace. Minting
    one for someone else's agent_id — or revoking a live one — must not be
    reachable anonymously.
    """
    assert (
        _client.post(
            "/marketplace/agents/victim-agent/certificate", json={"community_id": "c"}
        ).status_code
        == 401
    )
    assert (
        _client.delete("/marketplace/agents/victim-agent/certificate").status_code == 401
    )


def test_clearing_cannot_be_triggered_for_another_buyer(_client):
    """
    Clearing auto-rejects every other pending negotiation for the named buyer, so
    an anonymous call is a denial primitive against a competitor's open deals.
    """
    assert (
        _client.post(
            "/marketplace/clear",
            json={"winner_negotiation_id": "n1", "buyer_agent_id": "victim-buyer"},
        ).status_code
        == 401
    )


def test_discovery_reads_stay_open(_client):
    """
    The complement of the gates above. Unauthenticated agent-to-agent lookup is
    the premise of the marketplace (docs/anonymous-route-audit-2026-07-29.md), so
    a later reflexive gating of discovery should fail here rather than silently
    break agent lookup.
    """
    assert _client.get("/marketplace/listings").status_code != 401
    assert _client.get("/marketplace/autonomy/a1").status_code != 401
    # verify only checks a PEM the caller already holds
    assert (
        _client.post("/marketplace/certificates/verify", json={"cert_pem": "x"}).status_code
        != 401
    )


def test_authenticated_write_still_reaches_the_handler(_client):
    resp = _client.post(
        "/payments/usdc/intent",
        json={"amount_usd": 1.0, "merchant_wallet": "0x1"},
        headers=KEY,
    )
    assert resp.status_code != 401, "the gate must not lock out legitimate callers"


def test_rate_limit_is_not_mistaken_for_auth():
    """
    These three routers carried `dependencies=[Depends(marketplace_rate_limit)]`
    and nothing else. A limiter throttles an anonymous caller; it does not
    authenticate one. Structural guard — with no global auth middleware, nothing
    else catches a dropped dependency.
    """
    from warden.marketplace import api_escrow, api_listings
    from warden.security import api as cert_api

    for mod in (api_escrow, api_listings, cert_api):
        names = [
            getattr(getattr(d, "dependency", None), "__name__", "")
            for d in mod._WRITE
        ]
        assert "require_api_key" in names, (
            f"{mod.__name__} lost its write-path auth dependency"
        )
