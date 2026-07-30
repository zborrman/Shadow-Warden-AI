"""
/.well-known/agent.json serves two protocols at once (2026-07-30).

The A2A v1.0 spec and the marketplace M2M protocol both claim this path.
`warden/marketplace/api.py::agent_discovery_alias` is registered first, so it won
and `warden/protocols/a2a/api.py::agent_card` was unreachable — an A2A agent
doing spec discovery received a manifest with no `schema_version`, while the
startup banner claimed "Agent Card: /.well-known/agent.json".

Picking a winner breaks one set of agents either way, so the two documents are
merged. That is only safe while their field sets stay disjoint, which is what
these tests hold.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app, raise_server_exceptions=False)


def test_field_sets_are_disjoint():
    """
    The merge is only lossless while no key appears in both documents. If this
    fails, one protocol's field is being silently dropped from discovery — pick
    a name that does not collide, or stop merging.
    """
    import asyncio

    from fastapi import Response

    from warden.marketplace.api import get_market_protocol
    from warden.protocols.a2a.agent_card import build_agent_card

    card = build_agent_card()
    manifest = asyncio.run(get_market_protocol(Response()))
    collisions = sorted(set(card) & set(manifest))
    assert not collisions, (
        f"agent.json fields collide between the A2A card and the marketplace "
        f"manifest: {collisions}. The marketplace value wins, so the A2A field "
        f"would vanish from discovery."
    )


def test_agent_discovery_is_merged(client):
    """Both protocols must be discoverable at the spec path."""
    resp = client.get("/.well-known/agent.json")
    assert resp.status_code == 200
    body = resp.json()

    # A2A v1.0 side — this is what was missing in production.
    assert body.get("schema_version") == "a2a/v1.0"
    assert body.get("endpoint", "").endswith("/a2a")
    assert "auth_schemes" in body
    assert "supported_task_types" in body

    # Marketplace side — unchanged, so existing agents keep working.
    assert body.get("market_id") == "shadow-warden-marketplace"
    assert "supported_actions" in body
    assert "escrow" in body


def test_marketplace_manifest_is_unchanged(client):
    """
    Every field the marketplace manifest served before the merge must still be
    present with the same value. Existing M2M agents poll this document.
    """
    import asyncio

    from fastapi import Response

    from warden.marketplace.api import get_market_protocol

    manifest = asyncio.run(get_market_protocol(Response()))
    body = client.get("/.well-known/agent.json").json()
    for key, value in manifest.items():
        assert body.get(key) == value, f"marketplace field '{key}' changed"


def test_card_also_has_its_own_path(client):
    """A direct, unambiguous way to fetch just the A2A card."""
    resp = client.get("/a2a/agent-card.json")
    assert resp.status_code == 200
    assert resp.json().get("schema_version") == "a2a/v1.0"
