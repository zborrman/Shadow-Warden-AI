"""
warden/tests/test_community_store_bridge.py — D-6 one store behind /communities.

`/communities` is served by two routers whose routes do not collide, so both are
live — on disjoint halves of one API, backed by two different SQLite files:

    warden/communities/router.py  → warden_community_registry.db
        POST "" (create), GET /{id}, members, entities, break-glass, rotate
    warden/api/communities_v2.py  → warden_communities.db
        /{id}/join, /{id}/settings, /{id}/data, /{id}/peers, networks, analytics

v2 has **no create endpoint**, and the only writer of its table has no caller
outside tests — so before D-6 every v2 endpoint that resolved a community 404'd
on every community the API could actually produce. `test_join_resolves_a_created_
community` is that exact defect, pinned.
"""
from __future__ import annotations

import pytest

from warden.communities import community_factory as factory
from warden.communities import registry


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMUNITY_REGISTRY_PATH", str(tmp_path / "registry.db"))
    monkeypatch.setenv("COMM_DB_PATH", str(tmp_path / "communities.db"))
    monkeypatch.setattr(registry, "_REGISTRY_DB_PATH", str(tmp_path / "registry.db"))
    monkeypatch.setattr(factory, "COMM_DB_PATH", str(tmp_path / "communities.db"))
    yield


def _create(tenant="t1", *, visibility="PUBLIC", approval=False, name="Acme SOC"):
    return registry.create_community(
        tenant_id=tenant, display_name=name, created_by=tenant, description="d",
        tier="business",
        settings={
            "visibility": {"visibility": visibility, "type": "MARKETPLACE"},
            "security": {"join_approval_required": approval},
            "governance": {}, "integrations": {},
        },
    )


# ── The defect ────────────────────────────────────────────────────────────────

def test_join_resolves_a_created_community():
    """POST /communities then POST /communities/{id}/join must not 404.

    The join handler calls community_factory.get_community(); before the bridge
    that read a different database and returned None for everything.
    """
    cid = _create().community_id
    c = factory.get_community(cid)
    assert c is not None, "the v2 half of /communities cannot see a created community"
    assert c.name == "Acme SOC"
    assert c.creator_tenant_id == "t1"


# ── Projection of the wizard payload onto the discovery model ─────────────────

@pytest.mark.parametrize(
    ("visibility", "approval", "expect_vis", "expect_join"),
    [
        ("PUBLIC",      False, "public",  "open"),
        ("PUBLIC",      True,  "public",  "approval"),
        ("PRIVATE",     True,  "private", "approval"),
        ("INVITE_ONLY", False, "private", "invite"),
        ("INVITE_ONLY", True,  "private", "invite"),
    ],
)
def test_visibility_projection(visibility, approval, expect_vis, expect_join):
    cid = _create(visibility=visibility, approval=approval).community_id
    c = factory.get_community(cid)
    assert (c.visibility, c.join_policy) == (expect_vis, expect_join)


def test_projection_defaults_are_closed_when_settings_are_absent():
    """A community with no wizard payload must not become world-joinable."""
    vis, join = factory._registry_visibility({})
    assert vis == "private"
    assert join == "approval"


# ── Writes reach the canonical store ──────────────────────────────────────────

def test_patch_reaches_the_canonical_store():
    cid = _create().community_id
    assert factory.patch_community(cid, name="Acme SOC EU") is True
    assert factory.get_community(cid).name == "Acme SOC EU"
    assert registry.get_community(cid).display_name == "Acme SOC EU"


def test_settings_update_reaches_the_canonical_store():
    cid = _create().community_id
    assert factory.update_community_settings(
        cid, {"visibility": {"visibility": "INVITE_ONLY"}}
    ) is True
    assert factory.get_community(cid).join_policy == "invite"


def test_status_update_reaches_the_canonical_store():
    cid = _create().community_id
    assert factory.update_community_status(cid, "suspended") is True
    assert factory.get_community(cid).status == "suspended"
    assert registry.get_community(cid).status == "SUSPENDED"


def test_delete_requires_the_owning_tenant():
    cid = _create(tenant="owner").community_id
    assert factory.delete_community(cid, "attacker") is False
    assert registry.get_community(cid) is not None, "a non-owner deleted a community"
    assert factory.delete_community(cid, "owner") is True
    assert registry.get_community(cid) is None


# ── Legacy rows keep working ──────────────────────────────────────────────────

def test_legacy_factory_rows_still_resolve():
    """Rows already in warden_communities.db must not stop resolving."""
    legacy = factory.create_community(
        name="Legacy", description="d", creator_tenant_id="t9",
        visibility="public", join_policy="open",
    )
    got = factory.get_community(legacy.community_id)
    assert got is not None and got.name == "Legacy"


def test_listing_unions_both_stores_without_duplicates():
    legacy = factory.create_community(
        name="Legacy", description="d", creator_tenant_id="t1",
        visibility="public", join_policy="open",
    )
    canonical = _create(tenant="t1").community_id

    ids = [c.community_id for c in factory.list_communities(creator_tenant_id="t1")]
    assert legacy.community_id in ids
    assert canonical in ids
    assert len(ids) == len(set(ids)), "a community was reported twice"


def test_unknown_id_still_returns_none():
    assert factory.get_community("does-not-exist") is None


def test_registry_failure_falls_back_rather_than_raising(monkeypatch):
    """An unreachable canonical store must degrade to the legacy table, not 500."""
    legacy = factory.create_community(
        name="Legacy", description="d", creator_tenant_id="t1",
    )

    def _boom(*_a, **_kw):
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(registry, "get_community", _boom)
    got = factory.get_community(legacy.community_id)
    assert got is not None and got.name == "Legacy"
