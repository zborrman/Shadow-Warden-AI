"""
warden/tests/test_marketplace_commercial_reads_auth.py — audit S-6.

The M2M audit of 2026-11-11 (reconstruction stage R0, "close what is live")
found three marketplace **read** routes answering 200 to a caller with no
credentials:

    GET /marketplace/purchases          every agent's settled trades
    GET /marketplace/credits/balance    any tenant's spendable balance
    GET /marketplace/analytics/fairness trading-derived aggregate

The tables are empty in production today, so there was nothing to steal yet —
which is exactly why it had gone unnoticed. The finding becomes live with the
first real trade, and `test_marketplace_route_auth.py` could never catch it:
that ratchet covers POST/PUT/PATCH/DELETE only.

Two claims are tested separately, because they fail separately:

  * the routes refuse an anonymous caller (and `/listings` still does not —
    anonymous browsing is the premise of the marketplace, so over-gating is a
    regression too);
  * `list_purchases(tenant_id=...)` actually filters. It accepted that argument
    and ignored it: the SQL never referenced it, so a caller that asked for one
    tenant's slice got the whole table and could not tell.

Auth is enabled by patching `auth_guard`'s module globals rather than by
setting an environment variable — `_VALID_KEY` binds at import, so the suite's
`WARDEN_API_KEY=""` cannot be undone later (see
`test_marketplace_auth_actually_denies.py`).
"""
from __future__ import annotations

import pytest

_KEY = "s6-configured-key-not-a-real-credential"

#: Commercial reads. Each returned 200 to an anonymous caller before this fix.
GATED_READS = [
    "/marketplace/purchases",
    "/marketplace/credits/balance",
    "/marketplace/analytics/fairness",
]

#: Deliberately public: an agent finds goods before it has any relationship
#: with us. Gating these by reflex would break discovery.
PUBLIC_READS = [
    "/marketplace/listings",
    "/marketplace/protocol",
]


@pytest.fixture
def client(monkeypatch):
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", _KEY, raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app, raise_server_exceptions=False)


def test_the_key_really_reached_the_guard(client):
    """Guards the measurement: with auth off every case below passes vacuously."""
    import warden.auth_guard as ag

    assert ag._VALID_KEY == _KEY


@pytest.mark.parametrize("path", GATED_READS)
def test_commercial_read_refuses_an_anonymous_caller(client, path):
    status = client.get(path).status_code
    assert status == 401, (
        f"{path} served commercial data without credentials (got {status}). "
        f"Audit S-6: settled trades, credit balances and trading-derived "
        f"aggregates belong to the tenant that is party to them."
    )


@pytest.mark.parametrize("path", GATED_READS)
def test_commercial_read_accepts_the_configured_key(client, path):
    """The other half: a gate that refuses everyone is an outage, not a fix."""
    status = client.get(path, headers={"X-API-Key": _KEY}).status_code
    assert status != 401, f"{path} refused its own configured credential."
    assert status < 500, f"{path} answered {status} to an authenticated caller."


@pytest.mark.parametrize("path", PUBLIC_READS)
def test_discovery_stays_public(client, path):
    assert client.get(path).status_code != 401, (
        f"{path} now requires auth. Anonymous discovery is the premise of the "
        f"M2M marketplace — if that decision changes, change it here first."
    )


# ── tenant scoping of the purchase list ──────────────────────────────────────

def _seed(db_path: str) -> None:
    """Two tenants, one agent each, one purchase each.

    Rows go in through a connection rather than through `register_agent()`,
    which also mints an AP2 mandate — irrelevant here and a second failure
    mode in a test about a WHERE clause.
    """
    from warden.marketplace import listing as mkt

    with mkt._conn(db_path) as con:
        for agent_id, tenant in (("did:shadow:alice", "t-alice"),
                                 ("did:shadow:bob", "t-bob")):
            con.execute(
                "INSERT INTO marketplace_agents "
                "(agent_id, community_id, tenant_id, public_key, capabilities, "
                " status, mandate_id, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (agent_id, "c-1", tenant, "a2V5", '["buy"]', "active", "",
                 "2026-11-13T00:00:00+00:00"),
            )

    mkt.create_purchase(
        listing_id="L-1", asset_id="A-1", buyer_agent="did:shadow:alice",
        seller_agent="did:shadow:carol", price_paid=1.0, db_path=db_path,
    )
    mkt.create_purchase(
        listing_id="L-2", asset_id="A-2", buyer_agent="did:shadow:bob",
        seller_agent="did:shadow:carol", price_paid=2.0, db_path=db_path,
    )


def test_list_purchases_scopes_to_the_named_tenant(tmp_path):
    from warden.marketplace import listing as mkt

    db = str(tmp_path / "mkt.db")
    _seed(db)

    alice = mkt.list_purchases(tenant_id="t-alice", db_path=db)
    assert [p.buyer_agent for p in alice] == ["did:shadow:alice"], (
        "list_purchases accepted tenant_id and ignored it: the SQL never "
        "referenced the argument, so every caller asking for one tenant's "
        "trades received the whole table."
    )

    bob = mkt.list_purchases(tenant_id="t-bob", db_path=db)
    assert [p.buyer_agent for p in bob] == ["did:shadow:bob"]

    assert mkt.list_purchases(tenant_id="t-nobody", db_path=db) == []


def test_unscoped_listing_still_returns_everything(tmp_path):
    """`tenant_id=None` is the operator's view (X-Admin-Key on the route)."""
    from warden.marketplace import listing as mkt

    db = str(tmp_path / "mkt.db")
    _seed(db)

    assert len(mkt.list_purchases(db_path=db)) == 2


def test_a_tenant_cannot_name_another_tenants_agent(tmp_path):
    """The buyer_agent filter narrows the caller's own slice; it cannot widen it."""
    from warden.marketplace import listing as mkt

    db = str(tmp_path / "mkt.db")
    _seed(db)

    assert mkt.list_purchases(
        buyer_agent="did:shadow:bob", tenant_id="t-alice", db_path=db,
    ) == []


def test_seller_side_sees_its_own_sales(tmp_path):
    """A tenant is party to a trade as seller too, not only as buyer."""
    from warden.marketplace import listing as mkt

    db = str(tmp_path / "mkt.db")
    _seed(db)

    with mkt._conn(db) as con:
        con.execute(
            "INSERT INTO marketplace_agents "
            "(agent_id, community_id, tenant_id, public_key, capabilities, "
            " status, mandate_id, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("did:shadow:carol", "c-1", "t-carol", "a2V5", '["sell"]', "active",
             "", "2026-11-13T00:00:00+00:00"),
        )

    sales = mkt.list_purchases(tenant_id="t-carol", db_path=db)
    assert len(sales) == 2, (
        "Carol sold both assets; scoping on the buyer alone would hide a "
        "seller's own sales from it."
    )


# ── the operator's cross-tenant read ─────────────────────────────────────────
#
# `require_admin_key` is fail-closed but returns early when
# ALLOW_UNAUTHENTICATED=true, which the suite sets globally — so a test that
# did not turn that escape off would exercise nothing.

_ADMIN = "s6-admin-key-not-a-real-credential"


@pytest.fixture
def enforcing_client(monkeypatch):
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", _KEY, raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
    monkeypatch.setenv("ADMIN_KEY", _ADMIN)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app, raise_server_exceptions=False)


def test_naming_another_tenant_is_refused(enforcing_client):
    r = enforcing_client.get(
        "/marketplace/credits/balance",
        headers={"X-API-Key": _KEY, "X-Tenant-ID": "someone-else"},
    )
    assert r.status_code == 403, (
        f"X-Tenant-ID named another tenant and the route answered {r.status_code}. "
        "Before this fix the header chose the tenant outright, with no key at all."
    )


def test_the_caller_reads_its_own_balance(enforcing_client):
    r = enforcing_client.get(
        "/marketplace/credits/balance",
        headers={"X-API-Key": _KEY, "X-Tenant-ID": "default"},
    )
    assert r.status_code == 200
    assert r.json()["tenant_id"] == "default", (
        "The balance must be reported for the authenticated tenant, not for "
        "whatever the header said."
    )


def test_an_operator_may_read_another_tenant(enforcing_client):
    r = enforcing_client.get(
        "/marketplace/credits/balance",
        headers={"X-API-Key": _KEY, "X-Tenant-ID": "someone-else",
                 "X-Admin-Key": _ADMIN},
    )
    assert r.status_code == 200, (
        f"The operator path answered {r.status_code}; support and reconciliation "
        "depend on it, which is why gating the route did not simply remove it."
    )
    assert r.json()["tenant_id"] == "someone-else"


def test_a_wrong_admin_key_is_refused(enforcing_client):
    r = enforcing_client.get(
        "/marketplace/credits/balance",
        headers={"X-API-Key": _KEY, "X-Tenant-ID": "someone-else",
                 "X-Admin-Key": "not-the-admin-key"},
    )
    assert r.status_code == 403


def test_the_admin_path_is_disabled_when_no_key_is_configured(monkeypatch):
    """Fail-closed: an unprovisioned ADMIN_KEY is a 503, never a free pass."""
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", _KEY, raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
    monkeypatch.setenv("ADMIN_KEY", "")

    from fastapi.testclient import TestClient

    import warden.main as m

    r = TestClient(m.app, raise_server_exceptions=False).get(
        "/marketplace/purchases",
        headers={"X-API-Key": _KEY, "X-Admin-Key": "anything"},
    )
    assert r.status_code == 503, (
        f"Got {r.status_code}. An empty secret must disable the endpoint, never "
        "the check (warden/admin_guard.py)."
    )
