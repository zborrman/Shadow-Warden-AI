"""
warden/tests/test_purchase_escrow_atomicity.py — purchase + escrow in one transaction.

`_do_purchase` used to commit three separate statements: INSERT purchase, then
`create_escrow`'s own INSERT, then an UPDATE writing the escrow_id back. Every
gap between them is a state a crash could leave behind, and the last is the
worst — the escrow row exists, funds are held against it, and the purchase still
reads `escrow_id=""`.

The `_db_lock` around them is a `threading.RLock`: in-process only. `arq-worker`
and `workers/x402_settlement.py` write this same database from other containers,
so the lock never closed the window it appeared to guard.

These tests pin the transaction boundary, not the happy path — a failure injected
between the two writes must leave *neither* row, and the escrow-failure policy
(purchase still recorded, with escrow_id="") must be unchanged.
"""
from __future__ import annotations

import pytest

from warden.marketplace import listing
from warden.marketplace.escrow import EscrowService


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "marketplace.db")
    monkeypatch.setattr(listing, "_DB_PATH", path, raising=False)
    monkeypatch.setenv("MARKETPLACE_DB_PATH", path)
    # No RPC configured → _deploy_contract runs in simulation mode.
    monkeypatch.delenv("SEPOLIA_RPC_URL", raising=False)
    return path


def _seed_listing(db_path: str, price: float = 10.0):
    return listing.publish_listing(
        asset_id="asset-1", seller_agent="did:seller", community_id="c1",
        tenant_id="t1", asset_type="rule", price_usd=price, db_path=db_path,
    )


def _rows(db_path: str, table: str) -> list:
    with listing._conn(db_path) as con:
        return con.execute(f"SELECT * FROM {table}").fetchall()


# ── The happy path now writes both rows together ──────────────────────────────

def test_purchase_and_escrow_are_written_together(db):
    lst = _seed_listing(db)
    out = listing.purchase_listing(lst.listing_id, "did:buyer", db_path=db)

    purchases = _rows(db, "marketplace_purchases")
    escrows = _rows(db, "marketplace_escrow")
    assert len(purchases) == 1 and len(escrows) == 1

    # The escrow_id is written *with* the purchase row — there is no follow-up
    # UPDATE that a crash could skip.
    assert out["escrow_id"]
    assert purchases[0]["escrow_id"] == out["escrow_id"]
    assert escrows[0]["purchase_id"] == out["purchase_id"]


# ── The transaction boundary ──────────────────────────────────────────────────

def test_escrow_insert_failure_rolls_back_the_purchase(db, monkeypatch):
    """A failure *between* the two writes must leave neither row.

    Before the fix the purchase was already committed by the time the escrow
    insert ran, so this left a paid-for purchase with no escrow behind it.
    """
    lst = _seed_listing(db)

    def _boom(_con, _escrow):
        raise RuntimeError("escrow insert failed mid-transaction")

    monkeypatch.setattr(EscrowService, "insert_escrow", staticmethod(_boom))

    with pytest.raises(RuntimeError):
        listing.purchase_listing(lst.listing_id, "did:buyer", db_path=db)

    assert _rows(db, "marketplace_purchases") == [], "purchase survived a failed escrow write"
    assert _rows(db, "marketplace_escrow") == []


def test_no_orphan_escrow_when_the_purchase_insert_fails(db, monkeypatch):
    """The mirror image: a failing purchase insert must not leave an escrow row
    holding funds against a purchase that does not exist."""
    lst = _seed_listing(db)

    real = listing.create_purchase

    def _boom(*a, **kw):
        real(*a, **kw)
        raise RuntimeError("purchase insert failed mid-transaction")

    monkeypatch.setattr(listing, "create_purchase", _boom)

    with pytest.raises(RuntimeError):
        listing.purchase_listing(lst.listing_id, "did:buyer", db_path=db)

    assert _rows(db, "marketplace_escrow") == []
    assert _rows(db, "marketplace_purchases") == []


# ── Policy that must NOT change ───────────────────────────────────────────────

def test_contract_deployment_failure_still_records_the_purchase(db, monkeypatch):
    """Escrow-failure policy is deliberately preserved.

    When the chain RPC is configured but unreachable, `build_escrow` raises and
    the purchase is still recorded with escrow_id="" — exactly as before. Making
    that roll the purchase back is a money-semantics decision for Track F, not
    something to slip into an atomicity fix.
    """
    lst = _seed_listing(db)

    def _boom(*a, **kw):
        raise RuntimeError("EscrowDeploymentError: RPC unreachable")

    monkeypatch.setattr(EscrowService, "build_escrow", _boom)

    out = listing.purchase_listing(lst.listing_id, "did:buyer", db_path=db)
    assert out["escrow_id"] == ""

    purchases = _rows(db, "marketplace_purchases")
    assert len(purchases) == 1 and purchases[0]["escrow_id"] == ""
    assert _rows(db, "marketplace_escrow") == []


def test_contract_is_deployed_outside_the_transaction(db, monkeypatch):
    """Holding a write transaction across a network round-trip would block every
    other writer for its duration — and `build_escrow` is exactly that."""
    seen: list[bool] = []
    real_build = EscrowService.build_escrow

    def _tracking(self, **kw):
        # A second connection can still write while the contract "deploys",
        # which is only true if no transaction is open yet.
        with listing._conn(db) as con:
            con.execute(
                "INSERT INTO marketplace_purchases (purchase_id, listing_id, asset_id,"
                " buyer_agent, seller_agent, price_paid, status, escrow_id, negotiation_id,"
                " purchased_at, completed_at) VALUES ('PROBE','l','a','b','s',0,'x','', '','',NULL)"
            )
            seen.append(True)
        return real_build(self, **kw)

    monkeypatch.setattr(EscrowService, "build_escrow", _tracking)

    lst = _seed_listing(db)
    listing.purchase_listing(lst.listing_id, "did:buyer", db_path=db)
    assert seen == [True], "another writer was blocked during contract deployment"


# ── Idempotency still holds on top of the new boundary ────────────────────────

def test_idempotent_replay_creates_nothing_new(db):
    lst = _seed_listing(db)
    first = listing.purchase_listing(lst.listing_id, "did:buyer", db_path=db, idempotency_key="k1")
    again = listing.purchase_listing(lst.listing_id, "did:buyer", db_path=db, idempotency_key="k1")

    assert again["replayed"] is True
    assert again["purchase_id"] == first["purchase_id"]
    assert again["escrow_id"] == first["escrow_id"]
    assert len(_rows(db, "marketplace_purchases")) == 1
    assert len(_rows(db, "marketplace_escrow")) == 1


def test_do_purchase_opens_exactly_one_connection(db, monkeypatch):
    """Structural guard, independent of the API shape.

    The defect was three separately-committed statements; the fix is one
    transaction. Counting connection opens catches a future re-split even if
    someone changes how the writes are expressed.
    """
    lst = _seed_listing(db)

    real_conn = listing._conn
    opens: list[int] = []

    def _counting(db_path=None):
        opens.append(1)
        return real_conn(db_path)

    monkeypatch.setattr(listing, "_conn", _counting)
    listing.purchase_listing(lst.listing_id, "did:buyer", db_path=db)

    # One for the listing lookup, one for the purchase+escrow transaction.
    assert sum(opens) == 2, (
        f"_do_purchase opened {sum(opens)} connections; the purchase and its "
        "escrow must share exactly one transaction"
    )


def test_create_escrow_standalone_still_works(db):
    """The public API is unchanged for callers that are not inside a purchase."""
    esc = EscrowService().create_escrow(
        listing_id="l1", buyer_agent_id="did:b", seller_agent_id="did:s",
        amount_usd=5.0, db_path=db,
    )
    assert esc.escrow_id
    rows = _rows(db, "marketplace_escrow")
    assert len(rows) == 1 and rows[0]["escrow_id"] == esc.escrow_id
