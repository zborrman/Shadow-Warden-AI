"""
warden/tests/test_escrow_state_machine.py — the escrow money transitions.

Escrow is where buyer funds sit between purchase and delivery, so the state
machine *is* the money logic: fund → deliver → confirm releases to the seller,
dispute → resolve sends it one way or the other, and cancel refunds after
timeout. Before this file those transitions were largely uncovered (61%), which
is the wrong posture for code any storage migration would rewrite underneath.

What is pinned here is the **guard on every transition** — each one must reject
an escrow in the wrong state rather than move funds twice. An out-of-order call
that returned True would double-release.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from warden.marketplace.escrow import EscrowService


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "marketplace.db")
    monkeypatch.setenv("MARKETPLACE_DB_PATH", path)
    monkeypatch.delenv("SEPOLIA_RPC_URL", raising=False)
    return path


@pytest.fixture
def svc():
    return EscrowService()


def _new(svc, db, amount=10.0):
    return svc.create_escrow(
        listing_id="LST-1", buyer_agent_id="did:buyer", seller_agent_id="did:seller",
        amount_usd=amount, purchase_id="PUR-1", db_path=db,
    )


# ── The happy path, transition by transition ──────────────────────────────────

def test_full_lifecycle_to_confirmed(svc, db):
    esc = _new(svc, db)
    assert svc.get_escrow(esc.escrow_id, db).status == "pending_deposit"

    assert svc.fund_escrow(esc.escrow_id, db) is True
    assert svc.get_escrow(esc.escrow_id, db).status == "funded"

    assert svc.deliver_asset(esc.escrow_id, "sha256:abc", db) is True
    got = svc.get_escrow(esc.escrow_id, db)
    assert got.status == "delivered" and got.asset_hash == "sha256:abc"

    assert svc.confirm_receipt(esc.escrow_id, db_path=db) is True
    assert svc.get_escrow(esc.escrow_id, db).status == "confirmed"


# ── Every transition rejects the wrong starting state ─────────────────────────

def test_fund_only_from_pending_deposit(svc, db):
    esc = _new(svc, db)
    assert svc.fund_escrow(esc.escrow_id, db) is True
    # A replayed deposit must not fund twice.
    assert svc.fund_escrow(esc.escrow_id, db) is False


def test_deliver_requires_funded(svc, db):
    esc = _new(svc, db)
    assert svc.deliver_asset(esc.escrow_id, "h", db) is False, "delivered before funding"
    svc.fund_escrow(esc.escrow_id, db)
    assert svc.deliver_asset(esc.escrow_id, "h", db) is True
    assert svc.deliver_asset(esc.escrow_id, "h2", db) is False, "delivered twice"


def test_confirm_requires_delivered(svc, db):
    """Confirming releases funds to the seller — it must never fire early."""
    esc = _new(svc, db)
    assert svc.confirm_receipt(esc.escrow_id, db_path=db) is False
    svc.fund_escrow(esc.escrow_id, db)
    assert svc.confirm_receipt(esc.escrow_id, db_path=db) is False, "released before delivery"
    svc.deliver_asset(esc.escrow_id, "h", db)
    assert svc.confirm_receipt(esc.escrow_id, db_path=db) is True
    assert svc.confirm_receipt(esc.escrow_id, db_path=db) is False, "released twice"


def test_unknown_escrow_is_rejected_by_every_transition(svc, db):
    assert svc.fund_escrow("ESC-NOPE", db) is False
    assert svc.deliver_asset("ESC-NOPE", "h", db) is False
    assert svc.confirm_receipt("ESC-NOPE", db_path=db) is False
    assert svc.raise_dispute("ESC-NOPE", "r", db) is False
    assert svc.resolve_dispute("ESC-NOPE", True, db_path=db) is False
    assert svc.cancel_escrow("ESC-NOPE", db) is False
    assert svc.get_escrow("ESC-NOPE", db) is None


# ── Dispute path ──────────────────────────────────────────────────────────────

def test_dispute_allowed_from_funded_and_delivered(svc, db):
    a = _new(svc, db)
    svc.fund_escrow(a.escrow_id, db)
    assert svc.raise_dispute(a.escrow_id, "not as described", db) is True
    got = svc.get_escrow(a.escrow_id, db)
    assert got.status == "disputed" and got.dispute_reason == "not as described"

    b = _new(svc, db)
    svc.fund_escrow(b.escrow_id, db)
    svc.deliver_asset(b.escrow_id, "h", db)
    assert svc.raise_dispute(b.escrow_id, "bad asset", db) is True


def test_dispute_rejected_before_funding(svc, db):
    esc = _new(svc, db)
    assert svc.raise_dispute(esc.escrow_id, "r", db) is False


@pytest.mark.parametrize(
    ("release_to_buyer", "expected"),
    [(True, "resolved_buyer"), (False, "resolved_seller")],
)
def test_resolution_sends_funds_one_way(svc, db, release_to_buyer, expected):
    esc = _new(svc, db)
    svc.fund_escrow(esc.escrow_id, db)
    svc.raise_dispute(esc.escrow_id, "r", db)

    assert svc.resolve_dispute(esc.escrow_id, release_to_buyer, db_path=db) is True
    assert svc.get_escrow(esc.escrow_id, db).status == expected
    # Resolving twice would move the same funds again.
    assert svc.resolve_dispute(esc.escrow_id, release_to_buyer, db_path=db) is False


def test_resolve_requires_a_dispute(svc, db):
    esc = _new(svc, db)
    svc.fund_escrow(esc.escrow_id, db)
    assert svc.resolve_dispute(esc.escrow_id, True, db_path=db) is False


# ── Cancellation refunds only after the timeout ───────────────────────────────

def test_cancel_refuses_before_expiry(svc, db):
    esc = _new(svc, db)
    assert svc.cancel_escrow(esc.escrow_id, db) is False, "refunded before the timeout"


def test_cancel_after_expiry_refunds(svc, db):
    from warden.marketplace import escrow as escrow_mod

    esc = _new(svc, db)
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    with escrow_mod._conn(db) as con:
        con.execute(
            "UPDATE marketplace_escrow SET expires_at=? WHERE escrow_id=?",
            (past, esc.escrow_id),
        )

    assert svc.cancel_escrow(esc.escrow_id, db) is True
    assert svc.get_escrow(esc.escrow_id, db).status == "cancelled"


def test_cancel_refuses_once_delivered(svc, db):
    """Past delivery the seller has performed; a timeout refund would take back
    funds for work already done."""
    from warden.marketplace import escrow as escrow_mod

    esc = _new(svc, db)
    svc.fund_escrow(esc.escrow_id, db)
    svc.deliver_asset(esc.escrow_id, "h", db)
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    with escrow_mod._conn(db) as con:
        con.execute(
            "UPDATE marketplace_escrow SET expires_at=? WHERE escrow_id=?",
            (past, esc.escrow_id),
        )
    assert svc.cancel_escrow(esc.escrow_id, db) is False


# ── Listing ───────────────────────────────────────────────────────────────────

def test_listing_filters_by_agent_role_and_status(svc, db):
    a = _new(svc, db)
    b = _new(svc, db)
    svc.fund_escrow(b.escrow_id, db)

    both = svc.list_escrows("did:buyer", db_path=db)
    assert {e.escrow_id for e in both} == {a.escrow_id, b.escrow_id}

    # Role scoping: the same address is buyer on these, never seller.
    assert len(svc.list_escrows("did:buyer", role="buyer", db_path=db)) == 2
    assert svc.list_escrows("did:buyer", role="seller", db_path=db) == []
    assert len(svc.list_escrows("did:seller", role="seller", db_path=db)) == 2

    assert svc.list_escrows("did:nobody", db_path=db) == []
    assert len(svc.list_all_escrows(db_path=db)) == 2
    funded = svc.list_all_escrows(status="funded", db_path=db)
    assert {e.escrow_id for e in funded} == {b.escrow_id}


def test_amount_is_preserved_across_the_lifecycle(svc, db):
    """The held amount must not drift as the escrow changes state."""
    esc = _new(svc, db, amount=1234.56)
    svc.fund_escrow(esc.escrow_id, db)
    svc.deliver_asset(esc.escrow_id, "h", db)
    svc.confirm_receipt(esc.escrow_id, db_path=db)
    assert svc.get_escrow(esc.escrow_id, db).amount_usd == 1234.56
