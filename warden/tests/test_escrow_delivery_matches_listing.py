"""
A delivery must be the content that was listed.

`deliver_asset` recorded whatever hash the seller sent and moved the escrow to
"delivered", so a seller could list one asset and deliver another — or a hash
of nothing — and the buyer's confirmation was the only check. Now, when the
listing names an asset, the delivered hash must equal the SHA-256 of that
asset's stored content.
"""
from __future__ import annotations

import hashlib
import sqlite3

import pytest

from warden.marketplace.escrow import EscrowService, expected_asset_hash

_CONTENT = '{"ueciid": "SEP-00000000001", "rules": ["deny x"]}'
_GOOD = hashlib.sha256(_CONTENT.encode()).hexdigest()


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "marketplace.db")
    monkeypatch.setenv("MARKETPLACE_DB_PATH", path)
    monkeypatch.delenv("SEPOLIA_RPC_URL", raising=False)
    return path


def _seed(db: str, listing_id: str, asset_id: str, with_asset: bool = True) -> None:
    # Create the tables through the real modules, then write rows directly.
    from warden.marketplace import listing, service  # noqa: F401
    EscrowService().get_escrow("none", db)  # applies the registered DDL
    con = sqlite3.connect(db)
    if with_asset:
        con.execute(
            "INSERT INTO marketplace_assets (asset_id, asset_type, token_data, ipfs_hash,"
            " seller_agent_id, community_id, tenant_id, created_at)"
            " VALUES (?, 'rule', ?, '', 'did:seller', 'c1', 't1', '2026-10-31')",
            (asset_id, _CONTENT),
        )
    cols = {r[1] for r in con.execute("PRAGMA table_info(marketplace_listings)")}
    row = {
        "listing_id": listing_id, "asset_id": asset_id, "seller_agent": "did:seller",
        "community_id": "c1", "tenant_id": "t1", "asset_type": "rule",
        "price_usd": 1.0, "status": "active", "listed_at": "2026-10-31",
    }
    row = {k: v for k, v in row.items() if k in cols}
    con.execute(
        f"INSERT INTO marketplace_listings ({','.join(row)}) VALUES ({','.join('?' * len(row))})",
        tuple(row.values()),
    )
    con.commit()
    con.close()


def _funded(svc: EscrowService, db: str, listing_id: str):
    esc = svc.create_escrow(
        listing_id=listing_id, buyer_agent_id="did:buyer", seller_agent_id="did:seller",
        amount_usd=1.0, purchase_id="PUR-1", db_path=db,
    )
    assert svc.fund_escrow(esc.escrow_id, db) is True
    return esc


def test_expected_hash_is_sha256_of_the_listed_content(db):
    _seed(db, "LST-A", "SEP-00000000001")
    assert expected_asset_hash("LST-A", db) == _GOOD


def test_a_different_hash_is_refused_and_the_escrow_stays_funded(db):
    _seed(db, "LST-A", "SEP-00000000001")
    svc = EscrowService()
    esc = _funded(svc, db, "LST-A")
    assert svc.deliver_asset(esc.escrow_id, "0x" + "00" * 32, db) is False
    assert svc.get_escrow(esc.escrow_id, db).status == "funded"


@pytest.mark.parametrize("form", [_GOOD, "0x" + _GOOD, "sha256:" + _GOOD, "0x" + _GOOD.upper()])
def test_the_listed_hash_is_accepted_in_any_common_spelling(db, form):
    _seed(db, "LST-A", "SEP-00000000001")
    svc = EscrowService()
    esc = _funded(svc, db, "LST-A")
    assert svc.deliver_asset(esc.escrow_id, form, db) is True
    assert svc.get_escrow(esc.escrow_id, db).status == "delivered"


def test_a_listing_whose_asset_is_not_registered_binds_no_content(db):
    _seed(db, "LST-S", "SEP-unregistered", with_asset=False)
    assert expected_asset_hash("LST-S", db) is None
    svc = EscrowService()
    esc = _funded(svc, db, "LST-S")
    assert svc.deliver_asset(esc.escrow_id, "sha256:anything", db) is True


# ── A listing must name the seller's own registered asset ─────────────────────

def _listings_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.marketplace import api_listings
    app = FastAPI()
    app.include_router(api_listings.router, prefix="/marketplace")
    return TestClient(app)


def _listing_body(asset_id: str, seller: str) -> dict:
    return {
        "asset_id": asset_id, "seller_agent_id": seller, "community_id": "c1",
        "tenant_id": "t1", "asset_type": "rule", "price_usd": 1.0,
    }


def _register_only_asset(db: str, asset_id: str, seller: str) -> None:
    EscrowService().get_escrow("none", db)
    con = sqlite3.connect(db)
    con.execute(
        "INSERT INTO marketplace_assets (asset_id, asset_type, token_data, ipfs_hash,"
        " seller_agent_id, community_id, tenant_id, created_at)"
        " VALUES (?, 'rule', ?, '', ?, 'c1', 't1', '2026-10-31')",
        (asset_id, _CONTENT, seller),
    )
    con.commit()
    con.close()


def test_listing_an_unregistered_asset_is_refused(db):
    resp = _listings_client().post(
        "/marketplace/listings", json=_listing_body("SEP-NOSUCHASSET", "did:seller")
    )
    assert resp.status_code == 404, resp.text


def test_listing_another_sellers_asset_is_refused(db):
    _register_only_asset(db, "SEP-00000000009", "did:owner")
    resp = _listings_client().post(
        "/marketplace/listings", json=_listing_body("SEP-00000000009", "did:thief")
    )
    assert resp.status_code == 403, resp.text


def test_listing_your_own_asset_is_accepted(db):
    _register_only_asset(db, "SEP-00000000008", "did:owner")
    resp = _listings_client().post(
        "/marketplace/listings", json=_listing_body("SEP-00000000008", "did:owner")
    )
    assert resp.status_code == 201, resp.text
