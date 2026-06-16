"""
warden/tests/test_api_escrow.py
────────────────────────────────
5 tests for api_escrow.py — create, full lifecycle, status guards,
dispute resolution, and timeout cancellation.

Mirrors: warden/marketplace/api_escrow.py
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
import uuid
from datetime import UTC, datetime, timedelta

import pytest

_TMP    = tempfile.gettempdir()
_DB     = os.path.join(_TMP, f"test_api_escrow_{uuid.uuid4().hex}.db")
_CMRCDB = os.path.join(_TMP, f"test_commerce_escrow_{uuid.uuid4().hex}.db")
_SEPDB  = os.path.join(_TMP, f"test_sep_escrow_{uuid.uuid4().hex}.db")

os.environ.setdefault("MARKETPLACE_DB_PATH", _DB)
os.environ.setdefault("COMMERCE_DB_PATH",    _CMRCDB)
os.environ.setdefault("SEP_DB_PATH",         _SEPDB)


def _tid() -> str:
    return f"t-{uuid.uuid4().hex[:8]}"

def _cid() -> str:
    return f"c-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def keypair_a():
    from warden.communities.keypair import generate_community_keypair
    return generate_community_keypair(f"esc-a-{uuid.uuid4().hex[:6]}", kid="v1")


@pytest.fixture(scope="module")
def keypair_b():
    from warden.communities.keypair import generate_community_keypair
    return generate_community_keypair(f"esc-b-{uuid.uuid4().hex[:6]}", kid="v1")


@pytest.fixture(scope="module")
def seller_id(keypair_a) -> str:
    from warden.marketplace.agent import register_agent
    agent = register_agent(
        tenant_id=_tid(), community_id=_cid(),
        public_key_b64=keypair_a.ed25519_pub_b64,
        capabilities=["marketplace_sell"],
        db_path=_DB,
    )
    return agent.agent_id


@pytest.fixture(scope="module")
def buyer_id(keypair_b) -> str:
    from warden.marketplace.agent import register_agent
    agent = register_agent(
        tenant_id=_tid(), community_id=_cid(),
        public_key_b64=keypair_b.ed25519_pub_b64,
        capabilities=["marketplace_buy"],
        db_path=_DB,
    )
    return agent.agent_id


# ─────────────────────────────────────────────────────────────────────────────
# 1. Create returns simulated contract address
# ─────────────────────────────────────────────────────────────────────────────

def test_escrow_create(seller_id, buyer_id):
    from warden.marketplace.escrow import EscrowService
    escrow = EscrowService().create_escrow(
        listing_id="LST-TEST01", buyer_agent_id=buyer_id,
        seller_agent_id=seller_id, amount_usd=10.0, db_path=_DB,
    )
    assert escrow.escrow_id.startswith("ESC-")
    assert escrow.status == "pending_deposit"
    addr_part = escrow.contract_address.split(":")[0]
    assert addr_part.startswith("0x")
    assert len(addr_part) == 42


# ─────────────────────────────────────────────────────────────────────────────
# 2. Full lifecycle: fund → deliver → confirm
# ─────────────────────────────────────────────────────────────────────────────

def test_escrow_full_lifecycle(seller_id, buyer_id):
    import hashlib

    from warden.marketplace.escrow import EscrowService
    svc    = EscrowService()
    escrow = svc.create_escrow(
        listing_id="LST-FULL01", buyer_agent_id=buyer_id,
        seller_agent_id=seller_id, amount_usd=15.0, db_path=_DB,
    )
    assert svc.fund_escrow(escrow.escrow_id, db_path=_DB) is True
    assert svc.get_escrow(escrow.escrow_id, db_path=_DB).status == "funded"

    asset_hash = "0x" + hashlib.sha256(b"test_asset_payload").hexdigest()
    assert svc.deliver_asset(escrow.escrow_id, asset_hash, db_path=_DB) is True

    delivered = svc.get_escrow(escrow.escrow_id, db_path=_DB)
    assert delivered.status == "delivered"
    assert delivered.asset_hash == asset_hash

    assert svc.confirm_receipt(escrow.escrow_id, db_path=_DB) is True
    assert svc.get_escrow(escrow.escrow_id, db_path=_DB).status == "confirmed"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Status guards prevent out-of-order transitions
# ─────────────────────────────────────────────────────────────────────────────

def test_escrow_status_guards(seller_id, buyer_id):
    from warden.marketplace.escrow import EscrowService
    svc    = EscrowService()
    escrow = svc.create_escrow(
        listing_id="LST-GUARD01", buyer_agent_id=buyer_id,
        seller_agent_id=seller_id, amount_usd=5.0, db_path=_DB,
    )
    assert svc.deliver_asset(escrow.escrow_id, "0xabcd", db_path=_DB) is False
    assert svc.confirm_receipt(escrow.escrow_id, db_path=_DB) is False


# ─────────────────────────────────────────────────────────────────────────────
# 4. Dispute raised and resolved by arbitrator
# ─────────────────────────────────────────────────────────────────────────────

def test_escrow_dispute_and_resolution(seller_id, buyer_id):
    from warden.marketplace.escrow import EscrowService
    svc    = EscrowService()
    escrow = svc.create_escrow(
        listing_id="LST-DISP01", buyer_agent_id=buyer_id,
        seller_agent_id=seller_id, amount_usd=20.0, db_path=_DB,
    )
    svc.fund_escrow(escrow.escrow_id, db_path=_DB)
    svc.raise_dispute(escrow.escrow_id, "Asset hash mismatch", db_path=_DB)

    disputed = svc.get_escrow(escrow.escrow_id, db_path=_DB)
    assert disputed.status == "disputed"
    assert "mismatch" in disputed.dispute_reason

    svc.resolve_dispute(escrow.escrow_id, release_to_buyer=True, db_path=_DB)
    assert svc.get_escrow(escrow.escrow_id, db_path=_DB).status == "resolved_buyer"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Cancel after timeout refunds buyer
# ─────────────────────────────────────────────────────────────────────────────

def test_escrow_cancel_after_timeout(seller_id, buyer_id):
    from warden.marketplace.escrow import EscrowService
    svc    = EscrowService()
    escrow = svc.create_escrow(
        listing_id="LST-TMOUT01", buyer_agent_id=buyer_id,
        seller_agent_id=seller_id, amount_usd=8.0, db_path=_DB,
    )
    svc.fund_escrow(escrow.escrow_id, db_path=_DB)

    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    con  = sqlite3.connect(_DB)
    con.execute(
        "UPDATE marketplace_escrow SET expires_at=? WHERE escrow_id=?",
        (past, escrow.escrow_id),
    )
    con.commit()
    con.close()

    assert svc.cancel_escrow(escrow.escrow_id, db_path=_DB) is True
    assert svc.get_escrow(escrow.escrow_id, db_path=_DB).status == "cancelled"
