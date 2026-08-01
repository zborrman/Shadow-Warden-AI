"""
warden/tests/test_marketplace_offer_signing.py — MP-1b.

Marketplace rule #1 always claimed "every offer must be Ed25519-signed". Until
MP-1b it was not true: ``_verify_offer_signature()`` existed but was called from
nowhere, ``send_offer``/``accept_offer`` defaulted ``keypair=None``, the HTTP
routes never passed one, and every stored signature was ``''``. Combined with an
unauthenticated router that meant a $1000 listing could be settled at $0.01 by
impersonating the seller on accept.

These tests pin the actor proof: a signature over the canonical envelope,
verified against the pubkey the DID is derived from.
"""
from __future__ import annotations

import base64
import os
from datetime import UTC, datetime, timedelta

import pytest


def _keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, base64.b64encode(raw).decode()


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Two registered agents on an isolated DB, plus an open negotiation."""
    db = str(tmp_path / "mkt.db")
    monkeypatch.setenv("MARKETPLACE_DB_PATH", db)
    monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "false")

    from warden.marketplace.agent import pubkey_to_agent_id, register_agent
    from warden.marketplace.listing import publish_listing
    from warden.marketplace.negotiation import NegotiationEngine

    buyer_priv, buyer_pub = _keypair()
    seller_priv, seller_pub = _keypair()
    buyer_id = pubkey_to_agent_id(buyer_pub)
    seller_id = pubkey_to_agent_id(seller_pub)

    for pub, tenant in ((buyer_pub, "t-buyer"), (seller_pub, "t-seller")):
        register_agent(community_id="C1", tenant_id=tenant, public_key_b64=pub,
                       capabilities=["marketplace_buy", "marketplace_sell",
                                     "marketplace_negotiate"], db_path=db)

    listing = publish_listing(
        asset_id="SEP-AAAAAAAAAAA", seller_agent=seller_id, community_id="C1",
        tenant_id="t-seller", asset_type="compute", price_usd=1000.0, db_path=db,
    )
    neg = NegotiationEngine().start_negotiation(
        buyer_agent_id=buyer_id, seller_agent_id=seller_id,
        listing_id=listing.listing_id, initial_price=1000.0,
        asset_ueciid=listing.asset_id, db_path=db,
    )
    return {
        "db": db, "neg": neg, "listing": listing,
        "buyer_priv": buyer_priv, "buyer_id": buyer_id,
        "seller_priv": seller_priv, "seller_id": seller_id,
    }


def _sign(priv, *, offer_type, price, asset_ueciid, round_, agent_id, timestamp, negotiation_id):
    from warden.marketplace.negotiation import build_offer_canonical
    canonical = build_offer_canonical(
        offer_type=offer_type, price=price, asset_ueciid=asset_ueciid, round_=round_,
        agent_id=agent_id, timestamp=timestamp, negotiation_id=negotiation_id,
    )
    return base64.b64encode(priv.sign(canonical)).decode()


class TestActorProof:
    def test_agent_id_is_derived_from_pubkey(self):
        """The whole scheme rests on this: the DID *is* a key fingerprint."""
        from warden.marketplace.agent import pubkey_to_agent_id
        _, pub = _keypair()
        assert pubkey_to_agent_id(pub) == pubkey_to_agent_id(pub)
        _, other = _keypair()
        assert pubkey_to_agent_id(pub) != pubkey_to_agent_id(other)

    def test_non_party_agent_is_rejected_even_unenforced(self, env, monkeypatch):
        """A stranger must never move someone else's negotiation, signed or not."""
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "false")
        from warden.marketplace.negotiation import NegotiationEngine, OfferSignatureError
        with pytest.raises(OfferSignatureError, match="not a party"):
            NegotiationEngine().send_offer(
                negotiation_id=env["neg"].negotiation_id,
                from_agent_id="did:shadow:STRANGER", price=1.0, db_path=env["db"],
            )

    def test_valid_signature_is_accepted(self, env, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        from warden.marketplace.negotiation import NegotiationEngine
        ts = datetime.now(UTC).isoformat()
        sig = _sign(env["buyer_priv"], offer_type="offer", price=900.0,
                    asset_ueciid=env["listing"].asset_id, round_=1,
                    agent_id=env["buyer_id"], timestamp=ts,
                    negotiation_id=env["neg"].negotiation_id)
        offer = NegotiationEngine().send_offer(
            negotiation_id=env["neg"].negotiation_id, from_agent_id=env["buyer_id"],
            price=900.0, db_path=env["db"], signature=sig, timestamp=ts,
        )
        assert offer.signature == sig

    def test_the_original_exploit_is_closed(self, env, monkeypatch):
        """Attacker offers $0.01 then accepts *as the seller*. Enforcement must stop it."""
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        from warden.marketplace.negotiation import NegotiationEngine, OfferSignatureError
        eng = NegotiationEngine()
        ts = datetime.now(UTC).isoformat()
        sig = _sign(env["buyer_priv"], offer_type="offer", price=0.01,
                    asset_ueciid=env["listing"].asset_id, round_=1,
                    agent_id=env["buyer_id"], timestamp=ts,
                    negotiation_id=env["neg"].negotiation_id)
        eng.send_offer(negotiation_id=env["neg"].negotiation_id,
                       from_agent_id=env["buyer_id"], price=0.01,
                       db_path=env["db"], signature=sig, timestamp=ts)
        # The buyer cannot accept as the seller: it holds no seller key.
        with pytest.raises(OfferSignatureError):
            eng.accept_offer(negotiation_id=env["neg"].negotiation_id,
                             from_agent_id=env["seller_id"], db_path=env["db"],
                             signature=sig, timestamp=ts)
        status = eng.get_negotiation_status(env["neg"].negotiation_id, db_path=env["db"])
        assert status["status"] == "open", "negotiation must not have settled"

    def test_signature_from_wrong_key_is_rejected(self, env, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        from warden.marketplace.negotiation import NegotiationEngine, OfferSignatureError
        ts = datetime.now(UTC).isoformat()
        # Seller's key, but claiming to be the buyer.
        sig = _sign(env["seller_priv"], offer_type="offer", price=900.0,
                    asset_ueciid=env["listing"].asset_id, round_=1,
                    agent_id=env["buyer_id"], timestamp=ts,
                    negotiation_id=env["neg"].negotiation_id)
        with pytest.raises(OfferSignatureError, match="does not verify"):
            NegotiationEngine().send_offer(
                negotiation_id=env["neg"].negotiation_id, from_agent_id=env["buyer_id"],
                price=900.0, db_path=env["db"], signature=sig, timestamp=ts,
            )

    def test_signature_bound_to_price(self, env, monkeypatch):
        """Sign $900, submit $1 — the envelope covers price, so it must not verify."""
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        from warden.marketplace.negotiation import NegotiationEngine, OfferSignatureError
        ts = datetime.now(UTC).isoformat()
        sig = _sign(env["buyer_priv"], offer_type="offer", price=900.0,
                    asset_ueciid=env["listing"].asset_id, round_=1,
                    agent_id=env["buyer_id"], timestamp=ts,
                    negotiation_id=env["neg"].negotiation_id)
        with pytest.raises(OfferSignatureError):
            NegotiationEngine().send_offer(
                negotiation_id=env["neg"].negotiation_id, from_agent_id=env["buyer_id"],
                price=1.0, db_path=env["db"], signature=sig, timestamp=ts,
            )

    def test_signature_is_bound_to_its_negotiation(self, env, monkeypatch):
        """MP-1b added negotiation_id precisely so a signature is not portable."""
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        from warden.marketplace.listing import publish_listing
        from warden.marketplace.negotiation import NegotiationEngine, OfferSignatureError
        other_listing = publish_listing(
            asset_id=env["listing"].asset_id, seller_agent=env["seller_id"],
            community_id="C1", tenant_id="t-seller", asset_type="compute",
            price_usd=1000.0, db_path=env["db"],
        )
        other = NegotiationEngine().start_negotiation(
            buyer_agent_id=env["buyer_id"], seller_agent_id=env["seller_id"],
            listing_id=other_listing.listing_id, initial_price=1000.0,
            asset_ueciid=other_listing.asset_id, db_path=env["db"],
        )
        ts = datetime.now(UTC).isoformat()
        sig = _sign(env["buyer_priv"], offer_type="offer", price=900.0,
                    asset_ueciid=env["listing"].asset_id, round_=1,
                    agent_id=env["buyer_id"], timestamp=ts,
                    negotiation_id=env["neg"].negotiation_id)
        with pytest.raises(OfferSignatureError):
            NegotiationEngine().send_offer(
                negotiation_id=other.negotiation_id, from_agent_id=env["buyer_id"],
                price=900.0, db_path=env["db"], signature=sig, timestamp=ts,
            )

    def test_stale_timestamp_is_rejected(self, env, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        monkeypatch.setenv("MARKETPLACE_OFFER_MAX_SKEW_S", "300")
        from warden.marketplace.negotiation import NegotiationEngine, OfferSignatureError
        ts = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
        sig = _sign(env["buyer_priv"], offer_type="offer", price=900.0,
                    asset_ueciid=env["listing"].asset_id, round_=1,
                    agent_id=env["buyer_id"], timestamp=ts,
                    negotiation_id=env["neg"].negotiation_id)
        with pytest.raises(OfferSignatureError, match="acceptance window"):
            NegotiationEngine().send_offer(
                negotiation_id=env["neg"].negotiation_id, from_agent_id=env["buyer_id"],
                price=900.0, db_path=env["db"], signature=sig, timestamp=ts,
            )

    def test_unknown_agent_denies_under_enforcement(self, env, monkeypatch, tmp_path):
        """Fail-CLOSED: an unresolvable key denies, it does not wave the offer through."""
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        from warden.marketplace.agent import pubkey_to_agent_id
        from warden.marketplace.negotiation import NegotiationEngine, OfferSignatureError
        ghost_priv, ghost_pub = _keypair()
        ghost_id = pubkey_to_agent_id(ghost_pub)
        neg = NegotiationEngine().start_negotiation(
            buyer_agent_id=ghost_id, seller_agent_id=env["seller_id"],
            listing_id=env["listing"].listing_id, initial_price=1000.0,
            asset_ueciid=env["listing"].asset_id, db_path=env["db"],
        )
        ts = datetime.now(UTC).isoformat()
        sig = _sign(ghost_priv, offer_type="offer", price=900.0,
                    asset_ueciid=env["listing"].asset_id, round_=1,
                    agent_id=ghost_id, timestamp=ts,
                    negotiation_id=neg.negotiation_id)
        with pytest.raises(OfferSignatureError):
            NegotiationEngine().send_offer(
                negotiation_id=neg.negotiation_id, from_agent_id=ghost_id,
                price=900.0, db_path=env["db"], signature=sig, timestamp=ts,
            )


class TestBakePeriod:
    def test_unsigned_offer_still_works_when_not_enforced(self, env, monkeypatch):
        """The migration contract: shipping this must not break live unsigned clients."""
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "false")
        from warden.marketplace.negotiation import NegotiationEngine
        offer = NegotiationEngine().send_offer(
            negotiation_id=env["neg"].negotiation_id, from_agent_id=env["buyer_id"],
            price=900.0, db_path=env["db"],
        )
        assert offer.price == 900.0
        assert offer.signature == ""

    def test_unsigned_offer_is_rejected_when_enforced(self, env, monkeypatch):
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        from warden.marketplace.negotiation import NegotiationEngine, OfferSignatureError
        with pytest.raises(OfferSignatureError, match="must carry an Ed25519 signature"):
            NegotiationEngine().send_offer(
                negotiation_id=env["neg"].negotiation_id, from_agent_id=env["buyer_id"],
                price=900.0, db_path=env["db"],
            )

    def test_flag_is_read_fresh_not_snapshotted(self, monkeypatch):
        from warden.marketplace.negotiation import signed_offers_required
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        assert signed_offers_required() is True
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "false")
        assert signed_offers_required() is False

    def test_flag_defaults_off(self, monkeypatch):
        monkeypatch.delenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", raising=False)
        from warden.marketplace.negotiation import signed_offers_required
        assert signed_offers_required() is False

    def test_bad_signature_unenforced_does_not_raise(self, env, monkeypatch):
        """Unenforced, a bad signature is counted, not fatal — that is the bake period."""
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "false")
        from warden.marketplace.negotiation import NegotiationEngine
        offer = NegotiationEngine().send_offer(
            negotiation_id=env["neg"].negotiation_id, from_agent_id=env["buyer_id"],
            price=900.0, db_path=env["db"], signature="bm90LWEtc2ln",
            timestamp=datetime.now(UTC).isoformat(),
        )
        assert offer.price == 900.0


class TestHttpSurface:
    def test_offer_signature_failure_is_http_400(self, env, monkeypatch):
        """Rule #1 always specified 400 for an unsigned/invalid offer."""
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        monkeypatch.setenv("MARKETPLACE_DB_PATH", env["db"])
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from warden.marketplace import api_negotiations
        app = FastAPI()
        app.include_router(api_negotiations.router, prefix="/marketplace")
        client = TestClient(app)
        resp = client.post(
            f"/marketplace/negotiations/{env['neg'].negotiation_id}/accept",
            json={"from_agent_id": env["seller_id"], "price": 0.01},
        )
        assert resp.status_code == 400

    def test_offer_request_accepts_signature_fields(self):
        from warden.marketplace.api_negotiations import OfferRequest
        req = OfferRequest(from_agent_id="a", price=1.0, signature="s", timestamp="t")
        assert req.signature == "s" and req.timestamp == "t"

    def test_signature_fields_are_optional(self):
        """Schema stays permissive; the env flag decides, so the bake period works."""
        from warden.marketplace.api_negotiations import OfferRequest
        assert OfferRequest(from_agent_id="a", price=1.0).signature == ""


class TestCanonicalEnvelope:
    def test_envelope_is_deterministic(self):
        from warden.marketplace.negotiation import build_offer_canonical
        kw = {"offer_type": "offer", "price": 1.5, "asset_ueciid": "SEP-X", "round_": 2,
              "agent_id": "did:shadow:A", "timestamp": "2026-01-01T00:00:00+00:00",
              "negotiation_id": "NEG-1"}
        assert build_offer_canonical(**kw) == build_offer_canonical(**kw)

    def test_envelope_includes_negotiation_id(self):
        from warden.marketplace.negotiation import build_offer_canonical
        kw = {"offer_type": "offer", "price": 1.5, "asset_ueciid": "SEP-X", "round_": 2,
              "agent_id": "did:shadow:A", "timestamp": "2026-01-01T00:00:00+00:00"}
        assert build_offer_canonical(**kw, negotiation_id="NEG-1") != \
               build_offer_canonical(**kw, negotiation_id="NEG-2")

    def test_verify_rejects_empty_inputs(self):
        from warden.marketplace.negotiation import _verify_offer_signature
        assert _verify_offer_signature(b"x", "", "pub") is False
        assert _verify_offer_signature(b"x", "sig", "") is False


def test_skew_window_is_configurable(monkeypatch):
    from warden.marketplace.negotiation import _timestamp_within_skew
    monkeypatch.setenv("MARKETPLACE_OFFER_MAX_SKEW_S", "60")
    assert _timestamp_within_skew(datetime.now(UTC).isoformat()) is True
    assert _timestamp_within_skew((datetime.now(UTC) - timedelta(seconds=600)).isoformat()) is False


def test_skew_rejects_unparseable_timestamp():
    from warden.marketplace.negotiation import _timestamp_within_skew
    assert _timestamp_within_skew("not-a-date") is False
    assert _timestamp_within_skew("") is False


def test_malformed_skew_env_falls_back(monkeypatch):
    from warden.marketplace.negotiation import _max_skew_seconds
    monkeypatch.setenv("MARKETPLACE_OFFER_MAX_SKEW_S", "not-an-int")
    assert _max_skew_seconds() == 300
    assert os.environ["MARKETPLACE_OFFER_MAX_SKEW_S"] == "not-an-int"
