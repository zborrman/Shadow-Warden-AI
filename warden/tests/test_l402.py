"""Tests for L402 Lightning-Native API Access protocol."""
from __future__ import annotations

import hashlib

import pytest


class TestMacaroon:
    def test_issue_and_verify(self):
        from warden.payments.l402 import issue_macaroon, verify_macaroon
        preimage = "a" * 32
        pay_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
        mac = issue_macaroon("did:shadow:abc", "filter", 100, payment_hash=pay_hash)
        ok, claims = verify_macaroon(mac, preimage)
        assert ok
        assert claims["agent_id"] == "did:shadow:abc"
        assert claims["tool_name"] == "filter"
        assert claims["amount_sat"] == 100

    def test_bad_hmac_rejected(self):
        from warden.payments.l402 import issue_macaroon, verify_macaroon
        mac = issue_macaroon("agent", "filter", 10)
        # Tamper
        tampered = mac[:-4] + "XXXX"
        ok, claims = verify_macaroon(tampered, "")
        assert not ok
        assert claims.get("error") in ("bad_hmac", "bad_macaroon_format")

    def test_wrong_preimage_rejected(self):
        from warden.payments.l402 import issue_macaroon, verify_macaroon
        real_preimage = "b" * 32
        wrong_preimage = "c" * 32
        pay_hash = hashlib.sha256(bytes.fromhex(real_preimage)).hexdigest()
        mac = issue_macaroon("agent", "tool", 50, payment_hash=pay_hash)
        ok, claims = verify_macaroon(mac, wrong_preimage)
        assert not ok
        assert claims.get("error") == "preimage_mismatch"

    def test_no_payment_hash_skip_preimage_check(self):
        from warden.payments.l402 import issue_macaroon, verify_macaroon
        mac = issue_macaroon("agent", "tool", 1, payment_hash="")
        ok, _ = verify_macaroon(mac, "any-preimage")
        assert ok

    def test_parse_authorization_header(self):
        from warden.payments.l402 import parse_authorization_header
        mac, pre = parse_authorization_header("L402 mytoken123:mypreimage456")
        assert mac == "mytoken123"
        assert pre == "mypreimage456"

    def test_parse_authorization_header_wrong_scheme(self):
        from warden.payments.l402 import parse_authorization_header
        mac, pre = parse_authorization_header("Bearer sometoken")
        assert mac == "" and pre == ""

    def test_build_www_authenticate(self):
        from warden.payments.l402 import build_www_authenticate
        header = build_www_authenticate("tok123", "lnbc100n1abc")
        assert 'L402 macaroon="tok123"' in header
        assert 'invoice="lnbc100n1abc"' in header


class TestInvoice:
    @pytest.mark.asyncio
    async def test_create_invoice_stub(self, monkeypatch):
        monkeypatch.setenv("L402_DEV_MODE", "true")
        from warden.payments.l402 import create_invoice
        data = await create_invoice(0.001, "test")
        assert "payment_hash" in data
        assert "payment_request" in data
        assert data["_stub"] is True
        assert data["amount_sat"] >= 1

    @pytest.mark.asyncio
    async def test_create_invoice_usd_to_sat(self, monkeypatch):
        monkeypatch.setenv("L402_DEV_MODE", "true")
        monkeypatch.setenv("L402_BTC_PRICE_USD", "50000")
        from warden.payments.l402 import create_invoice
        # $1 at $50k BTC = 2000 sat
        data = await create_invoice(1.0)
        assert data["amount_sat"] == 2000
