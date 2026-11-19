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


class TestMacaroonFailsClosed:
    """A token that cannot be verified is not a payment (it used to read as one)."""

    def test_not_base64_is_rejected(self):
        from warden.payments.l402 import verify_macaroon
        ok, claims = verify_macaroon("@@@not-base64@@@", "")
        assert ok is False and claims.get("agent_id") is None

    def test_not_utf8_is_rejected(self):
        import base64

        from warden.payments.l402 import verify_macaroon
        garbage = base64.urlsafe_b64encode(b"\xff\xfe\xfd").decode().rstrip("=")
        assert verify_macaroon(garbage, "")[0] is False

    def test_unresolvable_signing_key_is_rejected(self, monkeypatch):
        import warden.payments.l402 as l402
        tok = l402.issue_macaroon("agent-1", "filter_text", 10)

        def _no_key():
            raise RuntimeError("no key")

        monkeypatch.setattr(l402, "_hmac_key", _no_key)
        assert l402.verify_macaroon(tok, "")[0] is False

    def test_garbage_authorization_header_is_not_paid(self):
        from warden.payments.l402 import parse_authorization_header, verify_macaroon
        mac, pre = parse_authorization_header("L402 %%%%:zz")
        assert verify_macaroon(mac, pre)[0] is False


def _gateway_call(monkeypatch, authorization: str, tool: str) -> list:
    """Drive mcp.gateway._check_payment for a funded x402 agent; return deductions."""
    import asyncio

    from starlette.requests import Request

    import warden.marketplace.credits as credits
    import warden.marketplace.x402_gate as x402
    import warden.mcp.gateway as gw

    deducted: list = []

    async def _deduct(agent_id, resource, price):
        deducted.append((agent_id, resource))

    monkeypatch.setattr(gw, "payment_gate_enabled", lambda: True)
    monkeypatch.setattr(credits, "get_balance", lambda _t: 0)
    monkeypatch.setattr(x402, "_extract_agent_id", lambda _s: "agent-1")
    monkeypatch.setattr(x402, "_has_sufficient_balance", lambda _a: True)
    monkeypatch.setattr(x402, "deduct_payment", _deduct)
    scope = {
        "type": "http", "method": "POST", "path": "/mcp/", "query_string": b"",
        "headers": [(b"authorization", authorization.encode()),
                    (b"payment-signature", b"sig")],
        "client": ("127.0.0.1", 1), "server": ("test", 80), "scheme": "http",
    }
    agent, err = asyncio.run(gw._check_payment(Request(scope), tool))
    assert err is None and agent == "agent-1"
    return deducted


def test_mcp_garbage_l402_does_not_skip_the_x402_charge(monkeypatch):
    # Before: verify_macaroon returned (True, {}) on a parse error, the gateway
    # returned early, and the funded agent's balance was never charged.
    assert _gateway_call(monkeypatch, "L402 @@@not-base64@@@:00", "filter_text")


def test_mcp_macaroon_for_another_tool_does_not_skip_the_charge(monkeypatch):
    from warden.payments.l402 import issue_macaroon
    tok = issue_macaroon("agent-1", "gateway_health", 1)  # cheap tool, no invoice hash
    assert _gateway_call(monkeypatch, f"L402 {tok}:", "filter_text")
