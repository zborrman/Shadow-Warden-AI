"""Tests for USDC Multi-Rail Payments (MKT-12)."""
from __future__ import annotations

import os
import pytest

os.environ.setdefault("USDC_SIMULATE", "true")

from warden.payments.usdc import USDCService, get_usdc_service, PaymentIntent


class TestUSDCService:

    def setup_method(self):
        os.environ["USDC_SIMULATE"] = "true"
        self.svc = USDCService(chain="polygon")

    def test_singleton_same_chain(self):
        a = get_usdc_service("polygon")
        b = get_usdc_service("polygon")
        assert a is b

    def test_create_intent_returns_id(self):
        intent = self.svc.create_payment_intent(amount_usd=25.0, merchant_wallet="0xABCDEF")
        assert intent.intent_id
        assert intent.amount_usd == 25.0
        assert intent.status == "PENDING"

    def test_get_intent_after_create(self):
        intent = self.svc.create_payment_intent(amount_usd=10.0, merchant_wallet="0x1234")
        fetched = self.svc.get_intent(intent.intent_id)
        assert fetched is not None
        assert fetched.amount_usd == 10.0

    def test_verify_auto_confirms_in_simulation(self):
        intent = self.svc.create_payment_intent(amount_usd=5.0, merchant_wallet="0xDEAD")
        result = self.svc.verify_payment(intent.intent_id)
        assert result["status"] == "CONFIRMED"

    def test_verify_missing_intent_returns_not_found(self):
        result = self.svc.verify_payment("nonexistent-intent-id")
        assert result.get("status") == "NOT_FOUND" or "error" in result

    def test_payment_intent_chain_attribute(self):
        intent = self.svc.create_payment_intent(amount_usd=1.0, merchant_wallet="0x0")
        assert intent.chain == "polygon"

    def test_payment_intent_is_dataclass(self):
        intent = self.svc.create_payment_intent(amount_usd=1.0, merchant_wallet="0x0")
        assert isinstance(intent, PaymentIntent)

    def test_separate_chain_different_singleton(self):
        svc_eth = get_usdc_service("ethereum")
        svc_poly = get_usdc_service("polygon")
        assert svc_eth is not svc_poly
