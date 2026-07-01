"""Tests for the ACP protocol layer (token vault, cart, checkout, refund)."""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("LOGS_PATH", "/tmp/warden_test_acp_logs.json")
os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/warden_test_acp_dynamic.json")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("MODEL_CACHE_DIR", "/tmp/warden_test_models")
os.environ.setdefault("X402_GATE_ENABLED", "false")


@pytest.fixture(autouse=True)
def _isolate_db(tmp_path):
    os.environ["ACP_DB_PATH"] = str(tmp_path / "acp_test.db")
    os.environ["COMMERCE_DB_PATH"] = str(tmp_path / "commerce_test.db")
    yield


# ────────────────────────────────────────────────────────────────────────────────
# Token Vault
# ────────────────────────────────────────────────────────────────────────────────

class TestSharedPaymentToken:
    def test_issue_token(self):
        from warden.protocols.acp.token_vault import issue_spt
        spt = issue_spt("merchant-1", "agent:did:test", 50.0)
        assert spt.token_id.startswith("acp_spt_")
        assert spt.status == "ACTIVE"
        assert spt.max_amount == 50.0
        assert spt.remaining_uses == 1
        assert len(spt.signature) == 64

    def test_verify_valid_token(self):
        from warden.protocols.acp.token_vault import issue_spt, verify_spt
        spt = issue_spt("merchant-1", "agent:did:test", 100.0)
        result = verify_spt(spt.token_id)
        assert result["valid"] is True
        assert result["reason"] == "ok"

    def test_verify_wrong_agent(self):
        from warden.protocols.acp.token_vault import issue_spt, verify_spt
        spt = issue_spt("merchant-1", "agent:did:alice", 100.0)
        result = verify_spt(spt.token_id, expected_agent_id="agent:did:bob")
        assert result["valid"] is False
        assert result["reason"] == "agent_mismatch"

    def test_verify_amount_exceeds_limit(self):
        from warden.protocols.acp.token_vault import issue_spt, verify_spt
        spt = issue_spt("merchant-1", "agent:did:test", 10.0)
        result = verify_spt(spt.token_id, amount=99.0)
        assert result["valid"] is False
        assert result["reason"] == "amount_exceeds_token_limit"

    def test_consume_single_use(self):
        from warden.protocols.acp.token_vault import issue_spt, verify_spt
        spt = issue_spt("merchant-1", "agent:did:test", 50.0, use_limit=1)
        # Consume it
        r1 = verify_spt(spt.token_id, consume=True, order_id="order-1", amount=50.0)
        assert r1["valid"] is True
        # Second attempt must fail
        r2 = verify_spt(spt.token_id)
        assert r2["valid"] is False
        assert r2["reason"] in ("use_limit_exhausted", "status_used")

    def test_consume_multi_use(self):
        from warden.protocols.acp.token_vault import issue_spt, verify_spt
        spt = issue_spt("merchant-1", "agent:did:test", 200.0, use_limit=3)
        verify_spt(spt.token_id, consume=True, order_id="o1", amount=10.0)
        verify_spt(spt.token_id, consume=True, order_id="o2", amount=10.0)
        r = verify_spt(spt.token_id)
        assert r["valid"] is True           # one use remaining
        verify_spt(spt.token_id, consume=True, order_id="o3", amount=10.0)
        r4 = verify_spt(spt.token_id)
        assert r4["valid"] is False         # exhausted

    def test_revoke_token(self):
        from warden.protocols.acp.token_vault import issue_spt, revoke_spt, verify_spt
        spt = issue_spt("merchant-1", "agent:did:test", 50.0)
        revoke_spt(spt.token_id)
        result = verify_spt(spt.token_id)
        assert result["valid"] is False
        assert result["reason"] == "status_revoked"

    def test_nonexistent_token(self):
        from warden.protocols.acp.token_vault import verify_spt
        result = verify_spt("acp_spt_doesnotexist0000")
        assert result["valid"] is False
        assert result["reason"] == "not_found"

    def test_negative_max_amount_rejected(self):
        from warden.protocols.acp.token_vault import issue_spt
        with pytest.raises(ValueError, match="positive"):
            issue_spt("merchant-1", "agent:did:test", -10.0)


# ────────────────────────────────────────────────────────────────────────────────
# Cart
# ────────────────────────────────────────────────────────────────────────────────

class TestCart:
    def test_create_cart(self):
        from warden.protocols.acp.cart import create_cart
        cart = create_cart("tenant-1", "agent:did:test", "merchant-1", "mandate-1")
        assert cart.status == "OPEN"
        assert cart.total == 0.0

    def test_add_items(self):
        from warden.protocols.acp.cart import add_item, create_cart
        from warden.protocols.acp.models import CartItem
        cart = create_cart("tenant-1", "agent:did:test", "merchant-1", "mandate-1")
        add_item(cart.cart_id, CartItem(product_id="p1", name="Widget", qty=2, unit_price=10.0), redis=None)
        updated = add_item(cart.cart_id, CartItem(product_id="p2", name="Gadget", qty=1, unit_price=25.0), redis=None)
        assert updated.total == 45.0   # 2*10 + 1*25

    def test_merge_same_product(self):
        from warden.protocols.acp.cart import add_item, create_cart, get_cart
        from warden.protocols.acp.models import CartItem
        cart = create_cart("tenant-1", "agent:did:test", "merchant-1", "mandate-1")
        add_item(cart.cart_id, CartItem(product_id="p1", name="X", qty=1, unit_price=5.0), redis=None)
        add_item(cart.cart_id, CartItem(product_id="p1", name="X", qty=2, unit_price=5.0), redis=None)
        final = get_cart(cart.cart_id, redis=None)
        assert len(final.items) == 1
        assert final.items[0].qty == 3

    def test_add_to_closed_cart_raises(self):
        from warden.protocols.acp.cart import add_item, close_cart, create_cart
        from warden.protocols.acp.models import CartItem
        cart = create_cart("tenant-1", "agent:did:test", "merchant-1", "mandate-1")
        close_cart(cart.cart_id, "ABANDONED", redis=None)
        with pytest.raises(ValueError, match="ABANDONED"):
            add_item(cart.cart_id, CartItem(product_id="p1", name="X", qty=1, unit_price=5.0), redis=None)

    def test_cart_item_subtotal(self):
        from warden.protocols.acp.models import CartItem
        item = CartItem(product_id="p1", name="X", qty=3, unit_price=9.99)
        assert item.subtotal == 29.97


# ────────────────────────────────────────────────────────────────────────────────
# Checkout (integration — uses real AP2Processor)
# ────────────────────────────────────────────────────────────────────────────────

class TestCheckout:
    @pytest.fixture()
    def mandate(self):
        from warden.business_community.agentic_commerce.ap2 import AP2Processor
        proc = AP2Processor()
        return proc.create_mandate(
            tenant_id="tenant-checkout",
            max_amount=500.0,
            currency="USD",
            allowed_merchants=[],
        )

    @pytest.fixture()
    def spt(self):
        from warden.protocols.acp.token_vault import issue_spt
        return issue_spt("merchant-1", "agent:did:buyer", 100.0)

    @pytest.fixture()
    def cart(self, mandate):
        from warden.protocols.acp.cart import add_item, create_cart
        from warden.protocols.acp.models import CartItem
        c = create_cart("tenant-checkout", "agent:did:buyer", "merchant-1", mandate.id)
        add_item(c.cart_id, CartItem(product_id="sku-001", name="Security Report", qty=1, unit_price=30.0), redis=None)
        return c

    @pytest.mark.anyio
    async def test_checkout_success(self, cart, spt):
        from warden.protocols.acp.checkout import checkout
        result = await checkout(cart.cart_id, spt.token_id, "agent:did:buyer", "tenant-checkout")
        assert result["success"] is True
        receipt = result["receipt"]
        assert receipt["amount"] == 30.0
        assert receipt["agent_id"] == "agent:did:buyer"
        assert receipt["merchant_id"] == "merchant-1"
        assert receipt["transaction_id"].startswith("ap2-")

    @pytest.mark.anyio
    async def test_checkout_spt_consumed_after_success(self, cart, spt):
        from warden.protocols.acp.checkout import checkout
        from warden.protocols.acp.token_vault import verify_spt
        await checkout(cart.cart_id, spt.token_id, "agent:did:buyer", "tenant-checkout")
        r = verify_spt(spt.token_id)
        assert r["valid"] is False  # consumed

    @pytest.mark.anyio
    async def test_checkout_wrong_agent_blocked(self, cart, spt):
        from warden.protocols.acp.checkout import checkout
        result = await checkout(cart.cart_id, spt.token_id, "agent:did:wrong", "tenant-checkout")
        assert result["success"] is False
        assert "agent_mismatch" in result["reason"]

    @pytest.mark.anyio
    async def test_checkout_empty_cart(self, mandate, spt):
        from warden.protocols.acp.cart import create_cart
        from warden.protocols.acp.checkout import checkout
        empty = create_cart("tenant-checkout", "agent:did:buyer", "merchant-1", mandate.id)
        result = await checkout(empty.cart_id, spt.token_id, "agent:did:buyer", "tenant-checkout")
        assert result["success"] is False
        assert result["reason"] == "cart_empty"

    @pytest.mark.anyio
    async def test_checkout_cart_not_found(self, spt):
        from warden.protocols.acp.checkout import checkout
        result = await checkout("nonexistent-cart", spt.token_id, "agent:did:buyer", "tenant-checkout")
        assert result["success"] is False
        assert result["reason"] == "cart_not_found"

    @pytest.mark.anyio
    async def test_checkout_mandate_exceeded(self, spt):
        from warden.business_community.agentic_commerce.ap2 import AP2Processor
        from warden.protocols.acp.cart import add_item, create_cart
        from warden.protocols.acp.checkout import checkout
        from warden.protocols.acp.models import CartItem
        from warden.protocols.acp.token_vault import issue_spt
        # Mandate allows $5, SPT allows $100
        proc = AP2Processor()
        tiny = proc.create_mandate("tenant-tiny", max_amount=5.0)
        big_spt = issue_spt("merchant-1", "agent:did:buyer", 100.0)
        c = create_cart("tenant-tiny", "agent:did:buyer", "merchant-1", tiny.id)
        add_item(c.cart_id, CartItem(product_id="p1", name="X", qty=1, unit_price=50.0), redis=None)
        result = await checkout(c.cart_id, big_spt.token_id, "agent:did:buyer", "tenant-tiny")
        assert result["success"] is False
        assert "mandate" in result["reason"]


# ────────────────────────────────────────────────────────────────────────────────
# Refund
# ────────────────────────────────────────────────────────────────────────────────

class TestRefund:
    def test_request_refund_pending_review(self):
        from warden.protocols.acp.refund import request_refund
        r = request_refund("order-1", "merchant-1", "agent:did:test", "tenant-1", 25.0, reason="defective")
        assert r.status == "PENDING_REVIEW"
        assert r.refund_id.startswith("acp-refund-")
        assert r.amount == 25.0

    def test_get_refund(self):
        from warden.protocols.acp.refund import get_refund, request_refund
        r = request_refund("order-2", "merchant-1", "agent:did:test", "tenant-1", 10.0)
        found = get_refund(r.refund_id)
        assert found is not None
        assert found.order_id == "order-2"

    def test_approve_refund(self):
        from warden.protocols.acp.refund import get_refund, request_refund, resolve_refund
        r = request_refund("order-3", "merchant-1", "agent:did:test", "tenant-1", 5.0)
        ok = resolve_refund(r.refund_id, "approve")
        assert ok is True
        updated = get_refund(r.refund_id)
        assert updated.status == "APPROVED"

    def test_reject_refund(self):
        from warden.protocols.acp.refund import get_refund, request_refund, resolve_refund
        r = request_refund("order-4", "merchant-1", "agent:did:test", "tenant-1", 5.0)
        resolve_refund(r.refund_id, "reject")
        updated = get_refund(r.refund_id)
        assert updated.status == "REJECTED"

    def test_invalid_action_raises(self):
        from warden.protocols.acp.refund import request_refund, resolve_refund
        r = request_refund("order-5", "merchant-1", "agent:did:test", "tenant-1", 5.0)
        with pytest.raises(ValueError, match="approve.*reject"):
            resolve_refund(r.refund_id, "cancel")

    def test_list_refunds(self):
        from warden.protocols.acp.refund import list_refunds, request_refund, resolve_refund
        request_refund("o1", "m1", "a1", "tenant-list", 10.0)
        r2 = request_refund("o2", "m1", "a1", "tenant-list", 20.0)
        resolve_refund(r2.refund_id, "approve")
        all_r = list_refunds("tenant-list")
        assert len(all_r) == 2
        pending = list_refunds("tenant-list", status="PENDING_REVIEW")
        assert len(pending) == 1
        approved = list_refunds("tenant-list", status="APPROVED")
        assert len(approved) == 1

    def test_nonexistent_refund_not_found(self):
        from warden.protocols.acp.refund import get_refund
        assert get_refund("no-such-refund") is None


# ────────────────────────────────────────────────────────────────────────────────
# ACP manifest
# ────────────────────────────────────────────────────────────────────────────────

class TestACPManifest:
    def test_manifest_shape(self):
        from warden.protocols.acp.models import ACPMerchantManifest
        m = ACPMerchantManifest(
            merchant_id="shadow-warden-ai",
            token_endpoint="https://api.shadow-warden-ai.com/acp/token",
            checkout_endpoint="https://api.shadow-warden-ai.com/acp/cart/{cart_id}/checkout",
            refund_endpoint="https://api.shadow-warden-ai.com/acp/refund",
            receipt_endpoint="https://api.shadow-warden-ai.com/acp/receipt/{order_id}",
        )
        assert m.acp_version == "1.0"
        assert "checkout" in m.supported_scopes
        assert "USD" in m.supported_currencies
        assert m.require_agent_did is True
