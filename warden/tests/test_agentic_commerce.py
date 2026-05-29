"""
warden/tests/test_agentic_commerce.py  (CM-40)
Agentic Commerce (UCP/AP2/MCP) — 15 tests
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("COMMERCE_DB_PATH", "/tmp/test_commerce.db")
os.environ.setdefault("VAULT_MASTER_KEY", "")


# ── AP2 Processor ─────────────────────────────────────────────────────────────

class TestAP2Processor:
    @pytest.fixture(autouse=True)
    def _clean(self, tmp_path):
        db = str(tmp_path / "commerce.db")
        os.environ["COMMERCE_DB_PATH"] = db
        yield
        if os.path.exists(db):
            os.remove(db)

    def _proc(self):
        from warden.business_community.agentic_commerce.ap2 import AP2Processor
        return AP2Processor()

    def test_create_mandate_success(self):
        m = self._proc().create_mandate("tenant1", max_amount=500.0)
        assert m.id
        assert m.status == "ACTIVE"
        assert m.max_amount == 500.0
        assert m.signature  # signed

    def test_mandate_stored_and_retrievable(self):
        proc = self._proc()
        m = proc.create_mandate("tenant1", max_amount=200.0)
        retrieved = proc.get_mandate(m.id, "tenant1")
        assert retrieved is not None
        assert retrieved.id == m.id

    def test_payment_within_mandate(self):
        proc = self._proc()
        m = proc.create_mandate("tenant1", max_amount=100.0)
        result = proc.execute_payment(m.id, "tenant1", amount=30.0, merchant="shop.com", order_ref="order-1")
        assert result["success"] is True
        assert result["remaining"] == pytest.approx(70.0)

    def test_payment_exceeds_mandate_balance(self):
        proc = self._proc()
        m = proc.create_mandate("tenant1", max_amount=50.0)
        result = proc.execute_payment(m.id, "tenant1", amount=100.0, merchant="shop.com", order_ref="order-2")
        assert result["success"] is False
        assert result["reason"] == "insufficient_mandate_balance"

    def test_revoked_mandate_blocks_payment(self):
        proc = self._proc()
        m = proc.create_mandate("tenant1", max_amount=200.0)
        proc.revoke_mandate(m.id, "tenant1")
        result = proc.execute_payment(m.id, "tenant1", amount=10.0, merchant="shop.com", order_ref="order-3")
        assert result["success"] is False

    def test_merchant_allowlist_blocks_unknown(self):
        proc = self._proc()
        m = proc.create_mandate("tenant1", max_amount=200.0, allowed_merchants=["trusted.com"])
        result = proc.execute_payment(m.id, "tenant1", amount=10.0, merchant="evil.com", order_ref="order-4")
        assert result["success"] is False
        assert result["reason"] == "merchant_not_allowed"

    def test_merchant_allowlist_permits_known(self):
        proc = self._proc()
        m = proc.create_mandate("tenant1", max_amount=200.0, allowed_merchants=["trusted.com"])
        result = proc.execute_payment(m.id, "tenant1", amount=10.0, merchant="trusted.com", order_ref="order-5")
        assert result["success"] is True

    def test_mandate_usage_summary(self):
        proc = self._proc()
        proc.create_mandate("tenant2", max_amount=300.0)
        proc.create_mandate("tenant2", max_amount=700.0)
        usage = proc.get_mandate_usage("tenant2")
        assert usage["total_mandates"] == 2
        assert usage["total_authorized"] == pytest.approx(1000.0)

    def test_create_mandate_invalid_amount(self):
        with pytest.raises(ValueError):
            self._proc().create_mandate("tenant1", max_amount=-1.0)

    def test_verify_mandate_valid(self):
        proc = self._proc()
        m = proc.create_mandate("tenant1", max_amount=100.0)
        result = proc.verify_mandate(m.id, "tenant1")
        assert result["valid"] is True

    def test_list_mandates(self):
        proc = self._proc()
        proc.create_mandate("tenant3", max_amount=100.0)
        proc.create_mandate("tenant3", max_amount=200.0)
        mandates = proc.list_mandates("tenant3")
        assert len(mandates) == 2


# ── MCP Bridge ────────────────────────────────────────────────────────────────

class TestMCPBridge:
    def _bridge(self):
        from warden.business_community.agentic_commerce.mcp_bridge import MCPBridge
        return MCPBridge()

    def test_parse_intent_with_amount(self):
        bridge = self._bridge()
        intent = bridge.receive_intent({
            "tenant_id": "t1",
            "content": "Buy a software license for up to $49",
        })
        assert intent.max_amount == pytest.approx(49.0)
        assert "software" in intent.keywords or "license" in intent.keywords

    def test_parse_intent_requires_approval(self):
        bridge = self._bridge()
        intent = bridge.receive_intent({
            "tenant_id": "t1",
            "content": "Purchase cloud servers for $500",
        })
        assert intent.requires_approval is True

    def test_parse_intent_no_approval_below_threshold(self):
        bridge = self._bridge()
        intent = bridge.receive_intent({
            "tenant_id": "t1",
            "content": "Get a book for $20",
        })
        assert intent.requires_approval is False

    def test_translate_to_ucp(self):
        bridge = self._bridge()
        intent = bridge.receive_intent({"tenant_id": "t1", "content": "Buy software license $30"})
        ucp_req = bridge.translate_to_ucp(intent)
        assert "query" in ucp_req
        assert ucp_req["max_price"] == pytest.approx(30.0)
