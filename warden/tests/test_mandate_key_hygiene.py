"""
Phase 7 — key hygiene for agent payment mandates.

Regression tests for a fail-OPEN authorization bypass: `validate_mandate()` used to
verify the HMAC signature only `if _MANDATE_SECRET:`. Any deployment that never set
MANDATE_SECRET therefore accepted **unsigned** mandates — a caller could spend against
an agent's budget with no signature at all.

Signature verification is now unconditional, and the key comes from resolve_key
(explicit MANDATE_SECRET wins; else derived from VAULT_MASTER_KEY; else DENY).
"""
from __future__ import annotations

import hashlib
import hmac

import pytest

from warden.agentic.mandate import (
    _invoices,
    create_invoice,
    sign_mandate,
    validate_mandate,
)

_AGENT = {
    "agent_id": "agent-1",
    "status": "active",
    "max_per_item": 100.0,
    "monthly_budget": 1000.0,
    "_monthly_spend": 0.0,
}


def _mandate(invoice_hash, sku="sku-1", amount=10.0, agent_id="agent-1", signature=None):
    m = {
        "invoice_hash": invoice_hash,
        "sku": sku,
        "amount": amount,
        "agent_id": agent_id,
    }
    m["signature"] = sign_mandate(invoice_hash, sku, amount, agent_id) if signature is None else signature
    return m


@pytest.fixture(autouse=True)
def _clean():
    _invoices.clear()
    yield
    _invoices.clear()


class TestSignatureIsMandatory:
    def test_unsigned_mandate_is_rejected(self, monkeypatch):
        """THE bug: with no MANDATE_SECRET set, an unsigned mandate used to be accepted."""
        monkeypatch.delenv("MANDATE_SECRET", raising=False)   # the vulnerable config
        inv = create_invoice("sku-1", 10.0, "agent-1")
        m = _mandate(inv["invoice_hash"], signature="")       # no signature at all
        res = validate_mandate(m, dict(_AGENT))
        assert res.valid is False
        assert "signature" in res.reason.lower()

    def test_forged_signature_is_rejected(self, monkeypatch):
        monkeypatch.delenv("MANDATE_SECRET", raising=False)
        inv = create_invoice("sku-1", 10.0, "agent-1")
        m = _mandate(inv["invoice_hash"], signature="00" * 32)
        assert validate_mandate(m, dict(_AGENT)).valid is False

    def test_wrong_key_signature_is_rejected(self, monkeypatch):
        monkeypatch.setenv("MANDATE_SECRET", "the-real-secret")
        inv = create_invoice("sku-1", 10.0, "agent-1")
        bad = hmac.new(
            b"attacker-guess",
            f"{inv['invoice_hash']}:sku-1:10.0:agent-1".encode(),
            hashlib.sha256,
        ).hexdigest()
        m = _mandate(inv["invoice_hash"], signature=bad)
        assert validate_mandate(m, dict(_AGENT)).valid is False

    def test_correctly_signed_mandate_is_accepted(self, monkeypatch):
        monkeypatch.setenv("MANDATE_SECRET", "the-real-secret")
        inv = create_invoice("sku-1", 10.0, "agent-1")
        res = validate_mandate(_mandate(inv["invoice_hash"]), dict(_AGENT))
        assert res.valid is True, res.reason

    def test_signature_verified_when_key_only_derived(self, monkeypatch):
        """No explicit MANDATE_SECRET → key derived from VAULT_MASTER_KEY, still enforced."""
        monkeypatch.delenv("MANDATE_SECRET", raising=False)
        inv = create_invoice("sku-1", 10.0, "agent-1")
        # sign_mandate uses the same derived key the validator will use
        assert validate_mandate(_mandate(inv["invoice_hash"]), dict(_AGENT)).valid is True


class TestFailClosedWithoutKey:
    def test_no_key_at_all_denies(self, monkeypatch):
        """Production with neither MANDATE_SECRET nor a master key must DENY, not allow."""
        monkeypatch.delenv("MANDATE_SECRET", raising=False)
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.delenv("COMMUNITY_VAULT_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
        monkeypatch.setenv("ALLOW_INSECURE_SECRETS", "false")

        inv = create_invoice("sku-1", 10.0, "agent-1")
        m = {
            "invoice_hash": inv["invoice_hash"],
            "sku": "sku-1",
            "amount": 10.0,
            "agent_id": "agent-1",
            "signature": "deadbeef",
        }
        res = validate_mandate(m, dict(_AGENT))
        assert res.valid is False
        assert "key not configured" in res.reason.lower()


class TestExplicitOverrideIsVerbatim:
    def test_explicit_secret_used_as_is(self, monkeypatch):
        """Deployments that already set MANDATE_SECRET keep their existing signatures."""
        monkeypatch.setenv("MANDATE_SECRET", "legacy-secret")
        expected = hmac.new(
            b"legacy-secret", b"h:sku-1:10.0:agent-1", hashlib.sha256
        ).hexdigest()
        assert sign_mandate("h", "sku-1", 10.0, "agent-1") == expected
