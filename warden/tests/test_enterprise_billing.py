"""
Enterprise billing path — quote and invoice.

Enterprise has no self-serve checkout because a merchant-of-record checkout
cannot produce what procurement needs (company-addressed invoice, PO number,
net terms). These tests pin the two things that matter: the quote is priced
from the canonical list rather than from a number someone typed, and the
endpoint is admin-only because it can raise a real invoice.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from warden.billing.pricing import annual_price_usd, monthly_price_usd


@pytest.fixture
def admin(monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "test-admin-key")
    return "test-admin-key"


def _req(**kw):
    from warden.billing.router import EnterpriseQuoteRequest
    return EnterpriseQuoteRequest(**{
        "tenant_id": "t1", "customer_email": "ap@buyer.test", **kw
    })


# ── The quote ─────────────────────────────────────────────────────────────────

class TestEnterpriseQuote:
    @pytest.mark.asyncio
    async def test_annual_quote_uses_the_canonical_price(self, admin):
        from warden.billing.router import enterprise_quote
        q = await enterprise_quote(_req(), x_admin_key=admin)
        assert q["unit_usd"] == annual_price_usd("enterprise")
        assert q["period"] == "annual"
        assert q["total_usd"] == annual_price_usd("enterprise")

    @pytest.mark.asyncio
    async def test_monthly_quote_uses_the_monthly_price(self, admin):
        from warden.billing.router import enterprise_quote
        q = await enterprise_quote(_req(annual=False), x_admin_key=admin)
        assert q["unit_usd"] == monthly_price_usd("enterprise")
        assert q["period"] == "monthly"

    @pytest.mark.asyncio
    async def test_seats_multiply_the_total(self, admin):
        from warden.billing.router import enterprise_quote
        q = await enterprise_quote(_req(seats=4), x_admin_key=admin)
        assert q["total_usd"] == round(annual_price_usd("enterprise") * 4, 2)

    @pytest.mark.asyncio
    async def test_po_number_is_carried_through(self, admin):
        from warden.billing.router import enterprise_quote
        q = await enterprise_quote(_req(po_number="PO-4417"), x_admin_key=admin)
        assert q["po_number"] == "PO-4417"

    @pytest.mark.asyncio
    async def test_quoting_alone_raises_no_invoice(self, admin):
        from warden.billing.router import enterprise_quote
        q = await enterprise_quote(_req(), x_admin_key=admin)
        assert q["invoice"] is None

    @pytest.mark.asyncio
    async def test_zero_seats_is_rejected(self, admin):
        from fastapi import HTTPException

        from warden.billing.router import enterprise_quote
        with pytest.raises(HTTPException) as exc:
            await enterprise_quote(_req(seats=0), x_admin_key=admin)
        assert exc.value.status_code == 400


# ── Access ────────────────────────────────────────────────────────────────────

class TestQuoteIsAdminOnly:
    @pytest.mark.asyncio
    async def test_without_the_admin_key_it_refuses(self, admin):
        from fastapi import HTTPException

        from warden.billing.router import enterprise_quote
        with pytest.raises(HTTPException) as exc:
            await enterprise_quote(_req(), x_admin_key=None)
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_a_wrong_key_refuses(self, admin):
        from fastapi import HTTPException

        from warden.billing.router import enterprise_quote
        with pytest.raises(HTTPException) as exc:
            await enterprise_quote(_req(), x_admin_key="not-the-key")
        assert exc.value.status_code == 403


# ── Invoicing ─────────────────────────────────────────────────────────────────

class TestInvoiceRequest:
    @pytest.mark.asyncio
    async def test_unconfigured_stripe_still_returns_a_valid_quote(self, admin, monkeypatch):
        """
        Stripe being unconfigured is an operator state, not a client error: the
        quote is correct either way, so the caller gets it with the reason
        attached instead of a 500.
        """
        from warden.billing.router import enterprise_quote

        stub = MagicMock()
        stub.create_enterprise_invoice.side_effect = RuntimeError("Stripe not configured")
        with patch("warden.stripe_billing.get_stripe_billing", return_value=stub):
            q = await enterprise_quote(_req(raise_invoice=True), x_admin_key=admin)

        assert q["total_usd"] == annual_price_usd("enterprise")
        assert q["invoice"] is None
        assert "Stripe not configured" in q["invoice_error"]

    @pytest.mark.asyncio
    async def test_a_successful_invoice_is_attached(self, admin):
        from warden.billing.router import enterprise_quote

        stub = MagicMock()
        stub.create_enterprise_invoice.return_value = {
            "invoice_id": "in_123", "status": "open",
            "hosted_url": "https://invoice.stripe.test/in_123",
        }
        with patch("warden.stripe_billing.get_stripe_billing", return_value=stub):
            q = await enterprise_quote(
                _req(raise_invoice=True, seats=3, po_number="PO-1"), x_admin_key=admin
            )

        assert q["invoice"]["invoice_id"] == "in_123"
        kwargs = stub.create_enterprise_invoice.call_args.kwargs
        assert kwargs["seats"] == 3
        assert kwargs["po_number"] == "PO-1"
        assert kwargs["annual"] is True

    @pytest.mark.asyncio
    async def test_a_provider_failure_is_a_502_not_a_silent_success(self, admin):
        from fastapi import HTTPException

        from warden.billing.router import enterprise_quote

        stub = MagicMock()
        stub.create_enterprise_invoice.side_effect = ValueError("bad email")
        with (
            patch("warden.stripe_billing.get_stripe_billing", return_value=stub),
            pytest.raises(HTTPException) as exc,
        ):
            await enterprise_quote(_req(raise_invoice=True), x_admin_key=admin)
        assert exc.value.status_code == 502


# ── Enterprise features are purchasable below Enterprise ──────────────────────

class TestEnterpriseFeaturesAsAddons:
    @pytest.mark.parametrize(
        ("addon", "feature"),
        [("pqc_pack", "pqc_enabled"), ("sovereign_pack", "sovereign_enabled")],
    )
    def test_the_addon_unlocks_the_enterprise_feature(self, addon, feature):
        from warden.billing.addons import ADDON_CATALOG
        entry = ADDON_CATALOG[addon]
        assert feature in entry["unlocks"]
        assert entry["min_tier"] == "pro"
        assert entry["usd_per_month"] > 0

    @pytest.mark.parametrize("feature", ["pqc_enabled", "sovereign_enabled"])
    def test_enterprise_still_includes_them_natively(self, feature):
        from warden.billing.feature_gate import FeatureGate
        assert FeatureGate.for_tier("enterprise").is_enabled(feature) is True

    @pytest.mark.parametrize("feature", ["pqc_enabled", "sovereign_enabled"])
    def test_pro_does_not_get_them_for_free(self, feature):
        """The add-on is the only route at Pro — otherwise it is not a product."""
        from warden.billing.feature_gate import FeatureGate
        assert FeatureGate.for_tier("pro").is_enabled(feature) is False

    def test_both_addons_cost_less_than_the_tier_they_unbundle(self):
        from warden.billing.addons import ADDON_CATALOG
        from warden.billing.pricing import monthly_price_usd
        pair = ADDON_CATALOG["pqc_pack"]["usd_per_month"] + \
            ADDON_CATALOG["sovereign_pack"]["usd_per_month"]
        pro = monthly_price_usd("pro")
        assert pro + pair < monthly_price_usd("enterprise") * 2, (
            "Pro + both packs should stay a sane alternative to Enterprise"
        )
