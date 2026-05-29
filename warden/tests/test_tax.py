"""
warden/tests/test_tax.py  (Phase 3 — 8 tests)
Tax calculation, invoice generation, quarterly reporting.
"""
from __future__ import annotations

import pytest


class TestTaxCalculator:
    def _calc(self):
        from warden.tax.calculator import TaxCalculator
        return TaxCalculator()

    def test_eu_vat_germany(self):
        result = self._calc().calculate(100.0, "US", "DE")
        assert result.rate == pytest.approx(0.19)
        assert result.tax_type == "EU_VAT_OSS"
        assert result.total_with_tax == pytest.approx(119.0)

    def test_eu_vat_b2b_zero_rated(self):
        result = self._calc().calculate(100.0, "US", "DE", is_b2b=True, buyer_vat_id="DE123456789")
        assert result.rate == 0.0
        assert result.tax_type == "EU_VAT_ZERO_RATED"

    def test_us_sales_tax_california(self):
        result = self._calc().calculate(100.0, "US", "US", buyer_region="CA")
        assert result.rate == pytest.approx(0.0725)
        assert "US_SALES_TAX" in result.tax_type

    def test_uk_vat(self):
        result = self._calc().calculate(200.0, "US", "GB")
        assert result.rate == pytest.approx(0.20)
        assert result.total_with_tax == pytest.approx(240.0)

    def test_singapore_gst(self):
        result = self._calc().calculate(100.0, "US", "SG")
        assert result.rate == pytest.approx(0.09)

    def test_no_tax_unknown_country(self):
        result = self._calc().calculate(100.0, "US", "ZZ")
        assert result.rate == 0.0
        assert result.tax_type == "NO_TAX"

    def test_to_dict(self):
        result = self._calc().calculate(50.0, "US", "FR")
        d = result.to_dict()
        assert "rate_pct" in d and "tax_amount" in d and "total_with_tax" in d

    def test_quarterly_summary_empty(self):
        summary = self._calc().quarterly_summary([], 2026, 2)
        assert summary["total_tax"] == 0.0
        assert summary["quarter"] == 2


class TestInvoiceGenerator:
    def test_create_returns_invoice_number(self):
        from warden.tax.invoice_generator import InvoiceGenerator
        order = {"id": "abc123", "tenant_id": "t1", "store_url": "shop.com",
                 "total": 99.0, "items": []}
        invoice = InvoiceGenerator().create(order, None)
        assert invoice["invoice_number"].startswith("INV-")
        assert invoice["size_bytes"] > 0
