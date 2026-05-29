"""
warden/tax/calculator.py
VAT/GST/Sales Tax calculator for agentic commerce transactions.
Supports EU VAT OSS, US Sales Tax, Singapore GST, UK VAT, AU GST.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("warden.tax.calculator")

# ── Tax rate registry ─────────────────────────────────────────────────────────

# EU country codes → standard VAT rate (as of 2025)
EU_VAT: dict[str, float] = {
    "AT": 0.20, "BE": 0.21, "BG": 0.20, "CY": 0.19, "CZ": 0.21,
    "DE": 0.19, "DK": 0.25, "EE": 0.22, "ES": 0.21, "FI": 0.255,
    "FR": 0.20, "GR": 0.24, "HR": 0.25, "HU": 0.27, "IE": 0.23,
    "IT": 0.22, "LT": 0.21, "LU": 0.17, "LV": 0.21, "MT": 0.18,
    "NL": 0.21, "PL": 0.23, "PT": 0.23, "RO": 0.19, "SE": 0.25,
    "SI": 0.22, "SK": 0.20,
}

# US states with sales tax (approximate blended rate)
US_SALES_TAX: dict[str, float] = {
    "CA": 0.0725, "NY": 0.08, "TX": 0.0625, "FL": 0.06,
    "WA": 0.065,  "IL": 0.0625, "PA": 0.06, "OH": 0.0575,
    "GA": 0.04,   "NJ": 0.066,  "VA": 0.043, "AZ": 0.056,
    "MA": 0.0625, "TN": 0.07,   "IN": 0.07,  "MO": 0.04225,
    "MD": 0.06,   "WI": 0.05,   "MN": 0.06875, "CO": 0.029,
}

OTHER_TAXES: dict[str, float] = {
    "GB": 0.20,   # UK VAT
    "AU": 0.10,   # Australian GST
    "SG": 0.09,   # Singapore GST
    "CA": 0.05,   # Canadian federal GST (+ provincial varies)
    "NZ": 0.15,   # New Zealand GST
    "JP": 0.10,   # Japanese consumption tax
    "IN": 0.18,   # Indian GST (standard rate)
    "CH": 0.081,  # Swiss VAT
    "NO": 0.25,   # Norwegian VAT
}


@dataclass
class TaxResult:
    country: str
    region: str | None
    rate: float
    tax_amount: float
    total_with_tax: float
    tax_type: str
    net_amount: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "country": self.country,
            "region": self.region,
            "rate_pct": round(self.rate * 100, 3),
            "tax_type": self.tax_type,
            "net_amount": round(self.net_amount, 2),
            "tax_amount": round(self.tax_amount, 2),
            "total_with_tax": round(self.total_with_tax, 2),
        }


class TaxCalculator:

    def calculate(
        self,
        net_amount: float,
        seller_country: str,
        buyer_country: str,
        buyer_region: str | None = None,
        is_b2b: bool = False,
        buyer_vat_id: str | None = None,
    ) -> TaxResult:
        """
        Determine applicable tax rate and compute amounts.
        B2B cross-border EU transactions (with valid VAT ID) → zero-rated.
        """
        country = buyer_country.upper()
        region  = (buyer_region or "").upper()

        # EU VAT OSS
        if country in EU_VAT:
            if is_b2b and buyer_vat_id:
                rate, tax_type = 0.0, "EU_VAT_ZERO_RATED"
            else:
                rate, tax_type = EU_VAT[country], "EU_VAT_OSS"

        # US Sales Tax
        elif country == "US":
            rate = US_SALES_TAX.get(region, 0.0)
            tax_type = f"US_SALES_TAX_{region}" if region else "US_SALES_TAX"

        # Other jurisdictions
        elif country in OTHER_TAXES:
            rate = OTHER_TAXES[country]
            tax_type = f"{country}_TAX"

        else:
            rate, tax_type = 0.0, "NO_TAX"

        tax_amount = net_amount * rate
        return TaxResult(
            country=country,
            region=region or None,
            rate=rate,
            tax_amount=tax_amount,
            total_with_tax=net_amount + tax_amount,
            tax_type=tax_type,
            net_amount=net_amount,
        )

    def quarterly_summary(
        self,
        records: list[dict[str, Any]],
        year: int,
        quarter: int,
    ) -> dict[str, Any]:
        months = {
            1: [1, 2, 3], 2: [4, 5, 6],
            3: [7, 8, 9], 4: [10, 11, 12],
        }[quarter]
        relevant = [
            r for r in records
            if r.get("year") == year and r.get("month") in months
        ]
        by_country: dict[str, dict] = {}
        for r in relevant:
            c = r.get("country", "UNKNOWN")
            if c not in by_country:
                by_country[c] = {"tax_collected": 0.0, "net_sales": 0.0, "transactions": 0}
            by_country[c]["tax_collected"] += r.get("tax_amount", 0)
            by_country[c]["net_sales"]     += r.get("net_amount", 0)
            by_country[c]["transactions"]  += 1
        return {
            "year": year, "quarter": quarter,
            "total_tax": sum(v["tax_collected"] for v in by_country.values()),
            "total_net": sum(v["net_sales"] for v in by_country.values()),
            "by_country": by_country,
        }
