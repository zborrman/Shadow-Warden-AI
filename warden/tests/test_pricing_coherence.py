"""
Pricing coherence ratchet (FM-7).

Every surface that quotes a price must derive it from warden.billing.pricing.
This guard exists because they did not: on 2026-08-03 the annual plan sold a
year of Pro for $703 against a $1 199.88 monthly list (a 41% discount nobody
priced), because `feature_gate.ANNUAL_PRICING` was hand-written against a $69
Pro that `billing/router.py` had already moved to $99.99. The margin engine held
a third copy.

These tests fail on any new hand-written price, not just on the old ones.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from warden.billing.feature_gate import (
    ANNUAL_DISCOUNT,
    ANNUAL_PRICING,
    TIER_LIMITS,
    FeatureGate,
)
from warden.billing.pricing import (
    TIER_PRICE_USD_MONTH,
    annual_price_usd,
    monthly_price_usd,
)

_PAID_TIERS = ("individual", "community_business", "pro", "enterprise")

_SITE = Path(__file__).resolve().parents[2] / "site"

# Display name on the marketing site → canonical tier key.
_SITE_TIER_NAMES = {
    "Individual":         "individual",
    "Community Business": "community_business",
    "Pro":                "pro",
    "Enterprise":         "enterprise",
}


# ── The canonical table ───────────────────────────────────────────────────────

class TestCanonicalTable:
    def test_every_gated_tier_has_a_price(self):
        for tier in TIER_LIMITS:
            assert monthly_price_usd(tier) is not None, f"{tier} has no list price"

    def test_unknown_tier_has_no_price(self):
        assert monthly_price_usd("platinum_unicorn") is None

    def test_lookup_is_case_and_space_insensitive(self):
        assert monthly_price_usd("  PRO ") == monthly_price_usd("pro")

    @pytest.mark.parametrize(
        ("alias", "canonical"),
        [("free", "starter"), ("smb", "community_business"),
         ("business", "pro"), ("msp", "enterprise"), ("mcp", "enterprise")],
    )
    def test_legacy_aliases_price_as_their_canonical_tier(self, alias, canonical):
        assert monthly_price_usd(alias) == TIER_PRICE_USD_MONTH[canonical]

    def test_gating_and_pricing_share_one_alias_table(self):
        """A tenant must not be priced on one plan and gated on another."""
        from warden.billing.feature_gate import _normalize_tier
        from warden.billing.pricing import TIER_ALIASES
        for alias, canonical in TIER_ALIASES.items():
            assert _normalize_tier(alias) == canonical


# ── Annual pricing is derived, never typed ────────────────────────────────────

class TestAnnualPricing:
    @pytest.mark.parametrize("tier", _PAID_TIERS)
    def test_annual_is_exactly_twelve_months_less_discount(self, tier):
        monthly = TIER_PRICE_USD_MONTH[tier]
        expected = round(monthly * 12.0 * (1.0 - ANNUAL_DISCOUNT), 2)
        assert ANNUAL_PRICING[tier]["usd_per_year"] == expected

    @pytest.mark.parametrize("tier", _PAID_TIERS)
    def test_effective_monthly_matches_the_yearly_price(self, tier):
        plan = ANNUAL_PRICING[tier]
        assert plan["usd_per_month_effective"] == round(plan["usd_per_year"] / 12.0, 2)

    @pytest.mark.parametrize("tier", _PAID_TIERS)
    def test_discount_is_the_advertised_one(self, tier):
        """The regression that started this: a 41% effective discount on a 15% plan."""
        monthly = TIER_PRICE_USD_MONTH[tier]
        effective = 1.0 - (ANNUAL_PRICING[tier]["usd_per_year"] / (monthly * 12.0))
        assert effective == pytest.approx(ANNUAL_DISCOUNT, abs=1e-4)

    def test_free_tiers_have_no_annual_plan(self):
        assert annual_price_usd("starter") is None
        assert "starter" not in ANNUAL_PRICING


# ── Surfaces agree with the table ─────────────────────────────────────────────

class TestSurfacesAgree:
    def test_feature_gate_reexports_the_canonical_annual_map(self):
        from warden.billing import pricing
        assert ANNUAL_PRICING is pricing.ANNUAL_PRICING
        assert ANNUAL_DISCOUNT == pricing.ANNUAL_DISCOUNT

    def test_margin_engine_shares_the_table(self):
        from warden.finops import margin
        assert margin._TIER_PRICE_USD_MONTH is TIER_PRICE_USD_MONTH

    @pytest.mark.parametrize("tier", _PAID_TIERS)
    def test_feature_gate_exposes_the_price(self, tier):
        assert FeatureGate.for_tier(tier).monthly_price_usd() == TIER_PRICE_USD_MONTH[tier]

    @pytest.mark.parametrize("tier", _PAID_TIERS)
    def test_revenue_per_request_uses_the_canonical_price(self, tier):
        from warden.finops.margin import tier_revenue_per_request
        quota = FeatureGate.for_tier(tier).quota_req_per_month()
        rev = tier_revenue_per_request(tier)
        if not quota:                      # unlimited quota → custom pricing
            assert rev is None
        else:
            assert rev == pytest.approx(TIER_PRICE_USD_MONTH[tier] / quota)


# ── The public catalog endpoint ───────────────────────────────────────────────

class TestTierCatalogEndpoint:
    @staticmethod
    def _by_label(payload: dict) -> dict[str, dict]:
        # Keyed by label, not by ["tier"]: FeatureGate normalises "trial" to
        # "starter", so the trial and starter entries share a tier name.
        return {t["pricing"]["label"]: t["pricing"] for t in payload["tiers"]}

    @pytest.mark.asyncio
    async def test_catalog_prices_come_from_the_table(self):
        from warden.billing.router import get_billing_tiers
        priced = self._by_label(await get_billing_tiers())
        for label, tier in (("Individual", "individual"),
                            ("Community Business", "community_business"),
                            ("Pro", "pro"),
                            ("Enterprise", "enterprise")):
            assert priced[label]["usd_per_month"] == TIER_PRICE_USD_MONTH[tier]
            assert priced[label]["annual"] == ANNUAL_PRICING[tier]

    @pytest.mark.asyncio
    async def test_free_entries_carry_no_annual_plan(self):
        from warden.billing.router import get_billing_tiers
        priced = self._by_label(await get_billing_tiers())
        for label in ("Free", "Trial"):
            assert priced[label]["usd_per_month"] == 0.0
            assert priced[label]["annual"] is None

    @pytest.mark.asyncio
    async def test_trial_keeps_its_fourteen_day_marker(self):
        from warden.billing.router import get_billing_tiers
        priced = self._by_label(await get_billing_tiers())
        assert priced["Trial"]["trial_days"] == 14


# ── Request overage (BL-19) ───────────────────────────────────────────────────

class TestOverageRating:
    """
    `_calculate_overage` read a `per_1k_requests_usd` key that has never existed
    in OVERAGE_PRICES (which stores *cents*), so every overage on every tier
    rated at $0.00 and reported itself as disabled. These tests pin the rate to
    the table it is supposed to read.
    """

    @staticmethod
    def _overage(monkeypatch, plan: str, used: int, limit: int) -> dict:
        import warden.billing.quota_middleware as qm
        import warden.lemon_billing as lb
        from warden.billing.router import _calculate_overage

        monkeypatch.setattr(qm, "get_quota_usage",
                            lambda _t: {"used": used, "limit": limit})
        monkeypatch.setattr(lb, "get_lemon_billing",
                            lambda: type("F", (), {"get_plan": lambda _s, _t: plan})())
        return _calculate_overage("t1")

    def test_pro_overage_charges_the_table_rate(self, monkeypatch):
        from warden.billing.feature_gate import OVERAGE_PRICES
        row = self._overage(monkeypatch, "pro", 62_500, 50_000)
        expected_usd = OVERAGE_PRICES["pro"]["cents_per_1k_requests"] / 100.0
        assert row["overage_requests"] == 12_500
        assert row["rate_per_1k_usd"] == expected_usd
        assert row["charge_usd"] == pytest.approx(12.5 * expected_usd)
        assert row["overage_enabled"] is True

    def test_enterprise_rate_is_the_cheaper_one(self, monkeypatch):
        row = self._overage(monkeypatch, "enterprise", 1_100_000, 1_000_000)
        assert row["rate_per_1k_usd"] == 0.10

    def test_no_overage_below_the_quota(self, monkeypatch):
        row = self._overage(monkeypatch, "pro", 10_000, 50_000)
        assert row["overage_requests"] == 0
        assert row["charge_usd"] == 0.0

    def test_tier_without_an_overage_rate_charges_nothing(self, monkeypatch):
        row = self._overage(monkeypatch, "individual", 9_000, 5_000)
        assert row["rate_per_1k_usd"] == 0.0
        assert row["overage_enabled"] is False


# ── The marketing site quotes the same numbers ────────────────────────────────

class TestSitePricesMatchTheTable:
    """
    The site is where a stale price is actually seen and paid. It carried
    $19/$69 for months after the API had moved to $39.99/$99.99, and its annual
    figures ($194 / $705) were derived from the older list — so a customer on
    the annual toggle saw a discount nobody had priced.

    These tests read the Astro sources directly. A price is allowed to live in
    the site (Astro has no runtime access to the Python table), but it must
    agree with `warden.billing.pricing`.
    """

    @staticmethod
    def _read(rel: str) -> str | None:
        path = _SITE / rel
        return path.read_text(encoding="utf-8") if path.exists() else None

    def test_price_page_monthly_and_annual(self):
        src = self._read("src/pages/price.astro")
        if src is None:
            pytest.skip("site/ not present in this checkout")
        found = {
            m.group("name"): (float(m.group("m")), float(m.group("a")))
            for m in re.finditer(
                r"name:\s*'(?P<name>[^']+)',\s*\n\s*price_monthly:\s*(?P<m>[\d.]+),"
                r"\s*\n\s*price_annual:\s*(?P<a>[\d.]+),",
                src,
            )
        }
        assert found, "price.astro tier block no longer parses — update this guard"
        for name, (monthly, yearly) in found.items():
            tier = _SITE_TIER_NAMES.get(name)
            if tier is None:
                continue
            assert monthly == TIER_PRICE_USD_MONTH[tier], f"{name} monthly price is stale"
            assert yearly == annual_price_usd(tier), f"{name} annual price is stale"

    def test_pricing_page_tier_prices(self):
        src = self._read("src/pages/pricing.astro")
        if src is None:
            pytest.skip("site/ not present in this checkout")
        found = {
            m.group("id"): float(m.group("p"))
            for m in re.finditer(
                r"id:\s*'(?P<id>[a-z_]+)',\s*\n\s*name:\s*'[^']*',\s*\n\s*price:\s*(?P<p>[\d.]+),",
                src,
            )
        }
        assert found, "pricing.astro tier block no longer parses — update this guard"
        for tier, price in found.items():
            if tier in TIER_PRICE_USD_MONTH:
                assert price == TIER_PRICE_USD_MONTH[tier], f"{tier} price is stale on /pricing"

    def test_pricing_component_tier_prices(self):
        src = self._read("src/components/Pricing.astro")
        if src is None:
            pytest.skip("site/ not present in this checkout")
        for m in re.finditer(r"name:\s*'(?P<name>[^']+)',\s*price:\s*(?P<p>[\d.]+),", src):
            tier = _SITE_TIER_NAMES.get(m.group("name"))
            if tier is not None:
                assert float(m.group("p")) == TIER_PRICE_USD_MONTH[tier]

    def test_llms_txt_quotes_the_current_prices(self):
        src = self._read("public/llms.txt")
        if src is None:
            pytest.skip("site/ not present in this checkout")
        for name, tier in _SITE_TIER_NAMES.items():
            for m in re.finditer(rf"\*\*{re.escape(name)}\*\*:\s*\$([\d.]+)/month", src):
                assert float(m.group(1)) == TIER_PRICE_USD_MONTH[tier], f"{name} stale in llms.txt"
