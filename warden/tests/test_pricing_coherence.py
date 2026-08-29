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

    def test_served_markdown_quotes_the_current_prices(self):
        """
        `Accept: text/markdown` is answered from site/public/*.md. Those files
        are a fourth surface quoting prices, and an agent reads them instead of
        the HTML — a stale number here is a stale number quoted to a machine.
        """
        public = _SITE / "public"
        if not public.is_dir():
            pytest.skip("site/ not present in this checkout")
        for path in public.rglob("*.md"):
            src = path.read_text(encoding="utf-8")
            for name, tier in _SITE_TIER_NAMES.items():
                for m in re.finditer(rf"\*\*{re.escape(name)}\*\*[^\n|]*\|?\s*\$([\d.]+)", src):
                    assert float(m.group(1)) == TIER_PRICE_USD_MONTH[tier], (
                        f"{name} is stale in {path.name}"
                    )

    def test_homepage_structured_data_quotes_the_canonical_ceiling(self):
        """
        The homepage publishes an AggregateOffer to machines. Its highPrice is
        the most expensive plan — hand-written, because Astro cannot read the
        Python table, so it is pinned here like every other site price.
        """
        src = self._read("src/pages/index.astro")
        if src is None:
            pytest.skip("site/ not present in this checkout")
        high = re.search(r"highPrice:\s*'([\d.]+)'", src)
        assert high, "the homepage AggregateOffer no longer parses — update this guard"
        assert float(high.group(1)) == max(TIER_PRICE_USD_MONTH.values()), (
            "the homepage tells machines a ceiling price no plan costs"
        )
        low = re.search(r"lowPrice:\s*'([\d.]+)'", src)
        assert low and float(low.group(1)) == min(TIER_PRICE_USD_MONTH.values())


# ── Metered pricing: one price per unit of work ───────────────────────────────

class TestMeteredPricing:
    """
    A search cost $0.000001 on the x402 rail and $0.001 as a prepaid credit —
    a 1000x gap for identical work, decided by which rail the agent happened to
    use. Both now read the same constant.
    """

    def test_x402_and_credits_charge_the_same_for_a_search(self):
        from decimal import Decimal

        from warden.billing.pricing import CREDIT_USD, MARKETPLACE_SEARCH_FEE_USD
        from warden.marketplace.credits import _CREDIT_MICROS
        from warden.marketplace.x402_gate import _SEARCH_FEE_USD

        assert MARKETPLACE_SEARCH_FEE_USD == CREDIT_USD
        assert Decimal(str(MARKETPLACE_SEARCH_FEE_USD)) == _SEARCH_FEE_USD
        assert int(round(CREDIT_USD * 1_000_000)) == _CREDIT_MICROS

    def test_settings_default_matches_the_canonical_fee(self):
        from warden.billing.pricing import MARKETPLACE_SEARCH_FEE_USD
        from warden.config import Settings
        assert float(Settings().marketplace_search_fee_usd) == MARKETPLACE_SEARCH_FEE_USD


# ── Agent-turn allowance (published, not implicit) ────────────────────────────

class TestAgentTurnAllowance:
    def test_pro_publishes_an_allowance(self):
        assert FeatureGate.for_tier("pro").agent_turns_per_month() > 0

    def test_enterprise_is_unlimited_and_free_tiers_have_none(self):
        assert FeatureGate.for_tier("enterprise").agent_turns_per_month() is None
        assert FeatureGate.for_tier("starter").agent_turns_per_month() == 0

    @pytest.mark.parametrize("tier", ["starter", "individual", "community_business",
                                      "pro", "enterprise"])
    def test_an_allowance_is_published_only_where_the_agent_is_enabled(self, tier):
        """Publishing turns for a tier that cannot call the agent is a promise
        the product does not keep — and publishing none where it can is the
        unbounded-cost problem this whole allowance exists to close."""
        gate = FeatureGate.for_tier(tier)
        turns = gate.agent_turns_per_month()
        enabled = bool(gate.get("master_agent_enabled"))
        assert (turns is None or turns > 0) == enabled, (
            f"{tier}: master_agent_enabled={enabled} but turn allowance={turns}"
        )

    def test_the_allowance_fits_inside_the_tier_llm_budget(self):
        """
        The published turn count must be affordable within the tier's own
        inference allowance at the model it is sold with. A published allowance
        the plan cannot fund is the same unbounded promise, just written down.
        """
        from warden.finops.llm_budget import tier_llm_budget_usd
        from warden.finops.rating import rate_usage

        opus_turn = rate_usage("claude-opus-4-8", 2_000, 800, 20_000).total_usd
        for tier in ("pro",):
            turns = FeatureGate.for_tier(tier).agent_turns_per_month()
            budget = tier_llm_budget_usd(tier)
            assert turns * opus_turn <= budget, f"{tier} sells more turns than it funds"

    @pytest.mark.asyncio
    async def test_catalog_publishes_the_allowance_and_its_overage_rate(self):
        from warden.billing.pricing import AGENT_TURN_OVERAGE_USD
        from warden.billing.router import get_billing_tiers
        payload = await get_billing_tiers()
        pro = next(t for t in payload["tiers"] if t["pricing"]["label"] == "Pro")
        assert pro["agent_turns_per_month"] == FeatureGate.for_tier("pro").agent_turns_per_month()
        assert pro["agent_turn_overage_usd"] == AGENT_TURN_OVERAGE_USD


# ── Agent-turn overage metering ───────────────────────────────────────────────

class TestAgentTurnOverage:
    @staticmethod
    def _overage(monkeypatch, plan: str, turns_used: int) -> dict:
        import warden.billing.quota_middleware as qm
        import warden.lemon_billing as lb
        from warden.billing.router import _calculate_overage

        monkeypatch.setattr(qm, "get_quota_usage", lambda _t: {"used": 0, "limit": 50_000})
        monkeypatch.setattr(lb, "get_lemon_billing",
                            lambda: type("F", (), {"get_plan": lambda _s, _t: plan})())
        monkeypatch.setattr(
            "warden.staff.economics.TokenCostTracker.get_turns_since",
            lambda _self, _t, _since, agent_prefix="master": turns_used,
        )
        return _calculate_overage("t1")

    def test_turns_within_the_allowance_are_free(self, monkeypatch):
        row = self._overage(monkeypatch, "pro", turns_used=10)
        assert row["overage_turns"] == 0
        assert row["turn_charge_usd"] == 0.0

    def test_turns_beyond_the_allowance_are_metered(self, monkeypatch):
        from warden.billing.pricing import AGENT_TURN_OVERAGE_USD
        allowance = FeatureGate.for_tier("pro").agent_turns_per_month()
        row = self._overage(monkeypatch, "pro", turns_used=allowance + 20)
        assert row["overage_turns"] == 20
        assert row["turn_charge_usd"] == pytest.approx(20 * AGENT_TURN_OVERAGE_USD)
        assert row["charge_usd"] == pytest.approx(row["request_charge_usd"] + row["turn_charge_usd"])

    def test_enterprise_turns_are_never_metered(self, monkeypatch):
        row = self._overage(monkeypatch, "enterprise", turns_used=100_000)
        assert row["overage_turns"] == 0
        assert row["turn_charge_usd"] == 0.0


# ── The published HTML, not just the source ───────────────────────────────────

class TestPublishedSiteIsCurrent:
    """
    `landing/` is what Vercel actually serves — `vercel.json` sets
    `buildCommand: null` and `outputDirectory: "landing"`, so the Astro source in
    `site/` is never built at deploy time. Editing `site/` therefore changes the
    source and leaves production untouched: the live pricing page served $19/$69
    for two days after the corrected prices merged to main.

    CI regenerates the directory on merge (`.github/workflows/deploy-site.yml`).
    This test is the backstop for the day that workflow silently stops running —
    it reads the published bytes and asserts they quote the canonical prices.
    """

    _LANDING = _SITE.parent / "landing"

    def _published(self, page: str) -> str:
        path = self._LANDING / page / "index.html"
        if not path.exists():
            pytest.skip(f"landing/{page}/ not present in this checkout")
        return path.read_text(encoding="utf-8", errors="ignore")

    @pytest.mark.parametrize("tier", ["community_business", "pro"])
    def test_published_price_page_quotes_the_canonical_monthly_price(self, tier):
        html = self._published("price")
        price = f"${TIER_PRICE_USD_MONTH[tier]:g}"
        assert price in html, (
            f"landing/price/ does not quote {price} for {tier}. "
            "The published site is stale — rebuild site/ and regenerate landing/."
        )

    @pytest.mark.parametrize("tier", ["individual", "community_business", "pro"])
    def test_published_price_page_quotes_the_derived_annual_price(self, tier):
        html = self._published("price")
        annual = annual_price_usd(tier)
        assert annual is not None
        assert f"{annual:.2f}" in html, (
            f"landing/price/ does not quote the ${annual:.2f} annual price for {tier}."
        )

    def test_published_page_carries_no_retired_price(self):
        """The two numbers the live site was still serving after the fix."""
        html = self._published("price")
        # "$19" alone is not a safe marker — the Event Streaming add-on
        # legitimately costs $19/mo. Only strings that can be a tier price.
        for retired in ("$69<", "billed $194", "billed $705", "10,000 req / month"):
            assert retired not in html, (
                f"landing/price/ still carries the retired {retired!r} — "
                "the published build predates the canonical price list."
            )
