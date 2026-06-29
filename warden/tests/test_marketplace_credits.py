"""Tests for warden/marketplace/credits.py — Flex Credits system."""
import os
import pytest


@pytest.fixture(autouse=True)
def _isolate_credits(tmp_path):
    os.environ["MARKETPLACE_DB_PATH"] = str(tmp_path / "credits_test.db")
    os.environ["REDIS_URL"] = "memory://"
    yield
    os.environ.pop("MARKETPLACE_DB_PATH", None)
    os.environ.pop("REDIS_URL", None)


class TestCreditPackages:
    def test_package_catalog_has_four_skus(self):
        from warden.marketplace.credits import CREDIT_PACKAGES
        assert len(CREDIT_PACKAGES) == 4
        assert "credits_100" in CREDIT_PACKAGES
        assert "credits_5000" in CREDIT_PACKAGES

    def test_package_fields_present(self):
        from warden.marketplace.credits import CREDIT_PACKAGES
        for sku, pkg in CREDIT_PACKAGES.items():
            assert "credits" in pkg, f"{sku} missing 'credits'"
            assert "price_usd" in pkg, f"{sku} missing 'price_usd'"
            assert pkg["credits"] > 0
            assert pkg["price_usd"] > 0


class TestPurchaseCredits:
    def test_purchase_starter_pack(self):
        from warden.marketplace.credits import get_balance, purchase_credits
        new_balance = purchase_credits("tenant-1", "credits_100")
        assert new_balance == 100
        assert get_balance("tenant-1") == 100

    def test_purchase_adds_to_existing_balance(self):
        from warden.marketplace.credits import get_balance, purchase_credits
        purchase_credits("tenant-2", "credits_100")
        purchase_credits("tenant-2", "credits_100")
        assert get_balance("tenant-2") == 200

    def test_purchase_enterprise_pack(self):
        from warden.marketplace.credits import get_balance, purchase_credits
        purchase_credits("tenant-ent", "credits_5000")
        assert get_balance("tenant-ent") == 5000

    def test_purchase_unknown_package_raises(self):
        from warden.marketplace.credits import purchase_credits
        with pytest.raises(Exception):
            purchase_credits("tenant-bad", "credits_99999")

    def test_initial_balance_is_zero(self):
        from warden.marketplace.credits import get_balance
        assert get_balance("tenant-never-purchased") == 0


class TestDeductCredits:
    def test_deduct_succeeds_when_balance_sufficient(self):
        from warden.marketplace.credits import deduct_credits, get_balance, purchase_credits
        purchase_credits("tenant-3", "credits_100")
        result = deduct_credits("tenant-3", 1)
        assert result is True
        assert get_balance("tenant-3") == 99

    def test_deduct_multiple_times(self):
        from warden.marketplace.credits import deduct_credits, get_balance, purchase_credits
        purchase_credits("tenant-4", "credits_100")
        for _ in range(10):
            deduct_credits("tenant-4", 1)
        assert get_balance("tenant-4") == 90

    def test_deduct_with_zero_balance_returns_false(self):
        from warden.marketplace.credits import deduct_credits
        result = deduct_credits("tenant-empty", 1)
        assert result is False

    def test_deduct_does_not_go_negative(self):
        from warden.marketplace.credits import deduct_credits, get_balance
        deduct_credits("tenant-neg", 1)
        assert get_balance("tenant-neg") >= 0

    def test_deduct_exact_balance_returns_true(self):
        from warden.marketplace.credits import deduct_credits, get_balance, purchase_credits
        purchase_credits("tenant-exact", "credits_100")
        result = deduct_credits("tenant-exact", 100)
        assert result is True
        assert get_balance("tenant-exact") == 0

    def test_deduct_over_balance_returns_false(self):
        from warden.marketplace.credits import deduct_credits, purchase_credits
        purchase_credits("tenant-over", "credits_100")
        result = deduct_credits("tenant-over", 200)
        assert result is False

    def test_deduct_does_not_raise_on_zero_balance(self):
        from warden.marketplace.credits import deduct_credits
        deduct_credits("tenant-z", 1)   # must not raise
        deduct_credits("tenant-z", 1)   # repeat must not raise

    def test_deduct_preserves_balance_on_failure(self):
        """When deduct returns False, balance must stay the same."""
        from warden.marketplace.credits import deduct_credits, get_balance, purchase_credits
        purchase_credits("tenant-preserve", "credits_100")
        balance_before = get_balance("tenant-preserve")
        result = deduct_credits("tenant-preserve", 200)
        assert result is False
        assert get_balance("tenant-preserve") == balance_before


class TestGetBalance:
    def test_returns_int(self):
        from warden.marketplace.credits import get_balance
        assert isinstance(get_balance("tenant-type-check"), int)

    def test_isolated_between_tenants(self):
        from warden.marketplace.credits import get_balance, purchase_credits
        purchase_credits("tenant-A-iso", "credits_500")
        assert get_balance("tenant-B-iso") == 0
