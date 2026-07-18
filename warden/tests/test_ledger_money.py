"""
FT-0 — `warden/ledger/money.py` integer micro-USD money type.

Property-style tests (deterministic seeded loops — the repo has no `hypothesis`
dependency) plus targeted examples. The load-bearing invariants for a ledger are
**conservation** (value neither created nor destroyed by arithmetic or fee
splits) and **no float on money paths**.
"""
from __future__ import annotations

import random
from decimal import Decimal

import pytest

from warden.ledger.money import MICROS_PER_USD, Money


class TestConstruction:
    def test_from_micros(self):
        assert Money.from_micros(1_500_000).micros == 1_500_000

    def test_from_usd_decimal(self):
        assert Money.from_usd(Decimal("1.50")).micros == 1_500_000

    def test_from_usd_string(self):
        assert Money.from_usd("2.25").micros == 2_250_000

    def test_from_usd_int(self):
        assert Money.from_usd(3).micros == 3_000_000

    def test_zero(self):
        assert Money.zero().micros == 0
        assert Money.zero().is_zero()

    def test_float_rejected_in_from_usd(self):
        with pytest.raises(TypeError):
            Money.from_usd(1.5)

    def test_float_rejected_in_mul_rate(self):
        with pytest.raises(TypeError):
            Money.from_usd("10").mul_rate(0.015)

    def test_bool_rejected_as_micros(self):
        # bool is an int subclass — must not sneak through Money(True)
        with pytest.raises(TypeError):
            Money(True)

    def test_non_int_micros_rejected(self):
        with pytest.raises(TypeError):
            Money(Decimal("5"))  # type: ignore[arg-type]


class TestRounding:
    def test_banker_rounding_half_even(self):
        # 0.0000005 USD = 0.5 µUSD → rounds to even (0)
        assert Money.from_usd(Decimal("0.0000005")).micros == 0
        # 0.0000015 USD = 1.5 µUSD → rounds to even (2)
        assert Money.from_usd(Decimal("0.0000015")).micros == 2

    def test_roundtrip_six_dp(self):
        for s in ["0", "1", "0.000001", "1.234567", "999.999999", "42.500000"]:
            d = Decimal(s)
            assert Money.from_usd(d).to_usd() == d.quantize(Decimal("0.000001"))


class TestArithmeticConservation:
    def test_add_sub_inverse(self):
        rng = random.Random(1234)
        for _ in range(2000):
            a = Money(rng.randint(-10**12, 10**12))
            b = Money(rng.randint(-10**12, 10**12))
            assert (a + b) - b == a
            assert (a - b) + b == a

    def test_addition_commutative_associative(self):
        rng = random.Random(99)
        for _ in range(2000):
            a = Money(rng.randint(-10**9, 10**9))
            b = Money(rng.randint(-10**9, 10**9))
            c = Money(rng.randint(-10**9, 10**9))
            assert a + b == b + a
            assert (a + b) + c == a + (b + c)

    def test_sum_matches_micros_sum(self):
        rng = random.Random(7)
        for _ in range(500):
            xs = [Money(rng.randint(-10**8, 10**8)) for _ in range(rng.randint(0, 50))]
            total = Money.zero()
            for x in xs:
                total += x
            assert total.micros == sum(x.micros for x in xs)

    def test_negation(self):
        m = Money.from_usd("12.34")
        assert (-m).micros == -12_340_000
        assert m + (-m) == Money.zero()

    def test_scalar_multiplication(self):
        assert Money.from_usd("1.50") * 3 == Money.from_usd("4.50")
        assert 4 * Money.from_micros(250_000) == Money.from_usd("1.00")

    def test_scalar_mul_rejects_float(self):
        with pytest.raises(TypeError):
            Money.from_usd("1") * 1.5  # type: ignore[operator]


class TestFeeSplitConservation:
    def test_split_conserves_total(self):
        rng = random.Random(2024)
        rates = [Decimal("0.015"), Decimal("0.1"), Decimal("0.333333"), Decimal("0"), Decimal("1")]
        for _ in range(3000):
            total = Money(rng.randint(0, 10**12))
            rate = rng.choice(rates)
            fee, remainder = total.split_fee(rate)
            # THE invariant: no value leaks in the split.
            assert fee + remainder == total

    def test_take_rate_example(self):
        # 1.5% of $100.00 = $1.50 fee, $98.50 net
        fee, net = Money.from_usd("100.00").split_fee(Decimal("0.015"))
        assert fee == Money.from_usd("1.50")
        assert net == Money.from_usd("98.50")

    def test_mul_rate_rounds(self):
        # 1.5% of $0.000001 = 0.000000015 → rounds to 0 µUSD
        assert Money.from_micros(1).mul_rate(Decimal("0.015")) == Money.zero()


class TestComparisonsAndPredicates:
    def test_ordering(self):
        assert Money.from_usd("1") < Money.from_usd("2")
        assert Money.from_usd("2") >= Money.from_usd("2")
        assert Money.from_usd("3") > Money.from_usd("2.999999")

    def test_equality_and_hash(self):
        a = Money.from_usd("5.00")
        b = Money.from_micros(5_000_000)
        assert a == b
        assert hash(a) == hash(b)
        assert len({a, b}) == 1

    def test_not_equal_to_other_types(self):
        assert Money.zero() != 0
        assert Money.zero() != "0"

    def test_predicates(self):
        assert Money.from_usd("1").is_positive()
        assert Money.from_usd("-1").is_negative()
        assert Money.zero().is_zero()
        assert bool(Money.from_usd("0.01")) is True
        assert bool(Money.zero()) is False


class TestScaleConstant:
    def test_micros_per_usd(self):
        assert MICROS_PER_USD == 1_000_000
        assert Money.from_usd("1").micros == MICROS_PER_USD

    def test_repr_is_exact(self):
        assert repr(Money(1_234_567)) == "Money(1234567)"
