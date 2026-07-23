"""
warden/tests/test_x402_balance_shared.py
FT-6 slice 3/3 — shared x402 balance primitive (warden/payments/x402_balance.py).

Pins the exact-same behaviour voice/x402.py and marketplace/x402_gate.py each
had before consolidation: get_balance defaults to 0, credit_balance upserts,
deduct_strict rejects without mutation when insufficient, deduct_floor always
succeeds and clamps at 0.
"""
from __future__ import annotations

import sqlite3

import pytest

from warden.payments.x402_balance import (
    X402_BALANCES_DDL,
    credit_balance,
    deduct_floor,
    deduct_strict,
    get_balance,
)


@pytest.fixture
def con():
    connection = sqlite3.connect(":memory:")
    connection.executescript(X402_BALANCES_DDL)
    yield connection
    connection.close()


class TestGetBalance:
    def test_unknown_agent_returns_zero(self, con):
        assert get_balance(con, "nobody") == 0.0

    def test_returns_stored_balance(self, con):
        credit_balance(con, "a1", 10.0)
        assert get_balance(con, "a1") == pytest.approx(10.0)


class TestCreditBalance:
    def test_creates_row_for_new_agent(self, con):
        credit_balance(con, "a1", 5.0)
        assert get_balance(con, "a1") == pytest.approx(5.0)

    def test_adds_to_existing_balance(self, con):
        credit_balance(con, "a1", 5.0)
        credit_balance(con, "a1", 3.0)
        assert get_balance(con, "a1") == pytest.approx(8.0)


class TestDeductStrict:
    def test_rejects_when_insufficient_no_mutation(self, con):
        credit_balance(con, "a1", 1.0)
        assert deduct_strict(con, "a1", 99.0) is False
        assert get_balance(con, "a1") == pytest.approx(1.0)

    def test_succeeds_when_sufficient(self, con):
        credit_balance(con, "a1", 10.0)
        assert deduct_strict(con, "a1", 3.0) is True
        assert get_balance(con, "a1") == pytest.approx(7.0)

    def test_rejects_for_unknown_agent(self, con):
        assert deduct_strict(con, "nobody", 1.0) is False


class TestDeductFloor:
    def test_clamps_at_zero_when_amount_exceeds_balance(self, con):
        credit_balance(con, "a1", 1.0)
        deduct_floor(con, "a1", 99.0)
        assert get_balance(con, "a1") == pytest.approx(0.0)

    def test_normal_deduction(self, con):
        credit_balance(con, "a1", 10.0)
        deduct_floor(con, "a1", 3.0)
        assert get_balance(con, "a1") == pytest.approx(7.0)

    def test_unknown_agent_is_noop(self, con):
        deduct_floor(con, "nobody", 5.0)
        assert get_balance(con, "nobody") == 0.0
