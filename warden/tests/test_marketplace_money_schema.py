"""
warden/tests/test_marketplace_money_schema.py

The money path, pinned against the schema it actually runs on.

`ClearingEngine` queried two columns that have never existed —
`marketplace_negotiations.agreed_price` and `.buyer_agent_id` (the real names
are `current_price` and `buyer_agent`). Both SELECTs raised, both `except`
blocks swallowed it, and the result was a settlement engine that:

  * authorised **every** trade at $0.00 through the FT-6 chokepoint,
  * computed a $0.00 platform fee and a $0.00 seller net, and
  * never rejected a single losing negotiation.

None of that was visible, because each clearing test built its own fixture
table declaring the ghost columns — the suite agreed with the bug. The
fixtures now come from `_NEGOTIATION_DDL` itself (see
`warden/tests/marketplace_schema.py`), so a rename in the product breaks the
tests that depend on it.

Production had cleared nothing when this was found, so no money moved at the
wrong price. These tests exist so that stays true.
"""
from __future__ import annotations

import sqlite3

import pytest

from warden.marketplace.clearing import ClearingEngine
from warden.tests.marketplace_schema import create_marketplace_schema, seed_negotiation


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "mkt.db")
    create_marketplace_schema(path)
    seed_negotiation(path, "neg-win", buyer_agent="buyer-1", status="active", price=250.0)
    seed_negotiation(path, "neg-lose", buyer_agent="buyer-1", status="active", price=90.0)
    return path


class TestClearingUsesTheRealPrice:
    def test_fee_and_net_are_derived_from_the_negotiated_price(self, db):
        """The regression that matters: a real price, not $0.00."""
        rec = ClearingEngine(db_path=db).clear("neg-win", "buyer-1")

        assert rec.platform_fee_usd > 0, (
            "a cleared trade charged no platform fee — this is the $0.00 "
            "settlement the wrong column name produced"
        )
        assert rec.seller_net_usd > 0
        # fee + net reconstructs the agreed price exactly (Decimal math).
        assert round(rec.platform_fee_usd + rec.seller_net_usd, 6) == 250.0

    def test_authorisation_sees_the_real_amount(self, db, monkeypatch):
        """FT-6 must judge the trade's actual size.

        Authorising $0.00 is not a conservative default — it is the amount most
        likely to pass any budget or autonomy check ever written.
        """
        seen: list[float] = []

        def _spy(tenant_id, agent_id, action, amount_usd, **kw):
            seen.append(amount_usd)
            class _R:
                verdict = "ALLOW"
                reasons: list[str] = []
            return _R()

        monkeypatch.setattr("warden.payments.authorize.authorize_payment", _spy)
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")

        ClearingEngine(db_path=db).clear("neg-win", "buyer-1")
        assert seen == [250.0], f"authorisation ran against {seen}, not the agreed price"


class TestClearingRefusesToSettleBlind:
    def test_unknown_negotiation_raises_instead_of_clearing_free(self, db):
        with pytest.raises(ValueError, match="no price to clear"):
            ClearingEngine(db_path=db).clear("neg-does-not-exist", "buyer-1")

    def test_a_failing_price_query_raises_instead_of_clearing_free(self, db):
        """The exact shape of the original bug: the SELECT itself errors.

        A missing column raised `OperationalError`, the bare `except` turned it
        into `0.0`, and the trade settled for nothing. Dropping the table
        reproduces that failure mode without depending on a column name.
        """
        engine = ClearingEngine(db_path=db)
        con = sqlite3.connect(db)
        try:
            con.execute("DROP TABLE marketplace_negotiations")
            con.commit()
        finally:
            con.close()

        with pytest.raises(ValueError, match="cannot read the agreed price"):
            engine.clear("neg-win", "buyer-1")

    def test_a_refused_clearing_writes_no_record(self, db):
        with pytest.raises(ValueError):
            ClearingEngine(db_path=db).clear("neg-does-not-exist", "buyer-1")
        con = sqlite3.connect(db)
        try:
            n = con.execute("SELECT COUNT(*) FROM marketplace_clearing_log").fetchone()[0]
        finally:
            con.close()
        assert n == 0


class TestLosingNegotiationsAreActuallyRejected:
    def test_loser_is_marked_cleared_by_market(self, db):
        rec = ClearingEngine(db_path=db).clear("neg-win", "buyer-1")
        assert rec.rejected_neg_ids == ["neg-lose"]

        con = sqlite3.connect(db)
        try:
            status = con.execute(
                "SELECT status FROM marketplace_negotiations WHERE negotiation_id='neg-lose'"
            ).fetchone()[0]
        finally:
            con.close()
        assert status == "cleared_by_market", (
            "the losing negotiation stayed open — it remains eligible to clear "
            "a second time, which is exactly what _reject_losers prevents"
        )

    def test_another_buyers_negotiation_is_untouched(self, db):
        seed_negotiation(db, "neg-other", buyer_agent="buyer-2", status="active", price=10.0)
        rec = ClearingEngine(db_path=db).clear("neg-win", "buyer-1")
        assert "neg-other" not in rec.rejected_neg_ids


class TestUnscopedAnalyticsQueryIsRejected:
    """`_confused_deputy_check` promised this and only the promise existed."""

    def test_unscoped_read_of_an_agent_table_is_refused(self):
        from warden.marketplace.api import _confused_deputy_check

        err = _confused_deputy_check(
            "SELECT * FROM marketplace_escrow", "did:shadow:me"
        )
        assert err is not None and "without scoping" in err

    def test_scoped_read_is_allowed(self):
        from warden.marketplace.api import _confused_deputy_check

        assert _confused_deputy_check(
            "SELECT * FROM marketplace_escrow WHERE buyer_agent = 'did:shadow:me'",
            "did:shadow:me",
        ) is None

    def test_foreign_literal_still_rejected(self):
        from warden.marketplace.api import _confused_deputy_check

        err = _confused_deputy_check(
            "SELECT * FROM marketplace_escrow WHERE buyer_agent = 'did:shadow:you'",
            "did:shadow:me",
        )
        assert err is not None and "did:shadow:you" in err

    def test_query_touching_no_agent_table_needs_no_scope(self):
        from warden.marketplace.api import _confused_deputy_check

        assert _confused_deputy_check(
            "SELECT COUNT(*) FROM marketplace_clearing_log", "did:shadow:me"
        ) is None
