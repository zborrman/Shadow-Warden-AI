"""
FT-6 Phase C readiness — `warden/finops/order_recon.py`.

Phase C re-points readers at `marketplace_purchases`. Nothing measured whether
the Phase B mirror actually agrees with the source of truth, so the gate was a
judgement call over three fail-soft dual writes whose failures were logged at
DEBUG and counted nowhere.

These tests pin the three ways a mirror row can be wrong (missing / mismatched
/ orphaned), the one status divergence that is *correct* (a receipted commerce
order is mirrored as PAID on purpose), and that an empty system reports
`nothing_to_check` rather than readiness.
"""
from __future__ import annotations

import json

import pytest

from warden.business_community.agentic_commerce import ap2
from warden.business_community.agentic_commerce import service as commerce
from warden.finops import order_recon
from warden.m2m_store import inventory as m2m
from warden.marketplace import listing
from warden.observability import COUNTED, NOT_AVAILABLE, NOTHING_TO_CHECK


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """Isolate all three DBs.

    Each module resolves its path differently and none of them is a plain
    module constant you can set: m2m goes through `_get_db_path()` (env var
    M2M_STORE_DB_PATH via `data_path`), commerce reads a module `_DB_PATH` its
    `_conn` closes over, and the mirror lives in marketplace. A `setattr(...,
    raising=False)` on a name a module never reads is the isolation failure
    this project has hit repeatedly — it succeeds silently and the test then
    runs against the shared /tmp database.
    """
    monkeypatch.setattr(listing, "_DB_PATH", str(tmp_path / "mkt.db"))
    monkeypatch.setenv("M2M_STORE_DB_PATH", str(tmp_path / "m2m.db"))
    monkeypatch.setattr(commerce, "_DB_PATH", str(tmp_path / "commerce.db"))
    monkeypatch.setattr(ap2, "_DB_PATH", str(tmp_path / "commerce.db"))


def _seed_source(table: str, conn_factory, order_id: str, payload: dict) -> None:
    with conn_factory() as con:
        con.execute(
            f"INSERT OR REPLACE INTO {table} (id, data_json, created_at) VALUES (?,?,?)"  # noqa: S608
            if table == "m2m_orders"
            else f"INSERT OR REPLACE INTO {table} "  # noqa: S608
                 "(id, tenant_id, mandate_id, data_json, created_at) VALUES (?,?,?,?,?)",
            (order_id, json.dumps(payload), "2026-08-14T00:00:00Z")
            if table == "m2m_orders"
            else (order_id, "t1", "m1", json.dumps(payload), "2026-08-14T00:00:00Z"),
        )


def _seed_m2m(order_id: str, **payload) -> None:
    _seed_source("m2m_orders", m2m._conn, order_id, payload)


def _seed_commerce(order_id: str, **payload) -> None:
    _seed_source("commerce_orders", commerce._conn, order_id, payload)


class TestEmptySystem:
    def test_nothing_to_check_is_not_readiness(self, wired):
        rep = order_recon.order_mirror_drift()
        assert rep["evidence"] == NOTHING_TO_CHECK
        assert rep["orders_checked"] == 0
        assert rep["ok"] is True  # narrow meaning: nothing disagreed

        gate = order_recon.phase_c_ready()
        assert gate["ready"] is False
        assert "no orders were compared" in gate["reason"]


class TestAgreement:
    def test_a_mirrored_order_reconciles_clean(self, wired):
        _seed_m2m("o1", status="shipped", total=12.50)
        listing.upsert_mirrored_order(
            "m2m_store", "o1", status="shipped", price_paid=12.50,
        )
        rep = order_recon.order_mirror_drift()
        assert rep["evidence"] == COUNTED
        assert rep["orders_checked"] == 1
        assert rep["drifted"] == 0
        assert order_recon.phase_c_ready()["ready"] is True

    def test_float_noise_within_a_cent_is_not_drift(self, wired):
        _seed_m2m("o1", status="paid", total=12.499999999)
        listing.upsert_mirrored_order("m2m_store", "o1", status="paid", price_paid=12.5)
        assert order_recon.order_mirror_drift()["mismatched"] == 0


class TestTheThreeWaysAMirrorIsWrong:
    def test_a_dropped_dual_write_shows_as_missing(self, wired):
        """Exactly what the three fail-soft `except` sites produce."""
        _seed_m2m("o1", status="paid", total=5.0)  # mirror never written

        rep = order_recon.order_mirror_drift()
        assert rep["missing"] == 1
        assert rep["ok"] is False
        assert rep["details"][0]["problem"] == "missing"
        assert order_recon.phase_c_ready()["ready"] is False

    def test_status_disagreement_is_mismatched(self, wired):
        _seed_m2m("o1", status="shipped", total=5.0)
        listing.upsert_mirrored_order("m2m_store", "o1", status="pending", price_paid=5.0)

        rep = order_recon.order_mirror_drift()
        assert rep["mismatched"] == 1
        assert "status" in rep["details"][0]["detail"]

    def test_amount_disagreement_is_mismatched(self, wired):
        _seed_m2m("o1", status="paid", total=99.0)
        listing.upsert_mirrored_order("m2m_store", "o1", status="paid", price_paid=5.0)

        rep = order_recon.order_mirror_drift()
        assert rep["mismatched"] == 1
        assert "amount" in rep["details"][0]["detail"]

    def test_a_mirror_row_with_no_source_is_orphaned(self, wired):
        listing.upsert_mirrored_order("m2m_store", "ghost", status="paid", price_paid=1.0)

        rep = order_recon.order_mirror_drift()
        assert rep["orphaned"] == 1
        assert rep["details"][0]["order_id"] == "ghost"
        assert order_recon.phase_c_ready()["ready"] is False


class TestTheReceiptException:
    """`ap2.py` upserts status=PAID onto the order's own purchase_id."""

    def test_a_receipted_order_mirrored_as_paid_is_not_drift(self, wired):
        _seed_commerce("c1", status="pending", total=7.0)
        listing.upsert_mirrored_order("agentic_commerce", "c1", status="PAID", price_paid=7.0)
        with commerce._conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO commerce_receipts(id, order_id, data_json, created_at) "
                "VALUES (?,?,?,?)",
                ("r1", "c1", "{}", "2026-08-14T00:00:00Z"),
            )

        rep = order_recon.order_mirror_drift()
        assert rep["mismatched"] == 0, rep["details"]
        assert rep["orders_checked"] == 1

    def test_paid_without_a_receipt_is_still_drift(self, wired):
        _seed_commerce("c1", status="pending", total=7.0)
        listing.upsert_mirrored_order("agentic_commerce", "c1", status="PAID", price_paid=7.0)

        rep = order_recon.order_mirror_drift()
        assert rep["mismatched"] == 1


class TestFailSoft:
    def test_an_unreadable_mirror_is_not_reported_as_agreement(self, wired, monkeypatch):
        _seed_m2m("o1", status="paid", total=5.0)

        def _boom(*a, **kw):
            raise RuntimeError("mirror db down")
        monkeypatch.setattr(listing, "_conn", _boom)

        rep = order_recon.order_mirror_drift()  # must not raise
        assert rep["evidence"] == NOT_AVAILABLE
        assert rep["orders_checked"] == 0
        assert order_recon.phase_c_ready()["ready"] is False

    def test_corrupt_source_json_counts_as_unreadable_not_checked(self, wired):
        with m2m._conn() as con:
            con.execute(
                "INSERT INTO m2m_orders (id, data_json, created_at) VALUES (?,?,?)",
                ("o1", "{not json", "2026-08-14T00:00:00Z"),
            )
        rep = order_recon.order_mirror_drift()
        assert rep["unreadable"] == 1
        assert rep["orders_checked"] == 0
        assert order_recon.phase_c_ready()["ready"] is False


class TestJob:
    @pytest.fixture
    def alerts(self, monkeypatch):
        from warden.workers import order_recon_job as job
        sent: list[str] = []
        monkeypatch.setattr(job, "send_alert", lambda msg, **kw: sent.append(msg))
        return sent

    def test_drift_alerts(self, wired, alerts):
        from warden.workers import order_recon_job as job

        _seed_m2m("o1", status="paid", total=5.0)  # never mirrored
        rep = job.run_order_mirror_reconciliation()

        assert rep["missing"] == 1
        assert len(alerts) == 1
        assert "missing" in alerts[0]

    def test_nothing_to_reconcile_is_quiet(self, wired, alerts):
        from warden.workers import order_recon_job as job

        rep = job.run_order_mirror_reconciliation()
        assert rep["evidence"] == NOTHING_TO_CHECK
        assert alerts == []

    def test_a_check_that_could_not_run_alerts(self, wired, alerts, monkeypatch):
        from warden.workers import order_recon_job as job

        _seed_m2m("o1", status="paid", total=5.0)

        def _boom(*a, **kw):
            raise RuntimeError("mirror db down")
        monkeypatch.setattr(listing, "_conn", _boom)

        job.run_order_mirror_reconciliation()
        assert len(alerts) == 1
        assert "compared nothing" in alerts[0]

    @pytest.mark.asyncio
    async def test_arq_entry_point(self, wired, alerts):
        from warden.workers import order_recon_job as job

        result = await job.nightly_order_mirror_recon(ctx={})
        assert result["evidence"] == NOTHING_TO_CHECK


class TestOrphansAreEvidence:
    def test_an_orphan_with_no_source_rows_still_counts_as_observed(self, wired):
        """Both sides were read and found to disagree — that is a comparison.

        Reporting `nothing_to_check` beside a nonzero orphan count would be the
        same ok-by-vacuity confusion this vocabulary exists to end.
        """
        listing.upsert_mirrored_order("m2m_store", "ghost", status="paid", price_paid=1.0)

        rep = order_recon.order_mirror_drift()
        assert rep["evidence"] == COUNTED
        assert rep["by_source"]["m2m_store"]["evidence"] == COUNTED
        assert rep["orphaned"] == 1
        assert order_recon.phase_c_ready()["ready"] is False
