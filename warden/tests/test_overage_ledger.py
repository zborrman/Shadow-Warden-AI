"""
Overage settlement (FM-7 follow-up).

BL-19 computed an overage every month and stopped there — collection was left to
an admin endpoint nothing called. These tests pin the two properties that make
closing that loop safe to turn on: settlement is idempotent per (tenant, period),
and money only moves when an operator has explicitly enabled it.
"""
from __future__ import annotations

import pytest

from warden.billing import overage_ledger as ol


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "overage.db")
    monkeypatch.setenv("OVERAGE_LEDGER_DB_PATH", path)
    monkeypatch.setattr(ol, "_DB_PATH", path)
    return path


def _row(tenant="t1", requests=12_500, turns=0, charge=6.25) -> dict:
    return {
        "tenant_id": tenant,
        "plan": "pro",
        "overage_requests": requests,
        "overage_turns": turns,
        "request_charge_usd": 6.25,
        "turn_charge_usd": round(charge - 6.25, 4),
        "charge_usd": charge,
    }


# ── Idempotency ───────────────────────────────────────────────────────────────

class TestIdempotency:
    def test_second_settlement_of_a_period_does_not_double_charge(self, db):
        first = ol.settle(_row(), period="2026-08", db_path=db)
        second = ol.settle(_row(), period="2026-08", db_path=db)

        assert first["idempotent"] is False
        assert second["idempotent"] is True
        assert second["total_usd"] == first["total_usd"]
        assert len(ol.list_period("2026-08", db_path=db)) == 1

    def test_a_new_period_is_a_new_charge(self, db):
        ol.settle(_row(), period="2026-08", db_path=db)
        nxt = ol.settle(_row(), period="2026-09", db_path=db)
        assert nxt["idempotent"] is False
        assert len(ol.list_period("2026-09", db_path=db)) == 1

    def test_a_changed_amount_never_overwrites_a_settled_period(self, db):
        """A re-run with a bigger number must not silently re-bill the month."""
        ol.settle(_row(charge=6.25), period="2026-08", db_path=db)
        again = ol.settle(_row(charge=99.0), period="2026-08", db_path=db)
        assert again["total_usd"] == 6.25
        assert again["idempotent"] is True

    def test_settle_requires_a_tenant(self, db):
        with pytest.raises(ValueError):
            ol.settle({"charge_usd": 1.0}, period="2026-08", db_path=db)


# ── Enforcement is a deliberate posture decision ──────────────────────────────

class TestEnforcementFlag:
    def test_default_is_dry_run(self, db, monkeypatch):
        monkeypatch.delenv("OVERAGE_CHARGE_ENFORCED", raising=False)
        rec = ol.settle(_row(), period="2026-08", db_path=db)
        assert ol.charge_enforced() is False
        assert rec["status"] == ol.STATUS_COMPUTED
        assert rec["provider_ref"] == ""

    def test_nothing_owed_is_skipped_not_charged(self, db, monkeypatch):
        monkeypatch.setenv("OVERAGE_CHARGE_ENFORCED", "true")
        rec = ol.settle(_row(requests=0, charge=0.0), period="2026-08", db_path=db)
        assert rec["status"] == ol.STATUS_SKIPPED
        assert rec["total_usd"] == 0.0

    def test_enforced_without_a_provider_records_failed(self, db, monkeypatch):
        """An uncollectable charge must be visible, not silently 'charged'."""
        monkeypatch.setenv("OVERAGE_CHARGE_ENFORCED", "true")
        monkeypatch.delenv("LEMONSQUEEZY_API_KEY", raising=False)
        monkeypatch.setattr("warden.billing.overage.OVERAGE_WEBHOOK_URL", "")
        rec = ol.settle(_row(), period="2026-08", db_path=db)
        assert rec["status"] == ol.STATUS_FAILED
        assert "no billing provider" in rec["detail"]

    def test_enforced_with_a_webhook_presents_the_charge(self, db, monkeypatch):
        monkeypatch.setenv("OVERAGE_CHARGE_ENFORCED", "true")
        monkeypatch.setattr("warden.billing.overage.OVERAGE_WEBHOOK_URL", "https://x.test/hook")
        fired: list[tuple] = []
        monkeypatch.setattr(
            "warden.billing.overage._fire_overage_webhook",
            lambda *a, **k: fired.append(a),
        )
        rec = ol.settle(_row(), period="2026-08", db_path=db)
        assert rec["status"] == ol.STATUS_CHARGED
        assert rec["provider_ref"] == "webhook"
        assert len(fired) == 1

    def test_a_provider_error_records_failed_and_does_not_raise(self, db, monkeypatch):
        monkeypatch.setenv("OVERAGE_CHARGE_ENFORCED", "true")
        monkeypatch.setattr("warden.billing.overage.OVERAGE_WEBHOOK_URL", "https://x.test/hook")

        def _boom(*_a, **_k):
            raise RuntimeError("provider down")
        monkeypatch.setattr("warden.billing.overage._fire_overage_webhook", _boom)

        rec = ol.settle(_row(), period="2026-08", db_path=db)
        assert rec["status"] == ol.STATUS_FAILED
        assert "webhook error" in rec["detail"]


# ── What the ledger stores ────────────────────────────────────────────────────

class TestRecordContents:
    def test_requests_and_turns_are_stored_separately(self, db):
        rec = ol.settle(_row(turns=40, charge=12.25), period="2026-08", db_path=db)
        assert rec["overage_requests"] == 12_500
        assert rec["overage_turns"] == 40
        assert rec["request_charge_usd"] == 6.25
        assert rec["turn_charge_usd"] == 6.0
        assert rec["total_usd"] == 12.25

    def test_period_listing_sorts_by_amount(self, db):
        ol.settle(_row(tenant="small", charge=1.0), period="2026-08", db_path=db)
        ol.settle(_row(tenant="big", charge=50.0), period="2026-08", db_path=db)
        rows = ol.list_period("2026-08", db_path=db)
        assert [r["tenant_id"] for r in rows] == ["big", "small"]

    def test_missing_charge_reads_as_none(self, db):
        assert ol.get_charge("nobody", "2026-08", db_path=db) is None
