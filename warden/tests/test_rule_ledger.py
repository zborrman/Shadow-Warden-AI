"""
warden/tests/test_rule_ledger.py
─────────────────────────────────
Unit tests for RuleLedger — the SQLite rule effectiveness ledger.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from warden.rule_ledger import FP_RETIRE_THRESHOLD, RETIRE_AFTER_DAYS, RuleLedger

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def ledger(tmp_path: Path) -> RuleLedger:
    """Return a fresh in-memory-equivalent ledger backed by a temp file."""
    rl = RuleLedger(db_path=tmp_path / "test_ledger.db")
    yield rl
    rl.close()


def _make_rule_id() -> str:
    return str(uuid.uuid4())


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _write(ledger: RuleLedger, rule_id: str = "", rule_type: str = "regex_pattern") -> str:
    rid = rule_id or _make_rule_id()
    ledger.write_rule(
        rule_id         = rid,
        source          = "evolution",
        created_at      = _iso(datetime.now(UTC)),
        pattern_snippet = "(?i)\\bjailbreak\\b",
        rule_type       = rule_type,
    )
    return rid


# ── write_rule ────────────────────────────────────────────────────────────────

class TestWriteRule:
    def test_basic_insert(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        rule = ledger.get_rule(rid)
        assert rule is not None
        assert rule["rule_id"] == rid
        assert rule["source"] == "evolution"
        assert rule["activation_count"] == 0
        assert rule["fp_reports"] == 0
        assert rule["status"] == "pending_review"
        assert rule["last_fired_at"] is None

    def test_idempotent(self, ledger: RuleLedger) -> None:
        """Second write_rule with same rule_id must not raise or duplicate."""
        rid = _write(ledger)
        _write(ledger, rule_id=rid)   # exact same id — INSERT OR IGNORE
        assert len(ledger.list_rules()) == 1

    def test_semantic_type(self, ledger: RuleLedger) -> None:
        rid = _write(ledger, rule_type="semantic_example")
        rule = ledger.get_rule(rid)
        assert rule["rule_type"] == "semantic_example"

    def test_unknown_rule_returns_none(self, ledger: RuleLedger) -> None:
        assert ledger.get_rule("nonexistent-id") is None


# ── increment ─────────────────────────────────────────────────────────────────

class TestIncrement:
    def test_increments_count(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        ledger.increment(rid)
        rule = ledger.get_rule(rid)
        assert rule["activation_count"] == 1

    def test_multiple_increments(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        for _ in range(5):
            ledger.increment(rid)
        assert ledger.get_rule(rid)["activation_count"] == 5

    def test_promotes_pending_to_active(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        assert ledger.get_rule(rid)["status"] == "pending_review"
        ledger.increment(rid)
        assert ledger.get_rule(rid)["status"] == "active"

    def test_does_not_downgrade_active(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        ledger.increment(rid)
        ledger.increment(rid)
        assert ledger.get_rule(rid)["status"] == "active"

    def test_sets_last_fired_at(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        assert ledger.get_rule(rid)["last_fired_at"] is None
        ledger.increment(rid)
        assert ledger.get_rule(rid)["last_fired_at"] is not None

    def test_noop_on_unknown_rule(self, ledger: RuleLedger) -> None:
        """increment() on a non-existent rule must not raise."""
        ledger.increment("ghost-rule-id")   # should not raise


# ── report_fp ─────────────────────────────────────────────────────────────────

class TestReportFp:
    def test_increments_fp_reports(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        assert ledger.report_fp(rid) is True
        assert ledger.get_rule(rid)["fp_reports"] == 1

    def test_returns_false_for_unknown(self, ledger: RuleLedger) -> None:
        assert ledger.report_fp("no-such-rule") is False

    def test_auto_retire_at_threshold(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        for _ in range(FP_RETIRE_THRESHOLD - 1):
            ledger.report_fp(rid)
        assert ledger.get_rule(rid)["status"] != "retired"
        ledger.report_fp(rid)   # this is the Nth report
        rule = ledger.get_rule(rid)
        assert rule["status"] == "retired"
        assert rule["fp_reports"] == FP_RETIRE_THRESHOLD

    def test_fp_count_accumulates(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        ledger.report_fp(rid)
        ledger.report_fp(rid)
        assert ledger.get_rule(rid)["fp_reports"] == 2


# ── retire_stale ──────────────────────────────────────────────────────────────

class TestRetireStale:
    def test_retires_old_unfired_rule(self, ledger: RuleLedger) -> None:
        old_ts = _iso(datetime.now(UTC) - timedelta(days=RETIRE_AFTER_DAYS + 1))
        ledger.write_rule(
            rule_id="stale-rule",
            source="evolution",
            created_at=old_ts,
            pattern_snippet="old pattern",
        )
        retired = ledger.retire_stale()
        assert retired == 1
        assert ledger.get_rule("stale-rule")["status"] == "retired"

    def test_does_not_retire_recent_rule(self, ledger: RuleLedger) -> None:
        _write(ledger)  # created_at = now
        retired = ledger.retire_stale()
        assert retired == 0

    def test_does_not_retire_fired_rule(self, ledger: RuleLedger) -> None:
        old_ts = _iso(datetime.now(UTC) - timedelta(days=RETIRE_AFTER_DAYS + 1))
        rid = _make_rule_id()
        ledger.write_rule(
            rule_id=rid,
            source="evolution",
            created_at=old_ts,
            pattern_snippet="active old pattern",
        )
        ledger.increment(rid)   # fired at least once
        retired = ledger.retire_stale()
        assert retired == 0
        assert ledger.get_rule(rid)["status"] == "active"

    def test_returns_zero_when_nothing_stale(self, ledger: RuleLedger) -> None:
        _write(ledger)
        assert ledger.retire_stale() == 0

    def test_multiple_stale_rules(self, ledger: RuleLedger) -> None:
        old_ts = _iso(datetime.now(UTC) - timedelta(days=RETIRE_AFTER_DAYS + 1))
        for i in range(3):
            ledger.write_rule(
                rule_id=f"stale-{i}",
                source="evolution",
                created_at=old_ts,
                pattern_snippet=f"stale pattern {i}",
            )
        assert ledger.retire_stale() == 3


# ── list_rules / get_active_regex_rules ───────────────────────────────────────

class TestQuery:
    def test_list_all(self, ledger: RuleLedger) -> None:
        for _ in range(3):
            _write(ledger)
        assert len(ledger.list_rules()) == 3

    def test_list_by_status(self, ledger: RuleLedger) -> None:
        rid_active = _write(ledger)
        ledger.increment(rid_active)        # promotes to active
        _write(ledger)                      # stays pending_review

        actives = ledger.list_rules(status="active")
        assert len(actives) == 1
        assert actives[0]["rule_id"] == rid_active

    def test_list_limit(self, ledger: RuleLedger) -> None:
        for _ in range(5):
            _write(ledger)
        assert len(ledger.list_rules(limit=3)) == 3

    def test_get_active_regex_rules_excludes_retired(self, ledger: RuleLedger) -> None:
        rid_active = _write(ledger, rule_type="regex_pattern")
        rid_retired = _write(ledger, rule_type="regex_pattern")
        # Retire via FP reports
        for _ in range(FP_RETIRE_THRESHOLD):
            ledger.report_fp(rid_retired)

        active = ledger.get_active_regex_rules()
        ids = [r["rule_id"] for r in active]
        assert rid_active in ids
        assert rid_retired not in ids

    def test_get_active_regex_rules_excludes_semantic(self, ledger: RuleLedger) -> None:
        _write(ledger, rule_type="semantic_example")
        active = ledger.get_active_regex_rules()
        assert active == []

    def test_empty_ledger(self, ledger: RuleLedger) -> None:
        assert ledger.list_rules() == []
        assert ledger.get_active_regex_rules() == []
