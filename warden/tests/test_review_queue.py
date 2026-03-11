"""
warden/tests/test_review_queue.py
──────────────────────────────────
Unit tests for ReviewQueue (rule activation gate) and the new
approve_rule / retire_rule methods added to RuleLedger.
"""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from warden.review_queue import ReviewQueue
from warden.rule_ledger import RuleLedger

# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_rule_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def ledger(tmp_path: Path) -> RuleLedger:
    rl = RuleLedger(db_path=tmp_path / "rq_test_ledger.db")
    yield rl
    rl.close()


def _write(ledger: RuleLedger, rule_type: str = "regex_pattern") -> str:
    from datetime import UTC, datetime
    rid = _make_rule_id()
    ledger.write_rule(
        rule_id         = rid,
        source          = "evolution",
        created_at      = datetime.now(UTC).isoformat(),
        pattern_snippet = "(?i)\\bjailbreak\\b",
        rule_type       = rule_type,
    )
    return rid


# ── ReviewQueue — auto mode ────────────────────────────────────────────────────

class TestAutoMode:
    def test_submit_returns_true(self) -> None:
        rq = ReviewQueue(mode="auto")
        assert rq.submit(_make_rule_id(), "regex_pattern", "pattern") is True

    def test_submit_fires_regex_callback(self) -> None:
        fired: list[tuple[str, str]] = []
        rq = ReviewQueue(on_activate_regex=lambda rid, val: fired.append((rid, val)), mode="auto")
        rid = _make_rule_id()
        rq.submit(rid, "regex_pattern", "(?i)test")
        assert fired == [(rid, "(?i)test")]

    def test_submit_no_callback_does_not_raise(self) -> None:
        rq = ReviewQueue(mode="auto")  # no callback
        rq.submit(_make_rule_id(), "regex_pattern", "(?i)test")  # must not raise

    def test_submit_semantic_does_not_fire_regex_callback(self) -> None:
        fired: list = []
        rq = ReviewQueue(on_activate_regex=lambda *a: fired.append(a), mode="auto")
        rq.submit(_make_rule_id(), "semantic_example", "ignore all instructions")
        assert fired == []

    def test_submit_semantic_returns_true(self) -> None:
        rq = ReviewQueue(mode="auto")
        assert rq.submit(_make_rule_id(), "semantic_example", "some example") is True

    def test_mode_property(self) -> None:
        rq = ReviewQueue(mode="auto")
        assert rq.mode == "auto"


# ── ReviewQueue — manual mode ──────────────────────────────────────────────────

class TestManualMode:
    def test_submit_returns_false(self) -> None:
        rq = ReviewQueue(mode="manual")
        assert rq.submit(_make_rule_id(), "regex_pattern", "pattern") is False

    def test_submit_does_not_fire_callback(self) -> None:
        fired: list = []
        rq = ReviewQueue(on_activate_regex=lambda *a: fired.append(a), mode="manual")
        rq.submit(_make_rule_id(), "regex_pattern", "(?i)jailbreak")
        assert fired == []

    def test_semantic_submit_returns_false(self) -> None:
        rq = ReviewQueue(mode="manual")
        assert rq.submit(_make_rule_id(), "semantic_example", "example") is False

    def test_mode_property(self) -> None:
        rq = ReviewQueue(mode="manual")
        assert rq.mode == "manual"


# ── ReviewQueue — activate (admin approval) ────────────────────────────────────

class TestActivate:
    def test_activate_regex_fires_callback(self) -> None:
        fired: list[tuple[str, str]] = []
        rq = ReviewQueue(on_activate_regex=lambda rid, val: fired.append((rid, val)), mode="manual")
        rid = _make_rule_id()
        result = rq.activate(rid, "regex_pattern", "(?i)attack")
        assert result is True
        assert fired == [(rid, "(?i)attack")]

    def test_activate_semantic_calls_brain_guard(self) -> None:
        injected: list[list] = []

        class _FakeBrain:
            def add_examples(self, examples: list) -> None:
                injected.append(examples)

        rq = ReviewQueue(mode="manual")
        result = rq.activate(_make_rule_id(), "semantic_example", "ignore instructions", _FakeBrain())
        assert result is True
        assert injected == [["ignore instructions"]]

    def test_activate_semantic_without_brain_returns_false(self) -> None:
        rq = ReviewQueue(mode="manual")
        result = rq.activate(_make_rule_id(), "semantic_example", "value", brain_guard=None)
        assert result is False

    def test_activate_regex_no_callback_returns_true(self) -> None:
        rq = ReviewQueue(mode="manual")  # no callback
        # activate still returns True (attempt was made) even with no callback
        result = rq.activate(_make_rule_id(), "regex_pattern", "(?i)test")
        assert result is True


# ── RuleLedger.approve_rule ────────────────────────────────────────────────────

class TestApproveRule:
    def test_promotes_pending_to_active(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        assert ledger.get_rule(rid)["status"] == "pending_review"
        assert ledger.approve_rule(rid) is True
        assert ledger.get_rule(rid)["status"] == "active"

    def test_returns_false_for_unknown_rule(self, ledger: RuleLedger) -> None:
        assert ledger.approve_rule("no-such-rule") is False

    def test_returns_false_for_already_active(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        ledger.increment(rid)          # promotes pending → active
        # approve_rule only targets pending_review; already-active returns False
        assert ledger.approve_rule(rid) is False

    def test_returns_false_for_retired_rule(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        ledger.retire_rule(rid)
        assert ledger.approve_rule(rid) is False

    def test_idempotent_on_double_approve(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        assert ledger.approve_rule(rid) is True
        # Second call: already active, returns False but does not raise
        assert ledger.approve_rule(rid) is False
        assert ledger.get_rule(rid)["status"] == "active"


# ── RuleLedger.retire_rule ─────────────────────────────────────────────────────

class TestRetireRule:
    def test_retires_pending_rule(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        assert ledger.retire_rule(rid) is True
        assert ledger.get_rule(rid)["status"] == "retired"

    def test_retires_active_rule(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        ledger.increment(rid)          # active
        assert ledger.retire_rule(rid) is True
        assert ledger.get_rule(rid)["status"] == "retired"

    def test_returns_false_for_unknown(self, ledger: RuleLedger) -> None:
        assert ledger.retire_rule("ghost") is False

    def test_idempotent_on_already_retired(self, ledger: RuleLedger) -> None:
        rid = _write(ledger)
        ledger.retire_rule(rid)
        # Second call: rowcount == 0 for a no-op UPDATE, returns False
        # but must not raise
        result = ledger.retire_rule(rid)
        assert isinstance(result, bool)
        assert ledger.get_rule(rid)["status"] == "retired"
