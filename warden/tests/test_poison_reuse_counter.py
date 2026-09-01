"""
warden/tests/test_poison_reuse_counter.py

#428 removed a duplicate MiniLM encode from the poison guard by handing it the
brain's query vector. The reuse is conditional — the guard encodes for itself
whenever the vector does not belong to the exact content — and the fallback is
correct, silent, and indistinguishable from success.

That distinction cost an SSH session into the production container: the metric
showed `poison` still slow, the deployed code plainly contained the reuse, and
nothing on the outside could say whether the condition was firing. n=13 on a
cold process could not answer it either.

`warden_poison_embedding_reuse_total` answers it from the dashboard. These tests
check the label is the *decision*, not a constant — a counter that always
reports `yes` would be worse than none, because it would end the investigation
that found this in the first place.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("prometheus_client")

_MAIN = Path(__file__).resolve().parents[1] / "main.py"


def _labels_for(reused: str) -> float:
    from prometheus_client import REGISTRY

    value = REGISTRY.get_sample_value(
        "warden_poison_embedding_reuse_total", {"reused": reused}
    )
    return float(value or 0.0)


def test_the_counter_is_registered_with_the_reuse_label():
    from warden.metrics import POISON_EMBEDDING_REUSE_TOTAL

    assert hasattr(POISON_EMBEDDING_REUSE_TOTAL, "labels")


def test_all_three_outcomes_are_reachable():
    """
    Each label must correspond to a branch that can actually be taken. A label
    no code path reaches is the ghost-metric shape: it reads zero forever and
    looks like good news.
    """
    src = _MAIN.read_text(encoding="utf-8", errors="ignore")
    block = re.search(r"POISON_EMBEDDING_REUSE_TOTAL\.labels\((.*?)\)\.inc\(\)", src, re.S)
    assert block, "the counter is no longer incremented in the filter path"
    body = block.group(1)
    for outcome in ("yes", "no_vector", "text_differs"):
        assert f'"{outcome}"' in body, f"the {outcome} branch is gone"


def test_the_label_is_a_decision_not_a_constant():
    """The whole value of this counter is that it can say 'no'."""
    src = _MAIN.read_text(encoding="utf-8", errors="ignore")
    block = re.search(r"POISON_EMBEDDING_REUSE_TOTAL\.labels\((.*?)\)\.inc\(\)", src, re.S)
    body = block.group(1)
    assert "if" in body and "else" in body, (
        "the reuse label no longer depends on anything — it would report the "
        "same value whether the optimisation worked or not"
    )
    assert "_brain_text == redact_result.text" in body, (
        "the label no longer reflects the actual reuse condition in check_async"
    )


def test_it_is_counted_before_the_call_not_inside_the_guard():
    """
    The condition lives in `check_async`, but the counter belongs to the caller:
    the guard returns early when disabled, and a counter inside it would stop
    recording exactly when the pipeline still pays for the stage.
    """
    src = _MAIN.read_text(encoding="utf-8", errors="ignore")
    counter_at = src.index("POISON_EMBEDDING_REUSE_TOTAL.labels")
    call_at = src.index("_poison_guard.check_async(", counter_at - 4000)
    assert counter_at < call_at, "the counter must be incremented before the call"


class TestTheCounterMoves:
    """Registration proves nothing; these drive the real labels."""

    @pytest.mark.parametrize("outcome", ["yes", "no_vector", "text_differs"])
    def test_each_label_increments(self, outcome):
        from warden.metrics import POISON_EMBEDDING_REUSE_TOTAL

        before = _labels_for(outcome)
        POISON_EMBEDDING_REUSE_TOTAL.labels(reused=outcome).inc()
        assert _labels_for(outcome) == before + 1

    def test_the_labels_are_independent(self):
        from warden.metrics import POISON_EMBEDDING_REUSE_TOTAL

        before_no = _labels_for("no_vector")
        POISON_EMBEDDING_REUSE_TOTAL.labels(reused="yes").inc()
        assert _labels_for("no_vector") == before_no


def test_the_panel_reads_it():
    """An unread counter fails test_grafana_metrics_resolve; keep it read."""
    import json

    dash = json.loads(
        (Path(__file__).resolve().parents[2] / "grafana" / "dashboards" / "warden_overview.json")
        .read_text(encoding="utf-8")
    )
    exprs = [
        t.get("expr", "")
        for panel in dash["panels"]
        for t in panel.get("targets", [])
    ]
    assert any("warden_poison_embedding_reuse_total" in e for e in exprs), (
        "no panel reads the reuse counter"
    )
