"""warden/tests/test_alerts_describe_something.py — an alert must be able to be wrong.

Companion to test_alert_metrics_have_writers.py, which asks whether a metric an
alert queries has a producer at all. This file asks the next question: given
that it has one, can the rule reach both verdicts?

Three rules on prod could not, in opposite directions, and all three shipped
looking correct.

*Fires forever.* `histogram_quantile` over a zero rate returns NaN, and the
threshold evaluator reads NaN as breaching. So the two /filter latency rules
sent to the notifier once a minute, continuously, to report that nobody had
called the gateway — 0 requests/s, 40 in the counter's lifetime, P99 = NaN.
`noDataState: OK` does not catch this, which is the part worth remembering:
there IS data. The bucket series exist and are all zero. Only a traffic guard
distinguishes "slow" from "idle".

*Never fires.* `Host disk usage above 80%` queried node-exporter, which is
profile-gated off and had never once started in production —
`node_filesystem_avail_bytes` had zero series, ever — and carried
`noDataState: OK`, so no data read as healthy. It could not have fired at any
disk level since it was written, on a 38 GB volume the deploy prunes weekly
because it fills.

A check that cannot fail and an alert that always fires are the same defect
wearing opposite masks, and the same rule file held both.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_ALERTS = _ROOT / "grafana" / "provisioning" / "alerting" / "warden_alerts.yml"
_COMPOSE = _ROOT / "docker-compose.yml"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"


def _rules() -> list[dict]:
    if not _ALERTS.exists():
        pytest.skip("alerting provisioning not present in this checkout")
    doc = yaml.safe_load(_ALERTS.read_text(encoding="utf-8"))
    out: list[dict] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            if node.get("uid") and node.get("data"):
                out.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(doc)
    return out


@pytest.fixture(scope="module")
def rules() -> list[dict]:
    return _rules()


def _exprs(rule: dict) -> str:
    return " ".join(q.get("model", {}).get("expr", "") or "" for q in rule.get("data", []))


def _has_traffic_guard(expr: str) -> bool:
    """A quantile is only meaningful when the underlying counter is moving."""
    return bool(re.search(r"_count\b[^)]*\}?\s*\[[^\]]+\]\s*\)\s*\)?\s*>\s*0", expr)) or (
        "_count" in expr and "> 0" in expr
    )


def test_quantile_alerts_are_guarded_on_traffic(rules: list[dict]) -> None:
    unguarded = [
        rule["uid"]
        for rule in rules
        if "histogram_quantile" in _exprs(rule) and not _has_traffic_guard(_exprs(rule))
    ]
    assert not unguarded, (
        "These rules take a quantile without requiring the underlying counter to "
        "be moving: " + ", ".join(unguarded) + ". With no traffic every bucket "
        "rate is 0, histogram_quantile returns NaN, and the threshold evaluator "
        "treats NaN as a breach — the rule fires continuously to say the service "
        "was idle. Add `and sum(rate(<metric>_count{...}[<window>])) > 0`."
    )


def test_the_disk_alert_can_still_fail(rules: list[dict]) -> None:
    """
    The single consumer of node-exporter. It spent its whole life unable to
    fire, so this pins both halves of the repair: the metric is collected, and
    its absence is no longer reported as healthy.
    """
    disk = [r for r in rules if r.get("uid") == "warden-host-disk-high"]
    assert disk, "warden-host-disk-high is gone — re-check this guard"
    assert disk[0].get("noDataState") == "NoData", (
        "The disk alert is back on noDataState: OK. Its metric comes from a "
        "profile-gated exporter, so 'no data' is the exact symptom of the "
        "exporter not running — and mapping that to OK is what kept the alert "
        "silent at every disk level since it was written."
    )


def test_profile_gated_exporters_are_started_in_production() -> None:
    """
    node-exporter and cadvisor are behind the `monitoring` profile for a real
    reason (Windows/WSL2 lacks the mount propagation), so the profile is
    activated at deploy time rather than removed. If that export goes, the
    exporters stop running in prod and the disk alert loses its data again —
    silently, because nothing else consumes them.
    """
    if not _COMPOSE.exists() or not _CI.exists():
        pytest.skip("compose or workflow not present in this checkout")

    compose = _COMPOSE.read_text(encoding="utf-8")
    gated = [
        name
        for name in ("node-exporter", "cadvisor")
        if re.search(rf"^  {re.escape(name)}:", compose, re.M)
    ]
    if not gated:
        pytest.skip("exporters not declared in this compose file")

    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    deploy = next(
        s["run"]
        for s in workflow["jobs"]["deploy"]["steps"]
        if s.get("name") == "Deploy via SSH"
    )
    assert "COMPOSE_PROFILES=monitoring" in deploy, (
        "The deploy no longer activates the `monitoring` compose profile, so "
        f"{', '.join(gated)} will not start in production. Prometheus scrapes "
        "them regardless and they simply sit `down` — which is how "
        "node_filesystem_avail_bytes had zero series for the life of the "
        "cluster while a disk alert quietly reported OK."
    )
