"""
warden/tests/test_grafana_metrics_resolve.py — OB-6 observability guard.

**A Grafana query naming a metric nothing emits renders as an empty panel, and
an empty panel reads as calm rather than blind.** That is the same defect class
as the journal ghost fields, the ghost schema and the $0.00 clearing: a reader
querying a name no writer produces, reporting the silence as health.

Measured 2026-08-14, before OB-2, `warden_unified.json` queried four metrics
with no producer anywhere in the tree:

    warden_filter_duration_seconds_bucket   never defined
    warden_bypass_total                     never defined
    warden_circuit_breaker_open             never defined
    warden_shadow_bans_total                plural typo of warden_shadow_ban_total

Every one of those panels had been showing "No data" since the dashboard was
written, on the board titled "Unified Service Health".

Two directions, deliberately enforced differently:

  Grafana -> code   HARD FAIL. A dashboard or alert may not query a metric that
                    has no producer. This is at zero and must stay there.

  code -> Grafana   RATCHET. Metrics that are instrumented but graphed nowhere
                    are real waste — `warden_ledger_recon_drift_usd` (money
                    correctness) and the whole FM-7 FinOps set were emitting
                    into a store nobody queried — but retiring them is OB-8,
                    not a reason to block a PR today. The count may only drop.

Regenerate the orphan baseline after a genuine reduction (an increase fails
before it can write):

    UPDATE_GRAFANA_ORPHAN_BASELINE=1 pytest warden/tests/test_grafana_metrics_resolve.py
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_GRAFANA = _ROOT / "grafana"
_BASELINE = Path(__file__).parent / "grafana_orphan_metrics_baseline.json"

#: Modules that construct Prometheus metric singletons. Two registries exist and
#: they share no naming convention — which is how `warden_shadow_ban_total` came
#: to be queried in the plural.
_METRIC_MODULES = (
    _ROOT / "warden" / "metrics.py",
    _ROOT / "warden" / "voice" / "metrics.py",
)

#: Sample suffixes prometheus_client derives from a single registered metric.
#: A Histogram named `x_seconds` exposes `x_seconds_bucket/_sum/_count`; a
#: Counter exposes `_total` and `_created`.
_SAMPLE_SUFFIXES = ("_bucket", "_sum", "_count", "_created", "_total")

_NAME_IN_CODE = re.compile(r'"(warden_[a-z0-9_]+)"')
_NAME_IN_GRAFANA = re.compile(r"(warden_[a-z0-9_]+)")

#: A Counter declaration and the name on its next line. prometheus_client never
#: exports the bare name of a Counter — only `<name>_total` (plus `_created`) —
#: so a dashboard querying the base name is blind in exactly the way this file
#: exists to catch, while still passing the producer check above.
_COUNTER_DECL = re.compile(r"\bCounter\(\s*\n?\s*\"(warden_[a-z0-9_]+)\"")


def _grafana_files() -> list[Path]:
    files = sorted(_GRAFANA.glob("dashboards/*.json")) + sorted(
        _GRAFANA.glob("provisioning/alerting/*.yml")
    )
    assert files, f"no Grafana dashboards or alert files under {_GRAFANA}"
    return files


def _defined_metrics() -> set[str]:
    names: set[str] = set()
    for mod in _METRIC_MODULES:
        assert mod.exists(), f"metric module missing: {mod}"
        names |= set(_NAME_IN_CODE.findall(mod.read_text(encoding="utf-8")))
    return names


def _counter_base_names() -> set[str]:
    """Names registered as a Counter, minus any that already end in `_total`.

    `Counter("warden_x_total")` is exported as `warden_x_total`, so the base name
    *is* the series and querying it is correct. `Counter("warden_x")` is exported
    only as `warden_x_total`, so querying `warden_x` never resolves.
    """
    names: set[str] = set()
    for mod in _METRIC_MODULES:
        for name in _COUNTER_DECL.findall(mod.read_text(encoding="utf-8")):
            if not name.endswith("_total"):
                names.add(name)
    return names


def _alert_group_names() -> set[str]:
    """Alert *group* names also match `warden_*` — derive them, never hardcode.

    A hardcoded exclusion list silently starts skipping real metric names the
    moment somebody adds a group, which is precisely the kind of quiet drift
    this file exists to catch.
    """
    groups: set[str] = set()
    for path in sorted(_GRAFANA.glob("provisioning/alerting/*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for group in doc.get("groups") or []:
            name = group.get("name")
            if name:
                groups.add(str(name))
    return groups


def _queried_metrics() -> dict[str, set[str]]:
    """Every `warden_*` token used in Grafana, mapped to the files using it."""
    ignore = _alert_group_names()
    found: dict[str, set[str]] = {}
    for path in _grafana_files():
        for name in _NAME_IN_GRAFANA.findall(path.read_text(encoding="utf-8")):
            if name in ignore:
                continue
            found.setdefault(name, set()).add(path.name)
    return found


def _resolves(queried: str, defined: set[str]) -> bool:
    if queried in defined:
        return True
    # `warden_x_seconds_bucket` resolves to a Histogram registered as
    # `warden_x_seconds`. Suffix-stripping, not prefix-matching: a bare
    # startswith() would let `warden_foo` satisfy a query for `warden_foobar`.
    return any(
        queried.endswith(suffix) and queried[: -len(suffix)] in defined
        for suffix in _SAMPLE_SUFFIXES
    )


def test_every_grafana_metric_has_a_producer() -> None:
    defined = _defined_metrics()
    dead = {
        name: sorted(files)
        for name, files in sorted(_queried_metrics().items())
        if not _resolves(name, defined)
    }
    assert not dead, (
        "Grafana queries metrics with no producer in warden/:\n"
        + "\n".join(f"  {name}  <- {', '.join(files)}" for name, files in dead.items())
        + "\n\nSuch a panel renders 'No data' forever and an alert on it can never "
        "fire — indistinguishable from a healthy system. Fix the name in Grafana, "
        "or add the metric to warden/metrics.py (or warden/voice/metrics.py). "
        "Check for a singular/plural slip first: that is how warden_shadow_bans_total "
        "shipped against the real warden_shadow_ban_total."
    )


def test_no_grafana_query_uses_a_counter_base_name() -> None:
    """P0. A Counter's base name is never an exported series — only `_total` is.

    `warden_marketplace_trade_volume_usd` is declared as a Counter, so Prometheus
    only ever holds `warden_marketplace_trade_volume_usd_total`. Both trade-volume
    panels on the marketplace board queried the base name and had therefore been
    rendering "No data" since the board was written — on the one panel that
    reports whether the marketplace has moved any money at all.

    The producer check above cannot catch this: the name *is* in metrics.py, so it
    resolves. Only the metric's type reveals that the series can never exist.
    """
    counters = _counter_base_names()
    offenders = {
        name: sorted(files)
        for name, files in sorted(_queried_metrics().items())
        if name in counters
    }
    assert not offenders, (
        "Grafana queries the base name of a Counter, which Prometheus never "
        "exports:\n"
        + "\n".join(
            f"  {name}  ->  {name}_total   <- {', '.join(files)}"
            for name, files in offenders.items()
        )
        + "\n\nAppend _total to the query. Until then the panel reads 'No data' "
        "forever, which on a business metric is indistinguishable from a genuine "
        "zero — and a genuine zero is information we need."
    )


def test_orphan_metric_count_does_not_grow() -> None:
    defined = _defined_metrics()
    queried = _queried_metrics()
    orphans = sorted(
        name
        for name in defined
        if not any(_resolves(q, {name}) or q == name for q in queried)
    )
    current = {"total": len(orphans), "metrics": orphans}

    regenerate = os.getenv("UPDATE_GRAFANA_ORPHAN_BASELINE") == "1"
    if regenerate or not _BASELINE.exists():
        _BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        if regenerate:
            pytest.skip(f"orphan-metric baseline regenerated: total={len(orphans)}")

    base = json.loads(_BASELINE.read_text(encoding="utf-8"))
    new = sorted(set(orphans) - set(base["metrics"]))
    assert len(orphans) <= base["total"], (
        f"Instrumented-but-unobserved metrics rose: {len(orphans)} > baseline "
        f"{base['total']}. New: {new}\n"
        "A metric nobody graphs or alerts on is cost without benefit — it was "
        "warden_ledger_recon_drift_usd and the entire FM-7 FinOps set sitting in a "
        "store no query read. Add a panel or a rule (see the OB-8 dashboards), or "
        "drop the metric. After a genuine reduction: "
        "UPDATE_GRAFANA_ORPHAN_BASELINE=1 pytest "
        "warden/tests/test_grafana_metrics_resolve.py"
    )
