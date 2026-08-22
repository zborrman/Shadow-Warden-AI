"""
warden/tests/test_alert_metrics_have_writers.py — OB-F12 observability guard.

`test_grafana_metrics_resolve.py` already fails a build where Grafana queries a
metric name that is *defined* nowhere. This is the same defect one layer down:
a metric that is defined and then **written by nothing**.

prometheus_client exports a registered Gauge whether or not any code ever calls
`.set()` on it — at its zero value. So a declared-but-unwritten gauge is not an
empty panel an operator would notice. It is a confident number. The rule reading
it cannot tell that number from a measurement, and neither can the person
holding the pager.

Measured on production 2026-08-21:

    warden_community_peering_connections   declared in metrics.py, written by
                                           no code path anywhere in the tree

The critical rule "All community peerings lost" is `== 0` over that gauge, so it
had been firing continuously, on two instances (the gateway and the arq-worker
both import metrics.py, so both declare it and neither wrote it). It resolved to
`critical`, it was routed to PagerDuty, ntfy and Slack, and it never once
described a peering.

This is the class in [[journal_ghost_fields_class]] and [[ghost_schema_f8_ratchets]]
— a reader trusting a writer that does not exist — expressed in metrics.

HARD FAIL, and it is at zero. Only metrics some Grafana **alert rule** can page
on are covered: a dashboard panel showing a permanent 0 is waste, but it does
not wake anyone at 03:00, and the code -> Grafana direction is already ratcheted
by the orphan baseline in the sibling test.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_ALERTS = _ROOT / "grafana" / "provisioning" / "alerting" / "warden_alerts.yml"

#: Modules that construct Prometheus metric singletons.
_METRIC_MODULES = (
    _ROOT / "warden" / "metrics.py",
    _ROOT / "warden" / "voice" / "metrics.py",
)

#: Suffixes prometheus_client derives from one registered metric. A Histogram
#: `x_seconds` exposes `x_seconds_bucket/_sum/_count`; a Counter exposes
#: `_total`. An alert queries the derived name, the code declares the base.
_DERIVED_SUFFIXES = ("_bucket", "_sum", "_count", "_created", "_total")

#: What counts as a writer: any reference to the metric's symbol from
#: application code. Deliberately not `SYMBOL.set(` — the reconciliation job
#: hands the gauge to a helper (`_reconcile(..., gauge=LEDGER_RECON_DRIFT_USD)`)
#: and the write happens through the parameter name, so matching on the call
#: shape reports a live money-correctness metric as dead. Application code never
#: reads a prometheus metric — the scrape does that — so a reference from a
#: non-test module is a write path, and a metric referenced nowhere at all is
#: exactly what this test exists to catch.
_SYMBOL_REFERENCE = re.compile(r"\b([A-Z][A-Z0-9_]{3,})\b")

_DECLARATION = re.compile(
    r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*"
    r"(?:Gauge|Counter|Histogram|Summary|Info|Enum)\(\s*\n?\s*"
    r"[\"']([a-z][a-z0-9_]*)[\"']",
    re.MULTILINE,
)


def _symbol_by_metric_name() -> dict[str, str]:
    """metric name -> the module-level symbol it was assigned to."""
    mapping: dict[str, str] = {}
    for module in _METRIC_MODULES:
        if not module.exists():
            continue
        for symbol, name in _DECLARATION.findall(module.read_text(encoding="utf-8")):
            mapping[name] = symbol
    return mapping


def _metrics_queried_by_alerts() -> set[str]:
    """Every `warden_*` token appearing in an alert rule's PromQL."""
    rules = yaml.safe_load(_ALERTS.read_text(encoding="utf-8"))
    found: set[str] = set()
    for group in rules.get("groups", []):
        for rule in group.get("rules", []):
            for query in rule.get("data", []):
                expr = (query.get("model") or {}).get("expr")
                if isinstance(expr, str):
                    found.update(re.findall(r"\bwarden_[a-z0-9_]+\b", expr))
    return found


def _base_name(metric: str, known: set[str]) -> str:
    """Strip a prometheus-derived suffix back to the registered name."""
    if metric in known:
        return metric
    for suffix in _DERIVED_SUFFIXES:
        if metric.endswith(suffix) and metric[: -len(suffix)] in known:
            return metric[: -len(suffix)]
    return metric


def _source_files() -> list[Path]:
    skip_names = {module.name for module in _METRIC_MODULES}
    return [
        path
        for path in _ROOT.joinpath("warden").rglob("*.py")
        if path.name not in skip_names
        and "tests" not in path.parts
        and "testing" not in path.parts
    ]


def _referenced_symbols() -> set[str]:
    referenced: set[str] = set()
    for path in _source_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        referenced.update(_SYMBOL_REFERENCE.findall(text))
    return referenced


def _unwritten_alert_metrics(
    declared: dict[str, str], referenced: set[str]
) -> list[str]:
    """Alerted metrics whose declaring symbol appears in no application module."""
    unwritten: list[str] = []
    for metric in sorted(_metrics_queried_by_alerts()):
        base = _base_name(metric, set(declared))
        symbol = declared.get(base)
        if symbol is None:
            # No declaration at all is the sibling test's job, not this one.
            continue
        if symbol not in referenced:
            unwritten.append(f"{metric} (declared as {symbol}, referenced nowhere)")
    return unwritten


def test_every_alerted_metric_has_a_writer() -> None:
    unwritten = _unwritten_alert_metrics(_symbol_by_metric_name(), _referenced_symbols())

    assert not unwritten, (
        "Grafana alert rules page on metrics that no code path ever writes.\n"
        "prometheus exports these at 0, so the rule fires — or stays silent —\n"
        "on the absence of a writer rather than on a measurement:\n  "
        + "\n  ".join(unwritten)
        + "\n\nEither give the metric a writer, or retire the rule."
    )


def test_the_guard_can_see_an_unwritten_metric() -> None:
    """
    The guard above is only worth its runtime if it fails on the real defect.
    A test fixture agreeing with the bug is how the ghost-schema guard shipped
    blind, so this reproduces the actual production case: take the peering
    gauge's writer back out of the reference set, and the check must name it.
    """
    declared = _symbol_by_metric_name()
    symbol = declared.get("warden_community_peering_connections")
    assert symbol is not None, "peering gauge declaration disappeared from metrics.py"

    referenced = _referenced_symbols()
    assert symbol in referenced, (
        f"{symbol} has no writer — this is the OB-F12 defect itself, "
        "not a broken test"
    )

    # The negative control: the state production was actually in.
    caught = _unwritten_alert_metrics(declared, referenced - {symbol})
    assert any("warden_community_peering_connections" in entry for entry in caught), (
        "with the peering gauge's only writer removed the guard reported nothing, "
        f"so it cannot see the defect it exists for. Reported: {caught}"
    )
