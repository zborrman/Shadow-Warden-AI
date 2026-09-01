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

import json
import re
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_ALERTS = _ROOT / "grafana" / "provisioning" / "alerting" / "warden_alerts.yml"
_CONTACT_POINTS = _ROOT / "grafana" / "provisioning" / "alerting" / "contact_points.yml"
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


#: Smallest sample in which a quantile is defined at all: one observation per
#: percent of tail. A P99 needs 100, a P95 needs 20. Below that the "quantile"
#: is simply the slowest of a handful of calls, and an alert on it reports that
#: one call.
_MIN_SAMPLES = {0.99: 100, 0.95: 20, 0.9: 10, 0.5: 2}

_QUANTILE = re.compile(r"histogram_quantile\(\s*(0?\.\d+)")

#: A guard of the shape `sum(increase(<metric>_count{...}[<window>])) >= <n>`.
_SAMPLE_FLOOR = re.compile(r"_count\b[^)]*\)*\s*\)\s*>=\s*(\d+)")


def _traffic_guard_floor(expr: str) -> int | None:
    """The sample floor a quantile rule requires, or None if it requires none.

    OB-F20 replaced the original `> 0` check here, and the reason is worth
    keeping. `> 0` was written to stop a NaN from an idle histogram reading as
    a breach, and it does that. It does nothing whatever about a window holding
    one request. Measured on prod 2026-09-01: /filter carried 0.0011 rps, so
    the 5m window behind `warden-high-p99-latency` held about 0.3 requests, its
    "P99" was whichever single call happened to land, and the rule flapped
    Alerting -> Normal every five minutes for a whole day. `> 0` was true
    throughout, and this guard passed throughout.

    So the passing condition is no longer "a guard exists" but "the guard names
    a floor large enough for the quantile it protects".
    """
    m = _SAMPLE_FLOOR.search(expr)
    return int(m.group(1)) if m else None


def test_quantile_alerts_require_enough_samples_to_have_an_opinion(
    rules: list[dict],
) -> None:
    """A quantile over a handful of requests is not a quantile."""
    bad: list[str] = []
    for rule in rules:
        expr = _exprs(rule)
        if "histogram_quantile" not in expr:
            continue
        quantiles = [float(q) for q in _QUANTILE.findall(expr)]
        needed = max(_MIN_SAMPLES.get(q, 100) for q in quantiles) if quantiles else 100
        floor = _traffic_guard_floor(expr)
        if floor is None:
            bad.append(f"{rule['uid']}: no sample floor (a bare `> 0` is not one)")
        elif floor < needed:
            bad.append(
                f"{rule['uid']}: floor {floor}, needs {needed} for "
                f"P{int(max(quantiles) * 100)}"
            )

    assert not bad, (
        "These quantile rules can fire on a sample too small to hold the "
        "quantile they claim to measure:\n  " + "\n  ".join(bad) + "\n\n"
        "Guard the rule with `and sum(increase(<metric>_count{...}[<window>])) "
        ">= <n>`, where <n> is at least one observation per percent of tail "
        "(100 for a P99, 20 for a P95), and widen the window until real traffic "
        "can reach that floor. A rule that stays silent because the sample is "
        "too small is correct; one that pages on a single slow request is not. "
        "That was warden-high-p99-latency flapping every five minutes on "
        "0.0011 rps."
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


def test_restart_reset_gauges_are_read_over_a_window(rules: list[dict]) -> None:
    """A third instance of the same defect, found 2026-08-24.

    ``warden_arq_job_last_success_timestamp`` is an in-process prometheus_client
    Gauge. It is unset until the job next succeeds, so it vanishes from an
    *instant* query every time the arq-worker container is recreated — which
    every deploy does. The samples survive in the TSDB; only the instant read of
    them disappears.

    The nightly-backup rule read the bare gauge with ``noDataState: OK``. On any
    day the worker restarted after the 03:30 run, a backup that never happened
    produced NoData and was reported healthy — and deploys made that most days.
    Measured on production at one instant, the two forms disagreed completely::

        time() - max(...)                    -> NoData   (silently OK)
        time() - max(max_over_time(...30h))  -> 13.3h    (matches MinIO)

    Reading over a window makes the gauge's absence irrelevant and restores the
    meaning of NoData: no success recorded at all in the lookback, which is the
    condition the rule exists to detect.
    """
    offenders = []
    for rule in rules:
        expr = _exprs(rule)
        if "warden_arq_job_last_success_timestamp" not in expr:
            continue
        if "max_over_time" not in expr and rule.get("noDataState") == "OK":
            offenders.append(rule["uid"])

    assert not offenders, (
        "These rules read a restart-resetting gauge instantaneously and map its "
        "absence to healthy: " + ", ".join(offenders) + ". After any arq-worker "
        "restart the gauge is unset, so the rule reports OK without measuring "
        "anything. Wrap the metric in max_over_time(...[<window longer than the "
        "threshold>]) and set noDataState: Alerting."
    )


def test_the_backup_alert_can_still_fail(rules: list[dict]) -> None:
    """Pin both halves of the repair, the way the disk alert above is pinned."""
    backup = [r for r in rules if r.get("uid") == "warden-backup-stale"]
    assert backup, "warden-backup-stale is gone — re-check this guard"
    rule = backup[0]
    expr = _exprs(rule)

    assert "max_over_time" in expr, (
        "The backup alert is back on an instant read of "
        "warden_arq_job_last_success_timestamp. That gauge is unset after every "
        "arq-worker restart, so the rule stops measuring anything."
    )
    assert rule.get("noDataState") == "Alerting", (
        "The backup alert is back on noDataState: OK. With max_over_time, NoData "
        "no longer means 'the worker restarted' — it means no successful backup "
        "in the whole lookback, which is precisely what must page."
    )


def test_alert_dashboard_links_resolve() -> None:
    """Every /d/<uid> in an alert annotation must be a dashboard that exists.

    A uid is a URL. Six alerts pointed at `/d/warden-overview`; the provisioned
    dashboard's uid is `shadow-warden-overview`, so following the link from any
    of them landed on "Dashboard not found" — at exactly the moment the link is
    for. Grafana does not validate annotation text, and a dashboard rename is
    invisible to the rules that reference it.
    """
    import glob

    dash_dir = _ROOT / "grafana" / "dashboards"
    if not _ALERTS.exists() or not dash_dir.is_dir():
        pytest.skip("grafana provisioning not present in this checkout")

    uids = set()
    for path in glob.glob(str(dash_dir / "*.json")):
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        if doc.get("uid"):
            uids.add(doc["uid"])
    assert uids, "no provisioned dashboards found — this guard would check nothing"

    linked = set(re.findall(r"/d/([a-zA-Z0-9_-]+)", _ALERTS.read_text(encoding="utf-8")))
    assert linked, "no dashboard links found in the alert rules — check the regex"

    broken = sorted(linked - uids)
    assert not broken, (
        "Alert annotations link to dashboards that do not exist: "
        + ", ".join(broken)
        + f". Provisioned uids are: {sorted(uids)}. An operator following the "
        "link from a firing alert gets 'Dashboard not found'."
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


def test_keep_firing_for_uses_the_key_grafana_actually_reads() -> None:
    """`keep_firing_for` in this file is accepted, ignored, and silent.

    Found on 2026-09-01 by booting grafana/grafana:13.1.3 against this very
    directory and reading the rules back through
    `/api/v1/provisioning/alert-rules`. Written as `keep_firing_for: 15m` the
    field came back as `0s`; written as `keepFiringFor: 15m` it came back as
    `15m`. Nothing in the container log mentioned either outcome.

    That is the whole defect class this repo keeps finding, in a single YAML
    key: a setting that looks applied, reviews as applied, and does nothing.
    An ignored `keepFiringFor` is not cosmetic — it is what stops a series
    going absent from reading as a recovery, which is precisely how
    warden-high-p99-latency came to resolve itself every five minutes.
    """
    raw = _ALERTS.read_text(encoding="utf-8")
    # Key position only: prose in a comment may name the wrong spelling in
    # order to explain why it is wrong.
    snake = re.findall(r"^\s*keep_firing_for\s*:", raw, re.M)
    assert not snake, (
        "`keep_firing_for` is not the provisioning key. Grafana's file "
        "provisioner reads `keepFiringFor`, accepts the snake_case spelling "
        "without complaint and applies 0s. Rename it, then verify by reading "
        "the rule back from /api/v1/provisioning/alert-rules — not by reading "
        "the file."
    )


def test_the_delivery_heartbeat_exists_and_reaches_the_push_channel(
    rules: list[dict],
) -> None:
    """The one rule whose job is to prove the other 35 can reach a human.

    Every other rule here proves something about the system; none of them
    proves that a firing alert arrives anywhere. On 2026-09-01 the evidence
    for that was 70 deliveries to Slack against 3 to ntfy — and ntfy is the
    channel that overrides silent mode at 03:00. Three deliveries is an
    untested alarm clock.

    So the heartbeat is always firing on purpose, and the daily push is the
    proof. Delete it and the alerting layer goes back to being trusted rather
    than demonstrated.
    """
    beat = [r for r in rules if r.get("uid") == "warden-heartbeat-delivery"]
    assert beat, (
        "warden-heartbeat-delivery is gone. Nothing now proves the "
        "notification path works, and its failure mode is silence — the one "
        "symptom no alert can report about itself."
    )
    severity = (beat[0].get("labels") or {}).get("severity")
    assert severity == "heartbeat", (
        f"The heartbeat carries severity={severity!r}. It must keep its own "
        "value: `critical` would route it to Slack forever and be counted by "
        "the compliance rules that tally criticals."
    )

    policies = yaml.safe_load(_CONTACT_POINTS.read_text(encoding="utf-8"))
    routes = policies["policies"][0].get("routes", [])
    matched = [
        r
        for r in routes
        if any(m[:3] == ["severity", "=", "heartbeat"] for m in r.get("object_matchers", []))
    ]
    assert matched, (
        "No route matches severity=heartbeat, so the heartbeat falls through "
        "to the default Slack receiver and proves nothing about the push "
        "channel it exists to test."
    )
    assert matched[0]["receiver"] == "warden-ntfy", (
        f"The heartbeat routes to {matched[0]['receiver']!r}. It has to reach "
        "the channel that overrides silent mode, or it proves the wrong path."
    )
    assert routes.index(matched[0]) == 0, (
        "The heartbeat route is no longer first. A later route can be claimed "
        "by an earlier `continue: true` branch, which would put a permanent "
        "synthetic alert into Slack as well."
    )
