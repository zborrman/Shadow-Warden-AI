"""
warden/tests/test_prometheus_scrape_targets.py — OB-6 observability guard.

Three ways a scrape config and its consumers drift apart, all of which fail
silently as an empty panel rather than as an error.

1. **A dashboard filters on a job Prometheus does not scrape.**
   Measured 2026-08-14: `warden_overview.json` — the board an operator opens
   first — filtered nine panels on `job="warden-gateway"` while the scrape job
   is `warden`. Requests/min, Block Rate and p95 Latency, the three headline
   tiles, had never displayed a number. `warden_unified.json` additionally
   queried `app`, `dashboard`, `analytics`, `minio` and `proxy`, none of which
   existed as jobs (`proxy` is scraped under the name `caddy`).

2. **A scrape target names a host that is not a service.**
   `arq-worker:9110` only resolves because the compose service is spelled
   exactly that way. A rename or a typo turns the job permanently down, which
   on a status tile is visually identical to "not scraped".

3. **A metric carries a reserved label.**
   `job` and `instance` belong to Prometheus: it overwrites them at scrape time
   with the scrape job and target, moving the original value to `exported_job` /
   `exported_instance`. The OB-4 worker metrics were first written as
   `warden_arq_jobs_total{job="sova_nightly_backup"}`, which would have made the
   backup-freshness alert match nothing while reading perfectly in review. This
   check is why that was caught before it shipped.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_GRAFANA = _ROOT / "grafana"
_PROM_CFG = _GRAFANA / "prometheus.yml"
_COMPOSE = _ROOT / "docker-compose.yml"

_METRIC_MODULES = (
    _ROOT / "warden" / "metrics.py",
    _ROOT / "warden" / "voice" / "metrics.py",
)

#: Prometheus attaches these itself on every sample. A metric that declares one
#: as its own label loses it — the value is renamed to `exported_<label>`.
_RESERVED_LABELS = {"job", "instance"}

_METRIC_FACTORIES = {"Counter", "Gauge", "Histogram", "Summary"}

#: Hosts that are not compose services but are legitimate scrape targets.
_NON_SERVICE_TARGETS = {"localhost"}


def _prom_config() -> dict:
    assert _PROM_CFG.exists(), f"missing {_PROM_CFG}"
    return yaml.safe_load(_PROM_CFG.read_text(encoding="utf-8")) or {}


def _scrape_jobs() -> set[str]:
    return {
        sc["job_name"]
        for sc in _prom_config().get("scrape_configs", [])
        if sc.get("job_name")
    }


def _scrape_target_hosts() -> dict[str, str]:
    """host -> job_name, for every static target."""
    hosts: dict[str, str] = {}
    for sc in _prom_config().get("scrape_configs", []):
        for static in sc.get("static_configs") or []:
            for target in static.get("targets") or []:
                hosts[str(target).split(":")[0]] = sc.get("job_name", "?")
    return hosts


def _compose_services() -> set[str]:
    assert _COMPOSE.exists(), f"missing {_COMPOSE}"
    doc = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8")) or {}
    return set(doc.get("services") or {})


def _queried_jobs() -> dict[str, set[str]]:
    """`job="X"` used anywhere in Grafana, mapped to the files using it."""
    files = sorted(_GRAFANA.glob("dashboards/*.json")) + sorted(
        _GRAFANA.glob("provisioning/alerting/*.yml")
    )
    assert files, f"no Grafana files under {_GRAFANA}"
    found: dict[str, set[str]] = {}
    for path in files:
        # Unescape JSON string quoting first, so one plain pattern covers both
        # `job=\"warden\"` in a dashboard and `job="warden"` in an alert rule.
        text = path.read_text(encoding="utf-8").replace('\\"', '"')
        for job in re.findall(r'job="([A-Za-z0-9_.-]+)"', text):
            found.setdefault(job, set()).add(path.name)
    return found


def _declared_metric_labels() -> dict[str, list[str]]:
    """metric name -> declared label names, read from the AST of each module."""
    labels: dict[str, list[str]] = {}
    for mod in _METRIC_MODULES:
        assert mod.exists(), f"metric module missing: {mod}"
        tree = ast.parse(mod.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            if name not in _METRIC_FACTORIES or not node.args:
                continue
            first = node.args[0]
            if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
                continue
            metric = first.value
            for arg in node.args[1:]:
                if isinstance(arg, ast.List):
                    got = [
                        el.value
                        for el in arg.elts
                        if isinstance(el, ast.Constant) and isinstance(el.value, str)
                    ]
                    if got:
                        labels[metric] = got
            for kw in node.keywords:
                if kw.arg in {"labelnames", "labels"} and isinstance(kw.value, ast.List):
                    labels[metric] = [
                        el.value
                        for el in kw.value.elts
                        if isinstance(el, ast.Constant) and isinstance(el.value, str)
                    ]
    return labels


def test_every_queried_job_is_scraped() -> None:
    jobs = _scrape_jobs()
    missing = {
        job: sorted(files)
        for job, files in sorted(_queried_jobs().items())
        if job not in jobs
    }
    assert not missing, (
        "Grafana filters on Prometheus jobs that are never scraped:\n"
        + "\n".join(f"  job=\"{job}\"  <- {', '.join(f)}" for job, f in missing.items())
        + f"\n\nDefined jobs: {sorted(jobs)}\n"
        "Such a panel matches no series and shows 'No data' permanently. Fix the "
        "label in Grafana, or add the job to grafana/prometheus.yml. Prefer fixing "
        "Grafana: a job_name is referenced by alert expressions and is baked into "
        "the TSDB history, so renaming one orphans both."
    )


def test_scrape_targets_name_real_services() -> None:
    services = _compose_services()
    bad = {
        host: job
        for host, job in sorted(_scrape_target_hosts().items())
        if host not in services and host not in _NON_SERVICE_TARGETS
    }
    assert not bad, (
        "Scrape targets point at hosts that are not docker-compose services:\n"
        + "\n".join(f"  {host}  (job={job})" for host, job in bad.items())
        + f"\n\nCompose services: {sorted(services)}\n"
        "The job will sit permanently down, which on a status tile looks the same "
        "as never having been configured."
    )


def test_no_metric_declares_a_reserved_prometheus_label() -> None:
    offenders = {
        metric: sorted(set(labels) & _RESERVED_LABELS)
        for metric, labels in sorted(_declared_metric_labels().items())
        if set(labels) & _RESERVED_LABELS
    }
    assert not offenders, (
        "Metrics declare a label name Prometheus reserves for itself:\n"
        + "\n".join(f"  {m}  labels={ls}" for m, ls in offenders.items())
        + "\n\nPrometheus sets `job` and `instance` at scrape time and renames any "
        "conflicting label the application supplied to `exported_job` / "
        "`exported_instance`. Every query filtering on your value would therefore "
        "match nothing, while looking correct. Rename the label — the ARQ metrics "
        "use `task` for exactly this reason."
    )


def test_prometheus_config_has_no_duplicate_jobs() -> None:
    names = [
        sc.get("job_name")
        for sc in _prom_config().get("scrape_configs", [])
        if sc.get("job_name")
    ]
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, (
        f"Duplicate job_name entries in grafana/prometheus.yml: {dupes}. "
        "Prometheus refuses to start on a duplicate job name, so this is a boot "
        "failure for the whole metrics pipeline, not a degraded panel."
    )


def test_scrape_config_is_parseable_json_safe() -> None:
    # Guards against a YAML edit that parses but produces a shape the loaders
    # above would silently read as empty.
    cfg = _prom_config()
    assert cfg.get("scrape_configs"), "prometheus.yml declares no scrape_configs"
    assert len(_scrape_jobs()) >= 6, (
        f"only {len(_scrape_jobs())} scrape jobs found — OB-4 raised this to 15; "
        "a drop this large means the file lost a block rather than had one edited"
    )
    json.dumps(sorted(_scrape_jobs()))  # cheap sanity: names are plain strings
