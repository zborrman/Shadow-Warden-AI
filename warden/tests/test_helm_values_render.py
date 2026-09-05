"""warden/tests/test_helm_values_render.py — SW-13.

Every configurable block in `charts/shadow-warden/values.yaml` must be read by
a template.

The chart declared nine components — `app`, `analytics`, `dashboard`, `caddy`,
`postgres`, `minio`, `prometheus`, `grafana`, `ingress` — with replica counts,
images, resource limits and `enabled: true`. It renders four: the warden
deployment, redis, the arq worker and secrets. Everything else was values with
no template behind them, so `helm install` produced none of it while
`values.yaml` read like a full stack.

`enabled: true` is the part that misleads. A reader takes it as a switch that
is on. It was a switch wired to nothing.

`.github/workflows/helm-lint.yml` lints and templates this chart on every
change, so the file is touched by CI — but a values block that no template
consumes is invisible to both `helm lint` and `helm template`. The chart is
syntactically perfect and describes a deployment that does not happen. Same
class as the Grafana alert rules that referenced a metric nothing wrote.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_CHART = _ROOT / "charts" / "shadow-warden"
_VALUES = _CHART / "values.yaml"
_TEMPLATES = _CHART / "templates"

#: Read by Helm itself rather than by a template in this chart.
HELM_BUILTIN_KEYS = frozenset({"global", "nameOverride", "fullnameOverride"})


def _template_text() -> str:
    return "\n".join(
        p.read_text(encoding="utf-8") for p in sorted(_TEMPLATES.rglob("*")) if p.is_file()
    )


def test_every_values_block_is_read_by_a_template() -> None:
    values = yaml.safe_load(_VALUES.read_text(encoding="utf-8")) or {}
    templates = _template_text()

    dead = [
        key
        for key in values
        if key not in HELM_BUILTIN_KEYS
        and not re.search(r"\.Values\." + re.escape(key) + r"\b", templates)
    ]

    assert not dead, (
        "these values blocks are configured but no template reads them, so "
        "setting them changes nothing and `enabled: true` describes a "
        "deployment that does not happen:\n  "
        + "\n  ".join(sorted(dead))
        + "\n\nEither add the template or remove the block. A chart that "
        "documents components it cannot deploy is worse than a chart that "
        "says it deploys four things."
    )


def test_the_chart_says_what_it_actually_deploys() -> None:
    """A reader should not have to diff values against templates to find out.

    The failure above is only half the problem: someone comparing this chart to
    `docker-compose.yml` needs to know, from the chart, that it covers part of
    the stack. That belongs in the file, not in a review comment.
    """
    header = _VALUES.read_text(encoding="utf-8")[:2000]
    assert "does not deploy" in header or "deploys only" in header, (
        "values.yaml does not state which parts of the stack this chart "
        "actually renders. It renders a strict subset of docker-compose.yml, "
        "and nine components were once listed here that it never deployed."
    )
