"""
warden/tests/test_log_correlation_contract.py — OB-9 log pipeline guard.

Three files have to agree for a log line to be useful, and nothing checked that
they did:

    warden/main.py::_JsonFormatter   decides which fields exist on a line
    grafana/promtail.yml             parses those fields out and labels some
    provisioning/datasources/…       turns one of them into a link to a trace

Measured 2026-08-16, before OB-9, they did not agree. The formatter emitted
exactly four keys — ``ts``, ``level``, ``logger``, ``message``. Promtail had been
parsing every warden line for ``request_id`` and ``risk_level`` since it was
written, and promoting ``risk_level`` to a Loki label. Neither field was ever
emitted, so the extraction was a no-op and the ``risk_level`` label an operator
would filter on had never once held a value.

That is the same defect as the journal ghost fields and the ghost schema, one
layer further out: a reader parsing for a name no writer produces, and reporting
the emptiness as normal.

It also meant logs and traces had **no join key at all** — no log record and no
span shared any value — so "show me the trace for this error" was unanswerable
no matter which tool you opened.

These checks are static and cheap. They read the real files, not copies.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_MAIN = _ROOT / "warden" / "main.py"
_PROMTAIL = _ROOT / "grafana" / "promtail.yml"
_DATASOURCES = _ROOT / "grafana" / "provisioning" / "datasources" / "prometheus.yml"

#: Fields the formatter derives itself from the active OTel span.
_SPAN_DERIVED = {"trace_id", "span_id"}

#: Labels must stay bounded — Loki indexes them. trace_id and request_id are
#: per-request values; promoting either would blow up the index, which is why
#: trace_id is linked through a derived field on the log line instead.
_UNBOUNDED = {"trace_id", "span_id", "request_id", "session_id"}


def _formatter_fields() -> set[str]:
    """Every key `_JsonFormatter.format` can put on a line, read from the AST."""
    tree = ast.parse(_MAIN.read_text(encoding="utf-8"))

    extras: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "_LOG_EXTRA_FIELDS"
                    and isinstance(node.value, (ast.Tuple, ast.List))
                ):
                    extras |= {
                        e.value
                        for e in node.value.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    }

    fmt_node = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "_JsonFormatter":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "format":
                    fmt_node = item
    assert fmt_node is not None, "_JsonFormatter.format not found in warden/main.py"

    literal: set[str] = set()
    for node in ast.walk(fmt_node):
        if isinstance(node, ast.Dict):
            literal |= {
                k.value
                for k in node.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            }
        # payload["trace_id"] = ...
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.slice, ast.Constant)
                    and isinstance(target.slice.value, str)
                ):
                    literal.add(target.slice.value)

    return literal | extras | _SPAN_DERIVED


def _warden_json_stage() -> dict:
    doc = yaml.safe_load(_PROMTAIL.read_text(encoding="utf-8")) or {}
    for scrape in doc.get("scrape_configs") or []:
        for stage in scrape.get("pipeline_stages") or []:
            match = stage.get("match") or {}
            if 'service="warden"' not in str(match.get("selector", "")):
                continue
            out: dict = {"expressions": {}, "labels": {}}
            for sub in match.get("stages") or []:
                if "json" in sub:
                    out["expressions"].update(sub["json"].get("expressions") or {})
                if "labels" in sub:
                    out["labels"].update(sub["labels"] or {})
            return out
    raise AssertionError('no promtail pipeline stage found for {service="warden"}')


def _loki_datasource() -> dict:
    doc = yaml.safe_load(_DATASOURCES.read_text(encoding="utf-8")) or {}
    for ds in doc.get("datasources") or []:
        if ds.get("type") == "loki":
            return ds
    raise AssertionError("no Loki datasource provisioned")


def test_promtail_only_parses_fields_the_formatter_emits() -> None:
    emitted = _formatter_fields()
    parsed = set(_warden_json_stage()["expressions"])
    ghosts = sorted(parsed - emitted)
    assert not ghosts, (
        f"grafana/promtail.yml parses warden log fields nothing emits: {ghosts}\n"
        f"_JsonFormatter emits: {sorted(emitted)}\n\n"
        "The extraction silently yields nothing and any Loki label built on it is "
        "permanently empty — which reads as 'no events of that kind' rather than "
        "'never populated'. Either emit the field in warden/main.py::_JsonFormatter "
        "(add it to _LOG_EXTRA_FIELDS and pass it via logging extra=), or stop "
        "parsing for it."
    )


def test_loki_labels_stay_bounded() -> None:
    labels = set(_warden_json_stage()["labels"])
    unbounded = sorted(labels & _UNBOUNDED)
    assert not unbounded, (
        f"promtail promotes per-request values to Loki labels: {unbounded}\n"
        "Loki indexes every label value, so a per-request identifier creates one "
        "stream per request and destroys the index. Keep it in the log line and "
        "reach it with a derivedFields link on the Loki datasource — that is how "
        "trace_id is wired."
    )


def test_loki_labels_are_actually_emitted() -> None:
    emitted = _formatter_fields()
    labels = set(_warden_json_stage()["labels"])
    ghosts = sorted(labels - emitted)
    assert not ghosts, (
        f"Loki labels built from fields the formatter never emits: {ghosts}. "
        "An operator filtering on one of these gets an empty result that looks "
        "like a quiet system."
    )


def test_derived_field_regex_matches_a_real_log_line() -> None:
    loki = _loki_datasource()
    fields = (loki.get("jsonData") or {}).get("derivedFields") or []
    assert fields, (
        "The Loki datasource declares no derivedFields, so a log line carrying a "
        "trace_id cannot be linked to its trace. Logs and traces are then two "
        "stores with no path between them, which is the state OB-9 fixed."
    )

    # A line shaped exactly like _JsonFormatter.format() produces, built here
    # rather than imported so this stays a fast static check.
    sample = (
        '{"ts": "2026-08-16T13:27:17.343069+00:00", "level": "ERROR", '
        '"logger": "warden.gateway", "message": "boom", '
        '"trace_id": "a9f4d954dc310302dc2643574f558d9b", '
        '"span_id": "3b652b77b018b2d7"}'
    )
    for field in fields:
        rx = field.get("matcherRegex")
        assert rx, f"derivedField {field.get('name')} has no matcherRegex"
        match = re.search(rx, sample)
        assert match, (
            f"derivedField '{field.get('name')}' regex {rx!r} does not match a log "
            f"line in the shape _JsonFormatter actually emits:\n  {sample}\n"
            "A regex that matches nothing produces no link and no error — it just "
            "quietly never appears."
        )
        assert match.groups(), (
            f"derivedField '{field.get('name')}' regex has no capture group, so "
            "there is no value to build the link from."
        )


def test_derived_field_targets_a_real_datasource() -> None:
    doc = yaml.safe_load(_DATASOURCES.read_text(encoding="utf-8")) or {}
    uids = {ds["uid"] for ds in doc.get("datasources") or [] if ds.get("uid")}
    for field in (_loki_datasource().get("jsonData") or {}).get("derivedFields") or []:
        target = field.get("datasourceUid")
        if target:
            assert target in uids, (
                f"derivedField '{field.get('name')}' links to datasourceUid "
                f"{target!r}, which is not provisioned. Declared: {sorted(uids)}. "
                "The link renders and goes nowhere."
            )
