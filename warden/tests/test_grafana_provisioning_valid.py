"""
warden/tests/test_grafana_provisioning_valid.py — OB-6 observability guard.

Grafana provisioning fails quietly. A rule that cannot resolve its datasource
does not refuse to load — it loads, evaluates, errors, and reports nothing;
a dashboard exported "for sharing externally" provisions with an unresolvable
variable and renders empty. Both look identical to a healthy, quiet system.

Measured 2026-08-14 on the running instance, before OB-1:

    logger=ngalert.scheduler rule_uid=warden-canary-failing level=error
      msg="Failed to build rule evaluator"
      error="failed to build query 'A': data source not found"

— 135 occurrences in a three-minute window, covering every burn-rate,
poisoning, corpus-canary, latency and error-rate rule. The cause was one
missing line: `provisioning/datasources/prometheus.yml` declared no `uid`, so
Grafana generated a random one while 26 alert query nodes bound the literal
string `prometheus`. The alerting layer had been inert.

Alongside it, `contact_points.yml` shipped `contactPoints: []` with a comment
deferring routing to the UI — putting the entire notification config in the
`grafana-data` volume, which no backup covers (backup/service.py globs
`warden_*.db` plus a Postgres dump). Rules that did evaluate had nowhere to send.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_GRAFANA = _ROOT / "grafana"
_DASHBOARDS = _GRAFANA / "dashboards"
_DATASOURCES = _GRAFANA / "provisioning" / "datasources"
_ALERTING = _GRAFANA / "provisioning" / "alerting"

#: Grafana's built-in server-side expression pipeline. Not a provisioned
#: datasource, so it is exempt from UID resolution.
_EXPRESSION_UID = "__expr__"

#: The legacy numeric alias for the expression datasource. Mixing it with
#: `__expr__` in one file is how three voice rules ended up on a different
#: convention from the other twenty-one.
_LEGACY_EXPRESSION_UIDS = {"-100", "-100.0"}


def _datasource_docs() -> list[dict]:
    docs = []
    for path in sorted(_DATASOURCES.glob("*.yml")):
        docs.append(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    assert docs, f"no datasource provisioning under {_DATASOURCES}"
    return docs


def _declared_uids() -> set[str]:
    return {
        ds["uid"]
        for doc in _datasource_docs()
        for ds in doc.get("datasources") or []
        if ds.get("uid")
    }


def _alert_files() -> list[Path]:
    files = sorted(_ALERTING.glob("*.yml"))
    assert files, f"no alerting provisioning under {_ALERTING}"
    return files


def _dashboard_files() -> list[Path]:
    files = sorted(_DASHBOARDS.glob("*.json"))
    assert files, f"no dashboards under {_DASHBOARDS}"
    return files


def test_every_datasource_pins_a_uid() -> None:
    unpinned = [
        ds.get("name", "<unnamed>")
        for doc in _datasource_docs()
        for ds in doc.get("datasources") or []
        if not ds.get("uid")
    ]
    assert not unpinned, (
        f"Datasources provisioned without an explicit uid: {unpinned}. "
        "Grafana then generates a random UID at first boot, and every alert rule "
        "binding a literal uid fails to resolve its datasource — the rules error "
        "instead of firing, which is silent. Add `uid:` and keep it stable: "
        "changing it later breaks every rule and dashboard that references it."
    )


def test_every_alert_datasource_uid_resolves() -> None:
    declared = _declared_uids()
    unresolved: dict[str, set[str]] = {}
    for path in _alert_files():
        for uid in re.findall(r"datasourceUid:\s*\"?([^\"\s]+)\"?", path.read_text(encoding="utf-8")):
            if uid == _EXPRESSION_UID or uid in declared:
                continue
            unresolved.setdefault(uid, set()).add(path.name)
    assert not unresolved, (
        "Alert rules bind datasource UIDs that no provisioned datasource declares:\n"
        + "\n".join(f"  {uid}  <- {', '.join(sorted(f))}" for uid, f in sorted(unresolved.items()))
        + f"\n\nDeclared UIDs: {sorted(declared)} (plus {_EXPRESSION_UID}).\n"
        "Grafana logs 'failed to build query: data source not found' and the rule "
        "never evaluates. Note UIDs are case-sensitive: `PROMETHEUS` does not match "
        "`prometheus`."
    )


def test_no_legacy_expression_datasource_uid() -> None:
    offenders: dict[str, set[str]] = {}
    for path in _alert_files():
        text = path.read_text(encoding="utf-8")
        for uid in re.findall(r"datasourceUid:\s*\"?(-100(?:\.0)?)\"?", text):
            offenders.setdefault(uid, set()).add(path.name)
    assert not offenders, (
        f"Alert rules use the legacy numeric expression datasource {sorted(offenders)}. "
        f"Use `{_EXPRESSION_UID}` — one convention per file, so a reader can tell a "
        "server-side expression node from a real datasource at a glance."
    )


def test_dashboards_have_no_export_artifacts() -> None:
    offenders: dict[str, list[str]] = {}
    for path in _dashboard_files():
        text = path.read_text(encoding="utf-8")
        problems = []
        if "__inputs" in text:
            problems.append("__inputs")
        if "${DS_" in text:
            problems.append("${DS_...} datasource variable")
        if problems:
            offenders[path.name] = problems
    assert not offenders, (
        "Dashboards carry 'export for sharing externally' artifacts:\n"
        + "\n".join(f"  {name}: {', '.join(p)}" for name, p in sorted(offenders.items()))
        + "\n\nFile provisioning does not resolve __inputs, so a ${DS_*} reference "
        "stays a literal string and every panel in the file renders empty. Pin the "
        "datasource instead: {\"type\": \"prometheus\", \"uid\": \"prometheus\"}."
    )


def test_dashboards_parse_and_have_stable_identity() -> None:
    uids: list[str] = []
    for path in _dashboard_files():
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data.get("uid"), f"{path.name} has no uid — links and alert annotations need a stable one"
        assert data.get("title"), f"{path.name} has no title"
        assert data.get("panels"), f"{path.name} has no panels"
        uids.append(data["uid"])
    dupes = sorted({u for u, n in Counter(uids).items() if n > 1})
    assert not dupes, (
        f"Duplicate dashboard UIDs: {dupes}. Grafana provisioning overwrites one "
        "dashboard with the other, so a board silently disappears."
    )


def test_alert_rule_uids_are_unique() -> None:
    uids: list[str] = []
    for path in _alert_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for group in doc.get("groups") or []:
            for rule in group.get("rules") or []:
                assert rule.get("uid"), f"rule '{rule.get('title')}' has no uid"
                assert rule.get("title"), f"rule {rule.get('uid')} has no title"
                uids.append(rule["uid"])
    dupes = sorted({u for u, n in Counter(uids).items() if n > 1})
    assert not dupes, f"Duplicate alert rule UIDs: {dupes} — provisioning keeps only one."


def test_alert_routing_is_in_version_control() -> None:
    contact_points: list[str] = []
    routes = 0
    for path in _alert_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for cp in doc.get("contactPoints") or []:
            if cp.get("name"):
                contact_points.append(cp["name"])
        for policy in doc.get("policies") or []:
            routes += len(policy.get("routes") or [])

    assert contact_points, (
        "No contact points are provisioned. Routing then exists only inside the "
        "grafana-data Docker volume, which is in no backup set — warden/backup/"
        "service.py discovers warden_*.db plus a Postgres dump, not Grafana's own "
        "SQLite. A volume loss removes alert delivery with no signal, and every "
        "rule in this repo evaluates into nothing."
    )
    assert routes, (
        f"Contact points exist ({sorted(contact_points)}) but no notification "
        "policy routes to them, so everything falls through to the default receiver."
    )


def test_every_route_names_a_contact_point_that_exists() -> None:
    """A route to a receiver that is not defined drops its notifications.

    Retiring a contact point is two edits — the definition and every route that
    names it — plus a `deleteContactPoints` entry, because provisioning is
    additive and a receiver already written to Grafana's database survives the
    removal of its definition. Miss the route and critical alerts route to
    nothing; miss the deletion and the retired receiver keeps failing delivery,
    which is how four orphaned UI rules survived until OB-6.
    """
    defined: set[str] = set()
    deleted_uids: set[str] = set()
    routed: list[tuple[str, str]] = []

    for path in _alert_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for cp in doc.get("contactPoints") or []:
            if cp.get("name"):
                defined.add(cp["name"])
        for d in doc.get("deleteContactPoints") or []:
            if d.get("uid"):
                deleted_uids.add(d["uid"])
        for policy in doc.get("policies") or []:
            if policy.get("receiver"):
                routed.append((path.name, policy["receiver"]))
            for route in policy.get("routes") or []:
                if route.get("receiver"):
                    routed.append((path.name, route["receiver"]))

    dangling = sorted({(f, r) for f, r in routed if r not in defined})
    assert not dangling, (
        f"routes point at contact points that are not defined: {dangling}. "
        f"Defined: {sorted(defined)}. Notifications matching those routes go "
        f"nowhere."
    )

    # A receiver being deleted must not also still be defined, or provisioning
    # is asked to create and destroy the same thing on every restart.
    for path in _alert_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for cp in doc.get("contactPoints") or []:
            for recv in cp.get("receivers") or []:
                assert recv.get("uid") not in deleted_uids, (
                    f"{cp.get('name')} defines uid {recv.get('uid')} and "
                    f"deleteContactPoints removes it in the same provisioning pass."
                )


def test_every_alert_rule_declares_severity_and_nodata_handling() -> None:
    missing: list[str] = []
    for path in _alert_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for group in doc.get("groups") or []:
            for rule in group.get("rules") or []:
                labels = rule.get("labels") or {}
                if not labels.get("severity"):
                    missing.append(f"{rule.get('uid')}: no severity label")
                if rule.get("noDataState") is None:
                    missing.append(f"{rule.get('uid')}: no noDataState")
                if rule.get("execErrState") is None:
                    missing.append(f"{rule.get('uid')}: no execErrState")
    assert not missing, (
        "Alert rules missing routing or failure semantics:\n  "
        + "\n  ".join(missing)
        + "\n\n`severity` is what the notification policy matches on — without it a "
        "rule cannot be routed. `noDataState`/`execErrState` decide what happens "
        "when the query returns nothing or the datasource is unreachable; leaving "
        "them implicit is how a broken pipeline comes to look healthy."
    )
