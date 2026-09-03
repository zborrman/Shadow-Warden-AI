"""warden/tests/test_dashboard_links_resolve.py — OB-F21 observability guard.

The third direction of the same ratchet. `test_grafana_metrics_resolve.py` asks
whether a metric Grafana queries exists in code; `test_alert_metrics_have_writers.py`
asks whether it is ever written. This one asks the question nothing asked: does
the *link* the SOC dashboard hands a human actually go anywhere?

Measured on 2026-09-01, the Grafana link on `/platform/metrics` was broken in
four independent ways at once, and each would have been enough on its own:

  host    `NEXT_PUBLIC_GRAFANA_URL` held four different values across four
          files — `grafana:3000` (compose), `91.98.234.160:3000` and
          `localhost:3000` (two code fallbacks), `127.0.0.1:3001` (CLAUDE.md).
          Since OB-7 bound Grafana to loopback, none resolves for a visitor;
          probing 3000 and 3001 from outside the host returns nothing.

  path    the page deep-linked to `/d/shadow-warden/shadow-warden`. No
          dashboard in this repo has ever had that uid. The overview one is
          `shadow-warden-overview`.

  panels  it embedded panelId 1..4 with captions "P99 Latency", "Request Rate",
          "Block Rate", "Shadow Ban Rate". The real panels 1..4 are "Requests /
          min", "Block Rate", "p95 Latency" and "Request Rate — /filter". Every
          caption named a different panel than the one it opened, and "Shadow
          Ban Rate" is not a panel that exists.

  embed   all four were `<iframe>`s. Grafana ships `allow_embedding = false`
          and this deployment does not override it, so they rendered nothing —
          from the day they were written.

Four failures stacked in one component, none noticed, because the two sides
were never compared. That is what this file does: it compares them.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_DASHBOARD_SRC = _ROOT / "dashboard" / "src"
_GRAFANA_DASHBOARDS = _ROOT / "grafana" / "dashboards"
_LINKS = _DASHBOARD_SRC / "lib" / "internal-links.ts"

#: A Grafana deep link: /d/<uid>/...
_DEEP_LINK = re.compile(r"/d/([a-zA-Z0-9\-_]+)")

#: `{ id: 60, title: "…" }` as written in the metrics page's panel table.
_PANEL_ENTRY = re.compile(r"\{\s*id:\s*(\d+),\s*title:\s*\"([^\"]+)\"\s*\}")

#: Hosts nobody outside the VPS can reach. A literal one in the bundle is a
#: dead link by construction, not a configuration choice.
_UNREACHABLE_HOST = re.compile(
    r"https?://("
    r"grafana|jaeger|prometheus|loki|minio"           # docker-internal names
    r"|localhost|127\.0\.0\.1"                        # the visitor's own machine
    r"|91\.98\.234\.160"                              # the origin, firewalled
    r"):\d+"
)


def _provisioned_uids() -> dict[str, Path]:
    if not _GRAFANA_DASHBOARDS.exists():
        pytest.skip("grafana dashboards not present in this checkout")
    out: dict[str, Path] = {}
    for path in sorted(_GRAFANA_DASHBOARDS.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        uid = doc.get("uid") or (doc.get("dashboard") or {}).get("uid")
        if uid:
            out[uid] = path
    return out


def _dashboard_sources(client_only: bool = False) -> list[Path]:
    """Every TS/TSX file; `client_only` drops the server-side API routes.

    `src/app/api/**` runs inside the dashboard container, where a
    Docker-internal service name is the *correct* address. Only what reaches
    the browser is bound by the unreachable-host rule.
    """
    if not _DASHBOARD_SRC.exists():
        pytest.skip("dashboard/ not present in this checkout")
    out = [
        p
        for p in _DASHBOARD_SRC.rglob("*")
        if p.suffix in (".ts", ".tsx") and p.is_file()
    ]
    if client_only:
        server = _DASHBOARD_SRC / "app" / "api"
        out = [p for p in out if server not in p.parents]
    return out


def test_every_grafana_deep_link_names_a_dashboard_that_exists() -> None:
    """A uid the provisioning never declares is a 404 with extra steps."""
    uids = _provisioned_uids()
    bad: list[str] = []
    for path in _dashboard_sources():
        # internal-links.ts names the broken uid in prose, to explain it. The
        # uid it actually builds links from is pinned by the next test, against
        # the provisioning itself.
        if path == _LINKS:
            continue
        for uid in _DEEP_LINK.findall(path.read_text(encoding="utf-8")):
            if uid not in uids:
                bad.append(f"{path.relative_to(_ROOT)} -> /d/{uid}")

    assert not bad, (
        "These Grafana deep links name a dashboard uid that no file in "
        "grafana/dashboards/ declares:\n  " + "\n  ".join(bad) + "\n\n"
        "Available uids: " + ", ".join(sorted(uids)) + "\n"
        "This is how /d/shadow-warden/shadow-warden survived: the uid was "
        "plausible, the link was clickable, and nothing compared the two sides."
    )


def test_every_linked_panel_exists_with_the_title_the_ui_claims() -> None:
    """A caption that names a different panel than it opens is a lie, not a typo."""
    uids = _provisioned_uids()
    overview = re.search(r'OVERVIEW_UID\s*=\s*"([^"]+)"', _LINKS.read_text(encoding="utf-8"))
    assert overview, "OVERVIEW_UID is gone from lib/internal-links.ts"
    uid = overview.group(1)
    assert uid in uids, f"OVERVIEW_UID={uid!r} is not a provisioned dashboard"

    doc = json.loads(uids[uid].read_text(encoding="utf-8"))
    by_id = {p.get("id"): p.get("title") for p in doc.get("panels", [])}

    metrics_page = _DASHBOARD_SRC / "app" / "(soc)" / "platform" / "metrics" / "page.tsx"
    if not metrics_page.exists():
        pytest.skip("metrics page not present in this checkout")

    claimed = _PANEL_ENTRY.findall(metrics_page.read_text(encoding="utf-8"))
    assert claimed, (
        "No panel table found in the metrics page. If the panel list moved, "
        "point this guard at its new home rather than deleting it — the four "
        "captions it replaced all named the wrong panel."
    )

    wrong: list[str] = []
    for raw_id, title in claimed:
        panel_id = int(raw_id)
        if panel_id not in by_id:
            wrong.append(f"panel {panel_id} ({title!r}) does not exist on {uid}")
        elif by_id[panel_id] != title:
            wrong.append(
                f"panel {panel_id} is {by_id[panel_id]!r}, the UI calls it {title!r}"
            )

    assert not wrong, (
        "The SOC metrics page describes panels that are not what it opens:\n  "
        + "\n  ".join(wrong)
    )


def test_no_unreachable_host_is_hardcoded_in_the_bundle() -> None:
    """`NEXT_PUBLIC_*` is inlined at build time, so a guess here ships to users."""
    offenders: list[str] = []
    for path in _dashboard_sources(client_only=True):
        if path == _LINKS:
            # internal-links.ts documents the dead values on purpose, in prose.
            continue
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith(("//", "*", "/*")):
                continue
            if _UNREACHABLE_HOST.search(line):
                offenders.append(f"{path.relative_to(_ROOT)}:{line_no}: {line.strip()}")

    assert not offenders, (
        "These lines hardcode a host the visitor's browser cannot reach — a "
        "Docker-internal name, their own loopback, or the firewalled origin:\n  "
        + "\n  ".join(offenders)
        + "\n\nRoute it through lib/internal-links.ts instead, which renders "
        "the SSH tunnel command when a service has no published URL. An unset "
        "variable is an honest 'not published'; a wrong host is a dead link "
        "that costs a click and a browser error to discover."
    )


def test_a_published_url_is_validated_not_merely_non_empty() -> None:
    """`GRAFANA_PUBLIC_URL=http://grafana:3000` must not undo this fix.

    The first draft of `internalLink` treated any non-empty string as a link.
    One entry in a `.env` would then have reinstated the exact defect the file
    removes, and no guard here could have seen it — this test reads source, not
    the value someone puts in an environment. So the check has to live in the
    code, and this pins that it does.
    """
    src = _LINKS.read_text(encoding="utf-8")
    assert "function isPublished" in src, (
        "internal-links.ts no longer validates the configured URL. A non-empty "
        "value is not a reachable one; without the check, pointing a "
        "*_PUBLIC_URL at a Docker-internal name silently restores the dead link."
    )
    for host in ("grafana", "jaeger", "prometheus", "minio", "localhost", "127.0.0.1"):
        assert f'"{host}"' in src, (
            f"{host!r} dropped out of the unreachable-host list in "
            "internal-links.ts, so a URL naming it would render as a live link."
        )

    # A deny-list is the wrong shape here: every new spelling of the same
    # address is another gap, and review found two — `http://[::ffff:127.0.0.1]`
    # (URL canonicalises it to `[::ffff:7f00:1]`, matching no v6 prefix the
    # list checked) and `http://localhost.` (the fully-qualified form, absent
    # from the list and dotted, so it passed the DNS-name test too).
    #
    # So the rule names what is ALLOWED: a dotted DNS name, never an address
    # literal. Verified against real node, 23 cases.
    assert "IPV4_LITERAL" in src and 'startsWith("[")' in src, (
        "internal-links.ts no longer rejects address literals. Enumerating "
        "non-public ranges instead lets every alternative encoding of loopback "
        "through — that is exactly how ::ffff:127.0.0.1 got in."
    )
    assert 'host.endsWith(".")' in src, (
        "the trailing dot is no longer normalised. `http://localhost.` is the "
        "same host as `http://localhost` and must reach the same verdict."
    )


def test_every_public_build_variable_is_a_docker_build_arg() -> None:
    """Next inlines NEXT_PUBLIC_* at build time; runtime env never reaches it.

    docker-compose.yml passed NEXT_PUBLIC_GRAFANA_URL under `environment:` for
    the life of this dashboard and it had no effect on the bundle at all — the
    value that shipped came from next.config.mjs's fallback. The trap that
    matters is the future one: when the Grafana vhost exists, someone sets
    GRAFANA_PUBLIC_URL in the host .env, redeploys, and nothing changes.
    """
    config = (_ROOT / "dashboard" / "next.config.mjs").read_text(encoding="utf-8")
    dockerfile = (_ROOT / "dashboard" / "Dockerfile").read_text(encoding="utf-8")

    declared = set(re.findall(r"(NEXT_PUBLIC_[A-Z0-9_]+):\s*process\.env", config))
    assert declared, "no NEXT_PUBLIC_* entries found in next.config.mjs env block"

    missing = sorted(v for v in declared if f"ARG {v}" not in dockerfile)
    assert not missing, (
        "next.config.mjs inlines these at build time, but the Dockerfile "
        "declares no build ARG for them, so they are always empty in the "
        "image:\n  " + "\n  ".join(missing) + "\n\n"
        "Add `ARG <name>` plus an `ENV` line before `npm run build`, and pass "
        "it through `build.args` in docker-compose.yml. A runtime "
        "`environment:` entry cannot reach a bundle that was compiled hours "
        "earlier."
    )
