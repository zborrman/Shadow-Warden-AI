"""warden/tests/test_dashboard_calls_real_routes.py — SW-11.

Every path the SOC dashboard fetches must be a route the gateway serves.

The TrustRank leaderboard page called `GET /marketplace/trust/leaderboard` and
the trust page called `GET /marketplace/trust/graph`. Neither route has ever
existed. Both are allow-listed in the dashboard proxy, and
`warden/protocols/a2a/agent_card.py` advertises the second one to other agents
as a capability of this service — so the 404 was published, not merely
suffered.

The visible symptom was a mislabelled column: the table's "Trades" cell
rendered `agent.trust_rank` and its "Volume" cell was a hardcoded em dash.
That is what a table looks like when it was written for data that never
arrives. Fixing the labels alone would have left the page fetching a route
that does not exist, which is the actual defect.

This is the same class as the published OpenAPI that listed paths the live app
did not serve, and the MCP manifest that advertised a revision date that never
existed. A client and a server can disagree indefinitely when nothing compares
them, so this compares them.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_API_TS = _ROOT / "dashboard" / "src" / "lib" / "api.ts"
_INVENTORY = Path(__file__).parent / "fixtures" / "route_inventory.json"

#: `/api/v1/*` is the analytics service (`analytics/main.py`), a separate app
#: that the proxy routes to by prefix. It has its own inventory; this guard
#: covers the gateway, so those paths are out of scope rather than exempt.
ANALYTICS_PREFIX = "/api/v1/"

#: Base URLs, not endpoints. `/api/warden` is the same-origin proxy every call
#: is prefixed with; `/a2a` is the service endpoint an agent posts tasks to,
#: whose real routes (`/a2a/tasks`, ...) do exist. Listing them here is a claim
#: that they are prefixes, and the assertion below re-checks that claim rather
#: than trusting it: each must have at least one real route beneath it.
BASE_URLS = ("/api/warden", "/a2a")

#: Paths in `warden/agent/tools.py` that are known not to exist, recorded so a
#: NEW one fails this guard rather than joining them unnoticed. Five SOVA tools
#: address routes this gateway has never served, so each returns its exception
#: branch on every invocation:
#:
#:   /sep/ueciids/search  — the real route is `GET /sep/search`, which needs a
#:                          `community_id` the tool does not take.
#:   /sep/ueciids         — the real route is `POST /sep/register`, whose body
#:                          is a different schema entirely (`entity_id`,
#:                          `content_type`, `byte_size`) and which expects the
#:                          entity to exist first. `publish_to_community` has
#:                          therefore never published anything.
#:   /community/posts/{}/requeue      — no moderation requeue route exists.
#:   /community-intel/{}/report       — `/community-intel/{}` and its
#:                          sub-resources exist; `/report` is not among them.
#:   /marketplace/escrow/{}/dispute/vote — only `.../dispute` exists. The
#:                          dashboard proxy allow-lists the vote path too, so a
#:                          dead route is guarded as though it were live.
#:
#: None of these is a rename: each needs a decision about what the endpoint
#: should do. Recorded 2026-09-05; this list must shrink, never grow.
KNOWN_BROKEN_AGENT_TOOL_PATHS = frozenset({
    "/sep/ueciids/search",
    "/sep/ueciids",
    "/community/posts/{}/requeue",
    "/community-intel/{}/report",
    "/marketplace/escrow/{}/dispute/vote",
})


#: A quoted absolute path in Python source, in any of the three quote styles.
_TOOL_PATH = re.compile(r"""['"`](/[a-z0-9][^'"`\s]*)['"`]""")


def _gateway_routes() -> set[str]:
    """Every path the gateway serves, with path params normalised to `{}`."""
    data = json.loads(_INVENTORY.read_text(encoding="utf-8"))
    routes: set[str] = set()
    for module_routes in data.values():
        for entry in module_routes:
            _, _, path = entry.partition(" ")
            routes.add(re.sub(r"\{[^}]+\}", "{}", path).rstrip("/") or "/")
    return routes


def _resolves(path: str, routes: set[str]) -> bool:
    """Whether `path` would reach a route, treating `{}` as a wildcard segment.

    A caller writes a concrete id where the server declares a parameter, so
    `/communities/abc` has to match `/communities/{}`. Comparing the strings
    directly would report every parameterised call as missing, and a guard
    that cries wolf on most of its input gets muted — which is the same
    outcome as not having one.
    """
    if path in routes:
        return True
    parts = path.split("/")
    for route in routes:
        rparts = route.split("/")
        if len(rparts) != len(parts):
            continue
        if all(r == "{}" or r == p for r, p in zip(rparts, parts, strict=True)):
            return True
    return False


def _dashboard_paths() -> list[tuple[int, str]]:
    """(line number, path) for every gateway path `api.ts` fetches.

    Template placeholders become `{}` so `/communities/${id}` lines up with the
    inventory's `/communities/{community_id}`.
    """
    out: list[tuple[int, str]] = []
    for n, line in enumerate(_API_TS.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith(("//", "*", "/*")):
            continue
        for m in re.finditer(r'[`"](/[^`"$]*(?:\$\{[^}]*\}[^`"$]*)*)[`"]', line):
            raw = m.group(1)
            if raw.startswith(ANALYTICS_PREFIX):
                continue
            path = re.sub(r"\$\{[^}]*\}", "{}", raw).rstrip("/")
            if path:
                out.append((n, path))
    return out


def test_every_dashboard_call_hits_a_route_that_exists() -> None:
    routes = _gateway_routes()
    missing = [
        f"dashboard/src/lib/api.ts:{n}: {path} is not a route this gateway serves"
        for n, path in _dashboard_paths()
        if not _resolves(path, routes) and path not in BASE_URLS
    ]
    assert not missing, (
        "the dashboard fetches paths the gateway does not serve, so these "
        "panels 404 in production while looking like ordinary empty states:\n  "
        + "\n  ".join(missing)
        + "\n\nEither implement the route or stop calling it. Regenerate the "
        "inventory with UPDATE_ROUTE_INVENTORY=1 if you added one."
    )


def test_a_declared_base_url_really_has_routes_under_it() -> None:
    """The exemption above is a claim, so check it rather than trust it.

    `/api/warden` and `/a2a` are skipped as prefixes rather than endpoints. If
    a prefix ever stops having routes beneath it, the skip silently becomes a
    hole — an exemption that outlives its reason is how allow-lists rot.
    """
    routes = _gateway_routes()
    for base in BASE_URLS:
        if base == "/api/warden":
            continue  # the dashboard's own Next.js route, not a gateway path
        assert any(r.startswith(base + "/") for r in routes), (
            f"{base} is exempted as a base URL but the gateway serves nothing "
            f"beneath it, so the exemption now hides a dead path."
        )


def test_no_new_ghost_paths_in_the_agent_tools() -> None:
    """SOVA's tools call the gateway over HTTP and have the same defect.

    Five of them address routes that do not exist, so those tools return their
    error branch every time they are called. They are recorded in
    KNOWN_BROKEN_AGENT_TOOL_PATHS rather than fixed here because the repair is
    a schema decision, not a rename — but a third one must not be able to join
    them quietly.
    """
    tools = _ROOT / "warden" / "agent" / "tools.py"
    routes = _gateway_routes()
    unexpected: list[str] = []

    for n, line in enumerate(tools.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for m in re.finditer(_TOOL_PATH, line):
            path = m.group(1).split("?")[0].rstrip("/")
            # f-string interpolations stand in for path params.
            norm = re.sub(r"\{[^}]+\}", "{}", path)
            if norm in KNOWN_BROKEN_AGENT_TOOL_PATHS or path in KNOWN_BROKEN_AGENT_TOOL_PATHS:
                continue
            if _resolves(norm, routes):
                continue
            unexpected.append(f"warden/agent/tools.py:{n}: {path}")

    assert not unexpected, (
        "these agent tools call gateway paths that do not exist, so they fail "
        "on every invocation:\n  " + "\n  ".join(unexpected)
    )


def test_the_agent_card_advertises_only_routes_that_exist() -> None:
    """A capability published to other agents has to resolve.

    `agent_card.py` is fetched by external agents deciding what this service
    can do. A link in it that 404s is a promise to a machine, which will not
    read around it the way a person would.
    """
    card = (_ROOT / "warden" / "protocols" / "a2a" / "agent_card.py").read_text(encoding="utf-8")
    routes = _gateway_routes()
    broken: list[str] = []

    for m in re.finditer(r'f"\{_BASE_URL\}(/[^"]*)"', card):
        path = re.sub(r"\{[^}]+\}", "{}", m.group(1)).rstrip("/")
        if path and not _resolves(path, routes) and path not in BASE_URLS:
            broken.append(f"{path} is advertised in the agent card but not served")

    assert not broken, (
        "the A2A agent card links to routes that do not exist:\n  "
        + "\n  ".join(broken)
    )
