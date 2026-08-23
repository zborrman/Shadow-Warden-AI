"""
warden/api_versioning.py — the `/v1` prefix, and the promise attached to it.

The problem
───────────
`openapi.json` publishes 562 unversioned paths. Every one of them is a contract
the moment an external agent calls it, and none of them can change shape without
breaking that caller — there is no channel to say "this is moving" and no date by
which the old shape stops. P2 of the launch programme calls this out because a
machine-to-machine platform's front door is a package install and a stable path,
and the platform is about to acquire callers it does not control.

The approach
────────────
Not a second route table. Mounting 562 routes twice doubles the surface this
repository already struggles to keep honest, and every guard that counts routes
would have to learn to halve its number.

Instead one ASGI middleware, ahead of routing:

  * `/v1/<path>` is rewritten to `<path>` before the router sees it, so every
    endpoint is reachable under the version today, with no per-route edits and no
    duplicate entries in the route table.
  * A response to an **unversioned** path carries `Deprecation: true`, a `Sunset`
    date and a `Link: …; rel="successor-version"` pointing at the `/v1` form —
    RFC 8594 and RFC 8288, which is what a well-behaved client already knows how
    to read.

So integrators can move today, existing callers keep working, and the date by
which they must move is published rather than implied.

What is exempt
──────────────
Paths that are not part of the API contract: liveness and metrics scraped by
infrastructure, the docs, and the discovery documents that agents fetch by a
well-known name fixed in a spec. Deprecating those would say something untrue —
they are not moving.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import UTC, datetime

from starlette.datastructures import MutableHeaders
from starlette.routing import Match
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger("warden.api_versioning")

#: The only version that exists. A second one changes this module, not 562 routes.
API_VERSION = "v1"
_PREFIX = f"/{API_VERSION}"

#: When unversioned paths stop being served. Published, not implied: a
#: deprecation with no date is a preference, and callers correctly ignore it.
#: Overridable so the window can be extended without a code change — extending it
#: is a promise being kept, shortening it is not, and both belong in a PR body.
_DEFAULT_SUNSET = "2027-08-23"

#: Zero-padded ISO calendar date, nothing else.
_CANONICAL_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _validated_sunset(raw: str) -> str:
    """A date we can actually serve, or the built-in default.

    `Sunset: whenever` is not a deprecation notice, it is a malformed header — a
    client parsing it gets nothing and the promise is not made. Rather than
    publish that, a malformed override is refused and logged, and the compiled-in
    date stands. Refusing to boot over a notification header would trade an
    availability incident for a documentation one; refusing the *value* costs
    nothing and keeps the contract well-formed.
    """
    # strptime alone accepts `2027-8-3`, which then gets published verbatim in
    # `unversioned_supported_until`. A date a client has to guess the padding of
    # is not a date it can compare, so the shape is pinned before parsing.
    if _CANONICAL_DATE.fullmatch(raw or ""):
        try:
            datetime.strptime(raw, "%Y-%m-%d")
            return raw
        except ValueError:
            pass
    # The rejected value is not echoed: it is operator-controlled text heading
    # into a log line, and naming the variable is enough to fix it.
    log.error(
        "API_SUNSET_DATE is not a canonical YYYY-MM-DD date — ignoring it and "
        "publishing %s. The sunset window is a promise to callers; it cannot be "
        "a malformed string.", _DEFAULT_SUNSET,
    )
    return _DEFAULT_SUNSET


SUNSET_DATE = _validated_sunset(os.getenv("API_SUNSET_DATE", _DEFAULT_SUNSET))

#: Path *trees* that are not part of the versioned API contract. Matched on
#: segment boundaries, never as bare prefixes: `"/healthy-agents".startswith(
#: "/health")` is true, and a substring match would have quietly exempted a real
#: API route from the deprecation contract for the sake of a shared spelling.
_EXEMPT = (
    "/health",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/.well-known",
    "/static",
    "/favicon.ico",
    _PREFIX,
)


def _sunset_http_date(date_str: str = "") -> str:
    """RFC 1123 date for the `Sunset` header, which is an HTTP-date, not ISO."""
    raw = _validated_sunset(date_str or SUNSET_DATE)
    dt = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=UTC)
    return dt.strftime("%a, %d %b %Y 00:00:00 GMT")


def is_exempt(path: str) -> bool:
    """True when a path is infrastructure or discovery rather than API surface."""
    return any(path == e or path.startswith(e + "/") for e in _EXEMPT)


def _already_routed(scope: Scope) -> bool:
    """True when the app already owns this exact path, prefix included.

    `/v1` is not ours alone: `warden/openai_proxy.py` mounts the
    OpenAI-compatible surface at `APIRouter(prefix="/v1")`, because that is where
    every OpenAI client looks — `/v1/chat/completions`, `/v1/models`,
    `/v1/embeddings`. Stripping the prefix off those turns a working
    externally-specified endpoint into a 404, which is exactly what the test
    suite reported.

    So the question is not "does this start with /v1" but "does something already
    answer here". Asked of the router itself rather than a hand-kept list, so a
    future router that legitimately claims a `/v1/...` path keeps it without
    anyone remembering to update this module. `Match.PARTIAL` counts: it means the
    path is owned and only the method differs, and a 405 is the right answer there
    rather than a rewrite.
    """
    router = getattr(scope.get("app"), "router", None)
    if router is None:
        return False
    for route in getattr(router, "routes", []):
        try:
            match, _child = route.matches(scope)
        except Exception:  # a route type that cannot match this scope
            continue
        if match in (Match.FULL, Match.PARTIAL):
            return True
    return False


class APIVersionMiddleware:
    """Serve every route under `/v1`, and date-stamp the unversioned form."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # ── Versioned request: strip the prefix and route as normal ──────────
        if path == _PREFIX or path.startswith(_PREFIX + "/"):
            # …unless the app already serves this path with the prefix intact.
            if _already_routed(scope):
                await self.app(scope, receive, send)
                return
            stripped = path[len(_PREFIX):] or "/"
            scope = dict(scope)
            scope["path"] = stripped
            # `raw_path` is what Starlette prefers when present; leaving the
            # original there would route the unstripped path and 404.
            if scope.get("raw_path") is not None:
                scope["raw_path"] = stripped.encode("utf-8")
            await self.app(scope, receive, send)
            return

        if is_exempt(path):
            await self.app(scope, receive, send)
            return

        # ── Unversioned request: serve it, and say when that stops ───────────
        query = scope.get("query_string") or b""
        successor = f"{_PREFIX}{path}"
        if query:
            # A successor link that drops the query points at a different
            # resource — `/search?cursor=abc` and `/search` are not the same
            # answer, and a client following the link would silently restart.
            successor = f"{successor}?{query.decode('latin-1')}"

        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(raw=message["headers"])
                headers["Deprecation"] = "true"
                headers["Sunset"] = _sunset_http_date()
                link = f'<{successor}>; rel="successor-version"'
                # Link is a comma-separated list (RFC 8288) AND may be sent as
                # several headers. `.get()` returns only the first, so assigning
                # its value back would silently drop the rest — a paginated
                # response advertising `next` and `prev` as two headers would
                # come out holding one. getlist() takes all of them.
                existing = headers.getlist("Link")
                headers["Link"] = ", ".join([*existing, link])
            await send(message)

        await self.app(scope, receive, _send)


def version_info() -> dict:
    """The versioning contract, for discovery documents and the manifest."""
    return {
        "current": API_VERSION,
        "prefix": _PREFIX,
        "unversioned_supported_until": SUNSET_DATE,
        "policy": "https://github.com/zborrman/Shadow-Warden-AI/blob/main/docs/api-versioning.md",
    }
