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

import os
from datetime import UTC, datetime

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: The only version that exists. A second one changes this module, not 562 routes.
API_VERSION = "v1"
_PREFIX = f"/{API_VERSION}"

#: When unversioned paths stop being served. Published, not implied: a
#: deprecation with no date is a preference, and callers correctly ignore it.
#: Overridable so the window can be extended without a code change — extending it
#: is a promise being kept, shortening it is not, and both belong in a PR body.
SUNSET_DATE = os.getenv("API_SUNSET_DATE", "2027-08-23")

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
    raw = date_str or SUNSET_DATE
    try:
        dt = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return raw
    return dt.strftime("%a, %d %b %Y 00:00:00 GMT")


def is_exempt(path: str) -> bool:
    """True when a path is infrastructure or discovery rather than API surface."""
    return any(path == e or path.startswith(e + "/") for e in _EXEMPT)


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
        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(raw=message["headers"])
                headers["Deprecation"] = "true"
                headers["Sunset"] = _sunset_http_date()
                headers["Link"] = f'<{_PREFIX}{path}>; rel="successor-version"'
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
