"""
warden/middleware/edge_hidden.py
--------------------------------
Paths that answer inside the compose network and nowhere else.

Public traffic reaches this service through the Cloudflare Tunnel, which hands
the request straight to the container. Caddy is not on that path, so a rule
written in ``docker/Caddyfile`` does not protect anything the tunnel serves.
``/metrics`` was the case in point: Prometheus scrapes it over the internal
network, and the same 41 KB answered anyone on the public hostname.

Every request that came through Cloudflare carries ``CF-Ray`` and
``CF-Connecting-IP`` - the edge adds them and a client cannot remove them. A
request from Prometheus, a healthcheck or another container carries neither.
So "has an edge header" is the test, and a hidden path answers 404 to it.

A caller who sends the header themselves only hides the path from themselves.

Pure ASGI on purpose: ``BaseHTTPMiddleware`` holds the response until
background tasks finish (see the note in ``rate_limit_headers.py``).
"""
from __future__ import annotations

from collections.abc import Iterable

from starlette.types import ASGIApp, Receive, Scope, Send

#: Headers only the Cloudflare edge adds.
EDGE_HEADERS: frozenset[bytes] = frozenset({b"cf-ray", b"cf-connecting-ip"})

#: Paths served to the internal network only.
DEFAULT_HIDDEN_PATHS: frozenset[str] = frozenset({"/metrics"})

_BODY = b'{"detail":"Not Found"}'


def came_through_the_edge(headers: Iterable[tuple[bytes, bytes]]) -> bool:
    return any(name.lower() in EDGE_HEADERS for name, _ in headers)


class EdgeHiddenPathsMiddleware:
    def __init__(self, app: ASGIApp, paths: Iterable[str] = DEFAULT_HIDDEN_PATHS) -> None:
        self.app = app
        self.paths = frozenset(paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope.get("type") == "http"
            and scope.get("path", "").rstrip("/") in self.paths
            and came_through_the_edge(scope.get("headers") or ())
        ):
            await send(
                {
                    "type": "http.response.start",
                    "status": 404,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(_BODY)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": _BODY})
            return
        await self.app(scope, receive, send)
