# API versioning and the support window

**Current version: `v1` · unversioned paths served until 2027-08-23.**

Every endpoint is reachable two ways today:

```
POST https://api.shadow-warden-ai.com/v1/filter     ← use this
POST https://api.shadow-warden-ai.com/filter        ← works, deprecated
```

They reach the same handler. The second one carries the fact that it is going
away, in headers a client can act on without reading this page:

```http
HTTP/1.1 200 OK
Deprecation: true
Sunset: Mon, 23 Aug 2027 00:00:00 GMT
Link: </v1/filter>; rel="successor-version"
```

`Deprecation` and `Sunset` are RFC 8594; the `Link` relation is RFC 8288. A
machine client can follow the successor link without a human reading a changelog,
which is the point on a platform whose callers are agents.

## Why this exists

`openapi.json` publishes 562 paths and none of them carried a version. Each one
becomes a contract the first time an external agent calls it, and without a
version there is no way to change a response shape without breaking that caller —
no channel to announce it, and no date after which the old shape stops. The
launch programme lists this under P2 because it is cheap now and expensive the
moment the platform has integrators it does not control.

## How it is implemented

One ASGI middleware (`warden/api_versioning.py`), ahead of routing:

- `/v1/<path>` is rewritten to `<path>` before the router sees it. No route is
  declared twice, so the route table, the OpenAPI document and every guard that
  counts routes keep one number.
- A response to an unversioned path gets the three headers above.

The middleware is registered **last** in `warden/main.py`, which makes it
outermost: the prefix has to be stripped before anything that decides from the
path — auth exemptions, mTLS exemptions, quota, region — or every one of those
lists would need a second, versioned copy.

## What is exempt, and why

| Path tree | Reason |
|---|---|
| `/health`, `/metrics` | scraped by infrastructure, not part of the API contract |
| `/docs`, `/redoc`, `/openapi.json` | documentation surface |
| `/.well-known/*` | the path is fixed by the specs agents discover through |
| `/static`, `/favicon.ico` | assets |

These are not moving, so marking them deprecated would state something untrue.

Matching is on segment boundaries, never bare prefixes — `/healthy-agents` is an
API route that merely shares five letters with `/health`, and a substring match
would have exempted it silently.

## `/v1` was not empty

`warden/openai_proxy.py` mounts the OpenAI-compatible surface at
`APIRouter(prefix="/v1")` — `/v1/chat/completions`, `/v1/models`,
`/v1/embeddings` — because that is where every OpenAI client looks. Those paths
are specified by someone else and are not ours to alias.

So the middleware does not ask "does this start with `/v1`". It asks the router
whether anything already answers at the full path, and steps aside when something
does. That is derived from the route table rather than a hand-kept list, so a
future router claiming a `/v1/...` path keeps it without anyone remembering this
file. A method mismatch on an owned path still returns 405, not a rewrite.

## The promise

- **Additive changes** — a new optional field, a new endpoint — happen inside
  `v1` without a version bump.
- **Breaking changes** — a removed or renamed field, a changed status code, a
  narrowed input — require `v2`, and `v1` continues for at least 12 months from
  the date `v2` ships.
- **Unversioned paths** are served until the `Sunset` date above. Extending that
  date is keeping a promise and needs only `API_SUNSET_DATE`; shortening it is
  breaking one, and belongs in a pull request that says so.

The window is also published in the discovery document, so an agent can read it
without this page:

```json
GET /.well-known/agent.json
{
  "api_version": {
    "current": "v1",
    "prefix": "/v1",
    "unversioned_supported_until": "2027-08-23",
    "policy": "https://github.com/zborrman/Shadow-Warden-AI/blob/main/docs/api-versioning.md"
  }
}
```

## Status

`v1` is the alias and the deprecation contract. It is **not** yet a frozen
schema: the launch programme's P2 exit criterion is that every new route ships
under `/v1` with the legacy surface carrying a published sunset date, and that is
what this delivers. Freezing `v1`'s response shapes against a conformance suite is
separate work, and no claim is made here that it has happened.
