# Shadow Warden AI API Versioning and Deprecation Policy

Human page: <https://shadow-warden-ai.com/doc/versioning>

How the Shadow Warden AI API is versioned, and how a change is announced before
it can break a caller.

## Versioning

The version is in the URL path. The current and only version is **`v1`**, served
at `https://api.shadow-warden-ai.com/v1/...`.

```http
POST https://api.shadow-warden-ai.com/v1/filter     ← use this
POST https://api.shadow-warden-ai.com/filter        ← works, deprecated
```

Both reach the same handler. The OpenAPI 3.1 document at
<https://shadow-warden-ai.com/openapi.json> declares the `v1` base URL in its
`servers` block.

## What counts as a breaking change

Within `v1` we do not remove a field, rename a field, change a type, tighten a
validation rule, or remove an endpoint. Adding an optional field, an endpoint or
a response header is not breaking, so clients must ignore fields they do not
recognise. A breaking change ships as a new version (`v2`) beside `v1`, never
in place.

## How deprecation is signalled

A deprecated resource answers with standard headers, readable without a human:

| Header | Standard | Meaning |
|---|---|---|
| `Deprecation: @1787443200` | RFC 9745 | This resource is deprecated; the value is the Unix time it became so. |
| `Sunset: <HTTP-date>` | RFC 8594 | The instant after which it may stop working. |
| `Link: <successor>; rel="successor-version"` | RFC 8288 | Where to move to. |
| `Link: <policy>; rel="deprecation"` | RFC 9745 | This page. |

Today these headers are sent on every **unversioned** path (`/filter` rather than
`/v1/filter`). Unversioned paths are served until **2027-08-23**
(`Sunset: Mon, 23 Aug 2027 00:00:00 GMT`).

```bash
curl -sD - -o /dev/null -X POST https://api.shadow-warden-ai.com/filter   # any status; the headers ride every response
```

Infrastructure and discovery paths (`/health`, `/metrics`, `/docs`,
`/openapi.json`, `/.well-known/*`) are not versioned and not deprecated.

## The timeline we commit to

1. **Announce** — the `Deprecation` header and `Link` successor appear, and the
   change is recorded in the [changelog](https://shadow-warden-ai.com/doc/changelog).
2. **Notice period** — at least **180 days** between the first `Deprecation`
   header and the `Sunset` date for any versioned resource.
3. **Sunset** — after the date the resource may return `410 Gone`.

The sunset date may be extended, never shortened. Extending a window is a
promise being kept; a shorter one would not be, and we will not do it.

## Related

- [Developer portal](https://shadow-warden-ai.com/developers)
- [Rate limits](https://shadow-warden-ai.com/doc/rate-limits)
- [Authentication](https://shadow-warden-ai.com/doc/authentication)
