# Shadow Warden AI Rate Limits

Human page: <https://shadow-warden-ai.com/doc/rate-limits>

Two limits, published on every response, so a client never has to discover one
by being refused.

## The two limits

- **`requests-per-minute`** — a sliding window keyed on your API key, never on IP, so a shared egress address does not collapse tenants into one bucket. 60/min by default; enterprise keys carry their own rate.
- **`requests-per-month`** — the plan allowance, counted on `POST /filter` and `/filter/batch`, reset at the start of each UTC calendar month. Enterprise is unlimited and publishes no monthly policy.

## What every response carries

Structured fields from `draft-ietf-httpapi-ratelimit-headers-09`, alongside the
earlier draft spelling and the pre-draft `X-` spelling.

| Field | Example | Meaning |
|---|---|---|
| `RateLimit-Policy` | `"requests-per-minute";q=60;w=60, "requests-per-month";q=5000;w=2592000` | The static contract. One member per policy: `q` quota, `w` window seconds. On every response. |
| `RateLimit` | `"requests-per-minute";r=59;t=41` | The live reading. `r` remaining, `t` seconds to reset. Only when the request actually consumed the window. |
| `RateLimit-Limit` | `60` | Earlier draft spelling of `q`. |
| `RateLimit-Remaining` | `59` | Earlier draft spelling of `r`. |
| `RateLimit-Reset` | `41` | Earlier draft spelling of `t` — delta-seconds, not a timestamp. |
| `X-RateLimit-Limit` / `-Remaining` / `-Reset` | `1788426730` | Pre-draft spelling, kept for compatibility. `X-RateLimit-Reset` is a Unix epoch, not a delta. |
| `Retry-After` | `41` | Delta-seconds, on 429 only. Names the same instant as the reset, and takes precedence over it. |

## See it

```bash
$ curl -sS -D- -o/dev/null https://api.shadow-warden-ai.com/health

RateLimit-Policy: "requests-per-minute";q=60;w=60
RateLimit-Limit: 60
X-RateLimit-Limit: 60
```

A route that consumes no quota — `/health`, for instance — publishes the policy
and no counter. There is no bucket reading that belongs to that request, and
inventing one would be a number with nothing behind it.

## How to pace against it

- Read `RateLimit` on each response and slow down as `r` approaches zero, rather than waiting for a 429.
- On 429, honour `Retry-After`; it takes precedence over the reset parameter. Do not retry sooner.
- A monthly 429 carries a long `Retry-After` and an upgrade URL in the body. Retrying will not clear it.
- Both limits are per API key. Two workers on one key halve each worker's share.

The same conventions are described in the OpenAPI document
(<https://shadow-warden-ai.com/openapi.json>), so a generated client sees them too.
