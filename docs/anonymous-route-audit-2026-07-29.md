# Anonymous route audit — 2026-07-29

Empirical audit of which HTTP routes `api.shadow-warden-ai.com` serves **without
credentials**. Two modules were found broken and fixed (#239, #240). Nineteen
GET routes still answer anonymously; this document triages them so the
product decision is recorded rather than re-derived.

## Why this was done at all

`warden/main.py` registers exactly two HTTP middlewares — `attach_request_id`
and `security_headers`. **There is no global authentication middleware.** A
router without its own dependency is therefore genuinely open, not covered by a
blanket rule. That is the fact that makes the rest of this document necessary.

## Method, and why the static scan was discarded

A static scan of the route table flagged **304 routes across 61 modules** as
lacking auth. That number is not usable and is not reported as a finding: it
cannot see handlers that authenticate imperatively in the body
(`ctx = _get_tenant(request)`), which is the dominant style here.
`warden/communities/router.py` alone showed 14 false positives against 38 real
auth references.

Everything below is instead **probed against production** with no credentials,
read-only (`GET`), using `probe-x` as every path parameter. No write method was
issued against production at any point.

> Three tooling bugs each produced a *falsely clean* result before the numbers
> below were trusted, and they are recorded because every one of them fails in
> the reassuring direction:
>
> 1. probing during a container restart returned `000` for everything — a
>    200-only check read that as "nothing exposed";
> 2. `curl` inside `while read` consumes stdin, truncating the loop;
> 3. Python's `open(path, "w")` on Windows writes **CRLF**, so every URL carried
>    a trailing `\r` and curl failed with `000`.
>
> A clean audit result should be distrusted until the harness is shown to
> produce a dirty one.

## Fixed

| Module | Defect | PR |
|---|---|---|
| `warden/api/communities_v2.py` | 28 live routes, zero dependencies. Analytics, compliance posture, data listings, peerings, evolution bundles and memberships all served anonymously. Write surface (delete community, change member role, upload/delete files, approve evolution bundles) equally open. | #239 |
| `warden/api/webhooks.py` | No auth; `request: Any = None` published as a **query** parameter so the tenant was always `"default"` (no isolation); `?request=x` → HTTP 500; `/{id}/history` unscoped by tenant. | #240 |

Both verified 401 in production after deploy.

## Current status — 130 path-param GET routes, anonymous

| status | count |
|---|---|
| 401 | 63 |
| 403 | 27 |
| 404 | 15 |
| **200** | **19** |
| 503 | 2 |
| 422 / 400 | 2 |

## The 19 open routes, triaged

### A. Needs a decision — plausibly sensitive

These return live response structures for arbitrary ids. Whether they are
exploitable depends on whether ids are enumerable, which has **not** been
established.

| Route | Response for an unknown id | Concern |
|---|---|---|
| `/voice/sessions/{id}` | `{"session_id":…,"turns":0,"active":false,"history":[]}` | exposes conversation `history` for a real session id |
| `/tokenomics/balance/{id}` | `{"agent_id":…,"balance_wat":0.0}` | per-agent token balance |
| `/voice/x402/balance/{id}` | `{"agent_id":…,"balance_usd":0.0}` | per-agent USD balance |
| `/billing/usage-budgets/{id}` | `[]` | tenant budget configuration |
| `/billing/usage-budgets/{id}/{id}/check` | — | budget check |
| `/whitelabel/{id}` · `/{id}/css` · `/{id}/caddy-snippet` | `{"snippet":""}` | `caddy-snippet` returns reverse-proxy config |
| `/communities/{id}/notifications/subscriptions` | — | subscriber list |
| `/webhooks/{id}/history` | — | **fixed in #240** |

### B. Plausibly public by design — confirm before gating

Marketplace reputation and protocol schemas may be intentionally readable by
unauthenticated agents; gating them could break agent discovery.

`/marketplace/agents/{id}/trust` · `/marketplace/agents/{id}/maestro-report` ·
`/marketplace/autonomy/{id}` · `/marketplace/readiness/{id}` ·
`/marketplace/protocol/schema/{id}` · `/kya/trust/{id}` ·
`/sep/federation/{id}/verdicts` · `/compliance/frameworks/{id}` ·
`/streams/state/{id}`

## Why group A was not simply gated

The four owning modules have **zero** auth dependencies across *every* route,
not only the probed ones:

```
warden/tokenomics/api.py     5 routes, 0 auth deps
warden/voice/api.py          7 routes, 0 auth deps
warden/api/usage_budgets.py  5 routes, 0 auth deps
warden/api/whitelabel.py     5 routes, 0 auth deps
```

Uniformly absent rather than patchily absent, so the structure alone does not
distinguish an oversight from a deliberately public surface. Voice-Commerce
(VC-01) is a shipped product; adding a router-level dependency to 22 routes on
an assumption could break a live client. The two modules that *were* fixed each
had positive evidence that gating was safe — the SOC dashboard's community page
was already returning 401 on its v1-served calls, and the webhook endpoint list
was empty.

**Decision needed:** which of group B is public by design. Group A can then be
gated with the same router-level `dependencies=[Depends(require_api_key)]`
pattern used in #239/#240, deriving tenant from `AuthResult.tenant_id` rather
than any caller-supplied header.

## Not covered

- Write methods (POST/PUT/DELETE) were not probed against production. Group A/B
  modules have no auth on those either, and `POST` is usually the higher risk —
  #240's registration endpoint was the exfiltration channel, not its reads.
- IDOR among *authenticated* callers. `communities_v2` still takes
  `{community_id}` from the path and trusts it; a module TODO is in place.
- The SOC dashboard has no API-key mechanism (`dashboard/src/lib/api.ts` sends
  no headers on `hub*` calls, and hardcodes `"X-API-Key": ""` elsewhere), so its
  Community Hub page is now uniformly 401. Fix by giving it a key, not by
  reopening the gate.
