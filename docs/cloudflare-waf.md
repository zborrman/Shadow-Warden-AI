# Cloudflare WAF Rules — Shadow Warden AI

## Digital Staff Agent Endpoints

### Rate Limiting Rules

> **The Pro plan allows 2 rate-limiting rules for the whole zone.** One is spent
> on `Leaked credential check`, so there is exactly **one** free slot. The
> five-rule table this document used to carry was never deployable — that is why
> none of it was ever in the zone. Spend the slot on the credential endpoints and
> enforce the rest in warden, which now keys on the real client IP
> (`warden/client_ip.py`); before that fix every anonymous caller shared one
> bucket and the in-app limiter was effectively inert.

**The one edge rule — Cloudflare Dashboard → Security → WAF → Rate limiting rules:**

- **Name:** `auth-credential-throttle`
- **Expression** (use *Edit expression*):

```text
(http.request.method eq "POST" and (
  (http.host eq "api.shadow-warden-ai.com" and
     http.request.uri.path in {"/auth/login" "/auth/signup"}) or
  (http.host in {"shadow-warden-ai.com" "www.shadow-warden-ai.com"} and
     http.request.uri.path in {"/api/auth/login" "/api/auth/signup"})
))
```

- **Rate:** 10 requests / 1 minute, counting by *IP*
- **Action:** Block, duration 10 minutes

Both host branches are required. The browser does not call `api.*` for auth — the
marketing site proxies same-origin through `/api/auth/*` (`docker/Caddyfile`,
`handle /api/*`), so a rule matching only `/auth/` misses the path real users and
real attackers actually hit. `POST` and exact paths keep `GET /auth/me`, which
fires on every page load, out of the counter.

This rule does nothing until the `Bypass API` custom rule stops skipping
`All rate limiting rules` — see the skip section below.

**Enforced in warden, not at the edge** (no free slots):

| Surface | Where | Control |
|---------|-------|---------|
| `/auth/login` | `warden/auth/router.py` | 10 / 5 min per IP (`AUTH_LOGIN_RATE_LIMIT`, `AUTH_LOGIN_RATE_WINDOW`) |
| `/auth/signup` | `warden/auth/router.py` | `auth_signup_rate_limit` / hour per IP |
| `/filter`, `/filter/batch` | `warden/limiter.py` | per-tenant `RATE_LIMIT_PER_MINUTE`, keyed on API key then client IP |
| `/marketplace/*` | `warden/marketplace/rate_limit.py` | `MARKETPLACE_RATE_LIMIT_PER_MINUTE` per API key / IP |
| `/staff/agents/*`, `/agent/*` | `warden/staff/*`, velocity guard | `VelocityGuard.record_and_check()` |

### WAF Custom Rules

```text
# Block requests missing X-API-Key on staff agent routes
(http.request.uri.path matches "^/staff/" and not http.request.headers["x-api-key"][*] exists)

# Block suspiciously large bodies to agent endpoints (> 64KB)
(http.request.uri.path matches "^/agent/" and http.request.body.size > 65536)

# Country-based block for highest-risk jurisdictions on financial endpoints
(http.request.uri.path matches "^/financial/" and ip.geoip.country in {"KP" "IR" "SY" "CU"})
```

### Managed Ruleset

Enable **OWASP Core Ruleset** (Sensitivity: Medium) for `api.shadow-warden-ai.com`.

> ⚠️ **CRITICAL — WAF must skip the analysis endpoints.** `/filter`, `/ext/filter`,
> and `/v1/chat/completions` receive jailbreak / prompt-injection / secret-leak
> payloads *by design* — that is the product's input. The OWASP ruleset (and the
> Cloudflare Managed Ruleset) will classify those bodies as attacks and return
> **403 at the edge, before the request ever reaches warden** — silently breaking
> the core value prop and every customer integration. This is non-obvious and easy
> to lose on a zone migration, so it is pinned here.

**Dashboard → Security → WAF → Managed rules → (each managed ruleset) → Add exception → Skip:**

- **Name:** `skip-managed-on-analysis-endpoints`
- **Expression:**
  `(http.host eq "api.shadow-warden-ai.com" and (http.request.uri.path in {"/filter" "/ext/filter"} or http.request.uri.path matches "^/v1/"))`
- **Action:** Skip → *Cloudflare Managed Ruleset* + *OWASP Core Ruleset*
- **Order:** before the managed rulesets execute

The pipeline is warden's own job on these paths — the 9-layer filter *is* the WAF
here. Rate limiting (above) and Bot Fight allowlisting still apply; only the
payload-inspection managed rules are skipped. Do **not** widen the skip to other
paths — everything except these three analysis endpoints keeps full OWASP coverage.

## The skip rule is the most dangerous object in this zone

A zone audit on 2026-07-22 found the live configuration had drifted from
everything above into a near-total WAF bypass. It is written down here because
the drift was invisible: the dashboard shows a rule named "Bypass API" that
looks routine, and nothing in CI or the repo compares the zone against this doc.

What was actually deployed — one custom rule, **order First**, on **every
hostname in the zone**:

```text
(http.request.uri.path contains "/portal/") or (http.request.uri.path contains "/health")  or
(http.request.uri.path contains "/filter")  or (http.request.uri.path contains "/v1/")     or
(http.request.uri.path contains "/api/")    or (http.request.uri.path contains "/metrics") or
(http.request.uri.path contains "/admin")   or (http.request.uri.path contains "/tenant")
→ Skip: All remaining custom rules + All rate limiting rules + All managed rules
```

Three separate failures compound here:

1. **No hostname predicate.** It applied to the marketing site, the portal, the
   dashboard and analytics, not just `api.*`.
2. **`contains`, not `in` / `starts_with`.** `/health` also matched
   `/health/pipeline`; `/filter` also matched any path with that substring.
3. **Three skip components instead of one.** Rate limiting and managed rules were
   both disabled, not just the payload-inspection rulesets the analysis
   endpoints legitimately need.

The concrete consequence: `shadow-warden-ai.com/api/*` is the same-origin auth
proxy (see `docker/Caddyfile`), so `/api/auth/login` and `/api/auth/signup` ran
with no WAF, **no rate limiting, and no leaked-credential check** — unbounded
credential stuffing at the edge. `contains "/admin"` removed the same three
layers from the admin surface. Because the rule ran first and skipped all
remaining custom rules, `allow-health-probes` never executed and any *future*
security rule would have been silently dead on arrival.

### Rules for writing a skip

- **Always scope by `http.host`.** A path predicate alone hits every hostname.
- **Never use `contains` on a path.** Use `in {"/a" "/b"}` for exact paths or
  `starts_with(http.request.uri.path, "/prefix/")` for subtrees.
- **Skip exactly one component.** If you need managed rules off, check only
  *All managed rules*. `All rate limiting rules` and `All remaining custom
  rules` are almost never the right answer — the second one also disables every
  rule you add later.
- **Never skip anything on an auth or admin path.** `/auth/*`, `/admin*`,
  `/tenant*`, `/billing/*`, `/secrets/*` keep full coverage, always.
- **Order matters.** A first-position skip preempts the whole ruleset.

### Correct replacement

Two narrow rules replace the single broad one:

```text
# A — managed rules only, analysis endpoints only
(http.host eq "api.shadow-warden-ai.com" and (
   http.request.uri.path in {"/filter" "/ext/filter"} or
   starts_with(http.request.uri.path, "/v1/")))
→ Skip: All managed rules   (nothing else)

# B — Super Bot Fight Mode only, browser XHR paths only
(http.host in {"shadow-warden-ai.com" "www.shadow-warden-ai.com"
               "app.shadow-warden-ai.com"} and
   starts_with(http.request.uri.path, "/api/"))
→ Skip: All Super Bot Fight Mode Rules   (nothing else)
```

Rule B exists because Bot Fight Mode 403s browser XHR — the real reason
`/portal/` and `/api/` were originally added to the bypass. That is a Bot Fight
problem and takes a Bot Fight skip; it never justified disabling the WAF.

Note the path predicate applies to `app.*` too. An earlier draft of this rule
skipped that host entirely, which would have taken Super Bot Fight Mode off
every portal route — document loads, assets and all — to fix a problem that only
affects XHR. Real browsers pass Bot Fight on document loads; it is the
`fetch`/`XHR` calls that get scored. If the portal calls something outside
`/api/`, add that exact path to the list — never widen back to the bare host.

**Apply in this order.** Narrow the expression *first*, then uncheck the skip
components. Doing it the other way round re-enables managed rules against the
old broad expression, which means OWASP starts 403-ing `/filter` payloads at the
edge and the product stops working (see the CRITICAL note above).

After applying, watch Security → Events for 10 minutes: `/portal/` and `/api/`
will be under managed rules for the first time. If legitimate portal XHR trips a
rule, add an exception for that specific ruleset ID — never a broad path bypass.

### Rate limiting was never deployed

The same audit found **one** rate-limiting rule in the zone (`Leaked credential
check`) and none of the five this document used to list — and that one was
itself skipped on every path the bypass rule matched, `Leaked credential check`
included, because `contains "/api/"` covers the same-origin auth proxy.

The root cause was not neglect: **Pro allows 2 rate-limiting rules total**, so
the documented five could never have been created. Documentation that asks for
an impossible configuration produces exactly this outcome — nobody deploys it,
and the gap reads as "someone will get to it" rather than "this is unbuildable".
The section at the top of this file now describes one deployable edge rule and
names where every other limit actually lives in warden.

### Bot Fight Mode

Enable **Super Bot Fight Mode** on the zone.

> ⚠️ **Do not allowlist `104.18.0.0/16` / `104.21.0.0/16`.** Those are
> *Cloudflare's own* proxy ranges, not Vercel-specific — allowlisting them lets
> any request routed through any Cloudflare zone (including an attacker's own
> Worker) skip bot protection. Vercel deployments served through Cloudflare
> share that space, which is exactly why it is not an identity.
>
> Allowlist by **verified bot / AS number / service token**, not by CIDR:
> - Vercel → match `cf.verified_bot_category` or send a shared secret header
>   from the Vercel function and gate on it (`http.request.headers["x-origin-token"][0] eq "<secret>"`).
> - GitHub Actions → use the `allow-health-probes` skip rule below. Do **not**
>   try to pin runner CIDRs: `192.30.252.0/22` and `185.199.108.0/22` are
>   GitHub's web / hooks / Pages ranges, **not** hosted-runner egress. Hosted
>   runners leave from dynamic Azure addresses published under the `actions` key
>   of `https://api.github.com/meta`, and that list changes weekly — an allowlist
>   built from it is stale before it is useful, and the two ranges above simply
>   never match, so the probe stays blocked while the rule looks correct.

### Cloudflare Workers Pre-filter (C3 from improvement plan)

Deploy a thin Cloudflare Worker at `api.shadow-warden-ai.com/_preflight` that:
1. Validates `Content-Type: application/json`
2. Rejects bodies > 1MB before they reach Vercel/warden
3. Adds `CF-Ray` to request for distributed tracing correlation

Source of truth: `cloudflare/preflight-worker/src/index.js`.

Two non-obvious properties of that Worker:

- **`Content-Length` is not trusted on its own.** It is client-supplied and
  absent entirely on a `Transfer-Encoding: chunked` upload, so a size check
  alone is bypassable by streaming. The Worker rejects a body-bearing request
  to a guarded API prefix with **411** when no valid length is declared.
- **Only `CF-Connecting-IP` is promoted to `X-Real-IP`.** `X-Forwarded-For` is
  client-supplied and must never become an identity header; when
  `CF-Connecting-IP` is absent the Worker *deletes* `X-Real-IP` rather than
  passing a client-authored one through. See the client-IP contract below.

## Cache Rules (Pro plan)

The API must never be cached — `/filter` is a POST and stateful; a cached
response would leak one tenant's verdict to another.

- **`api.shadow-warden-ai.com` → Bypass cache.** Expression:
  `(http.host eq "api.shadow-warden-ai.com")` → Cache eligibility: **Bypass**.
  (Cloudflare does not cache POST by default, but pin this so no future page rule
  re-enables it for GET routes like `/health`.)
- **Static site (`shadow-warden-ai.com`) → Cache Everything** with Polish/Mirage
  image optimization on. Marketing assets (`/logo.png`, Astro build output) only.

## DNS / SSL

- **Proxy mode:** Orange-cloud (proxied) for all A/CNAME records
- **SSL mode:** Full (Strict) — requires valid origin cert (Caddy handles Let's Encrypt)
- **Min TLS version:** TLS 1.2 (enforce in SSL/TLS → Edge Certificates)
- **HSTS:** Max-age 1 year, includeSubDomains, preload — already set in Caddyfile

## Origin lockdown — everything above is edge-only

Every rule on this page runs at the Cloudflare edge. A request sent straight to
the origin IP skips **all** of it: rate limiting, the OWASP ruleset, Bot Fight,
the `/staff/` API-key rule, the preflight Worker. Full (Strict) TLS does not
prevent this — it only proves the origin holds a valid cert.

Two controls close it, and both are required:

1. **Authenticated Origin Pulls (mTLS).** SSL/TLS → Origin Server → enable
   *Authenticated Origin Pulls* (zone-level), then make Caddy require the
   Cloudflare client certificate on the public vhosts:

```text
   tls /etc/caddy/ssl/cert.pem /etc/caddy/ssl/key.pem {
       client_auth {
           mode                 require_and_verify
           trusted_ca_cert_file /etc/caddy/ssl/cloudflare-origin-pull-ca.pem
       }
   }
```

   CA bundle: <https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/>

2. **Host firewall.** Allow `80/443` only from Cloudflare's published ranges
   (<https://www.cloudflare.com/ips/>), or — better — drop the public
   `80/443` bind entirely and let the `cloudflared` tunnel be the only ingress.
   `docker-compose.yml` already runs two `cloudflared` replicas.

Ports that must **never** be published on the public interface (they are bound
to `127.0.0.1` in `docker-compose.yml` — reach them over SSH port-forward):

| Port | Service | Why |
|------|---------|-----|
| `16686` | Jaeger UI | No authentication whatsoever; traces carry request metadata |
| `9000` | MinIO S3 API | Evidence Vault + log objects; only consumed in-cluster |
| `9091` | MinIO Console | Credential-stuffing target with no WAF in front |

Grafana (`3001`) has its own auth and is still published for the SOC dashboard
deep-links; move it behind a `grafana.shadow-warden-ai.com` vhost + Cloudflare
Access when convenient.

## Client IP contract (Cloudflare → Caddy → warden)

warden never sees the client socket — the peer is always the Caddy container.
`request.client.host` is therefore a single constant for the entire internet,
and keying ERS / shadow ban / rate limits on it collapses every anonymous
caller into one bucket (one attacker shadow-bans everybody, and the per-minute
quota is shared globally).

The chain is now explicit:

1. Cloudflare sets `CF-Connecting-IP` at the edge, overwriting any client value.
2. `docker/Caddyfile` declares `trusted_proxies` (Cloudflare ranges +
   `private_ranges` for the `cloudflared` container) and
   `client_ip_headers CF-Connecting-IP X-Forwarded-For`, then **overwrites**
   `CF-Connecting-IP` / `X-Real-IP` / `X-Forwarded-For` with `{client_ip}` on
   every `reverse_proxy` (the `(client_ip_headers)` snippet). A direct-to-origin
   request from an untrusted peer gets its socket address substituted, so forged
   headers cannot survive.
3. `warden/client_ip.py::get_client_ip()` reads those headers **only** when the
   peer is inside `TRUSTED_PROXY_CIDRS` (default: loopback + RFC1918).

**Never read `request.client.host`, `get_remote_address()`, or a raw
`X-Forwarded-For` header directly in request code** — always call
`get_client_ip(request)`. Guarded by `warden/tests/test_client_ip.py`.

## Verified Routes

| Hostname | Target | Notes |
|----------|--------|-------|
| `api.shadow-warden-ai.com` | `warden:8001` via Caddy | Main API + filter pipeline |
| `shadow-warden-ai.com` | Vercel static | Landing/marketing site |
| `www.shadow-warden-ai.com` | Vercel static | Redirect → non-www |
| `app.shadow-warden-ai.com` | `portal:3001` via Caddy | Tenant portal |
| `analytics.shadow-warden-ai.com` | `analytics:8002` via Caddy | Streamlit dashboard |

## Health-check skip rule (uptime monitoring)

Bot Fight Mode 403s datacenter-origin requests, which blocks synthetic
monitors (GitHub Actions runners, the server's own outbound probes). The
`.github/workflows/uptime-monitor.yml` probe needs this rule to see `/health`:

**Dashboard → Security → WAF → Custom rules → Create rule:**

- **Name:** `allow-health-probes`
- **Expression:**
  `(http.request.uri.path eq "/health" and http.request.method eq "GET")`
- **Action:** Skip → *All remaining custom rules* + **Bot Fight Mode**
- **Order:** first

`/health` returns only aggregate status (no tenant data, no content), so
exposing it to unauthenticated automation is safe. Do NOT widen the path —
`/health/pipeline` stays protected.
