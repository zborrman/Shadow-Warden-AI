# Cloudflare WAF Rules — Shadow Warden AI

## Digital Staff Agent Endpoints

### Rate Limiting Rules

Apply these via **Cloudflare Dashboard → Security → WAF → Rate Limiting** (or Terraform):

| Rule Name | Expression | Limit | Period | Action |
|-----------|-----------|-------|--------|--------|
| Staff agents throttle | `http.request.uri.path matches "^/staff/agents/"` | 30 req | 60s | Block |
| Filter endpoint | `http.request.uri.path eq "/filter"` | 200 req | 60s | Block |
| SOVA agent | `http.request.uri.path matches "^/agent/"` | 20 req | 60s | Block |
| Auth endpoints | `http.request.uri.path matches "^/auth/"` | 10 req | 60s | Block |
| Batch filter | `http.request.uri.path eq "/filter/batch"` | 50 req | 60s | Block |

### WAF Custom Rules

```
# Block requests missing X-API-Key on staff agent routes
(http.request.uri.path matches "^/staff/" and not http.request.headers["x-api-key"][*] exists)

# Block suspiciously large bodies to agent endpoints (> 64KB)
(http.request.uri.path matches "^/agent/" and http.request.body.size > 65536)

# Country-based block for highest-risk jurisdictions on financial endpoints
(http.request.uri.path matches "^/financial/" and ip.geoip.country in {"KP" "IR" "SY" "CU"})
```

### Managed Ruleset

Enable **OWASP Core Ruleset** (Sensitivity: Medium) for all routes under `api.shadow-warden-ai.com`.

### Bot Fight Mode

Enable **Super Bot Fight Mode** on the zone. Allowlist:
- Vercel edge network (`104.18.0.0/16`, `104.21.0.0/16`)
- GitHub Actions (`192.30.252.0/22`, `185.199.108.0/22`)

### Cloudflare Workers Pre-filter (C3 from improvement plan)

Deploy a thin Cloudflare Worker at `api.shadow-warden-ai.com/_preflight` that:
1. Validates `Content-Type: application/json`
2. Rejects bodies > 1MB before they reach Vercel/warden
3. Adds `CF-Ray` to request for distributed tracing correlation

```javascript
// workers/preflight.js
export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Only check POST endpoints
    if (request.method === 'POST') {
      const contentLength = parseInt(request.headers.get('content-length') || '0');
      if (contentLength > 1_048_576) {
        return new Response(JSON.stringify({
          error: 'payload_too_large',
          max_bytes: 1048576
        }), { status: 413, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Pass through with CF-Ray for tracing
    const headers = new Headers(request.headers);
    headers.set('X-CF-Ray', request.headers.get('cf-ray') || '');
    return fetch(new Request(request, { headers }));
  }
};
```

## DNS / SSL

- **Proxy mode:** Orange-cloud (proxied) for all A/CNAME records
- **SSL mode:** Full (Strict) — requires valid origin cert (Caddy handles Let's Encrypt)
- **Min TLS version:** TLS 1.2 (enforce in SSL/TLS → Edge Certificates)
- **HSTS:** Max-age 1 year, includeSubDomains, preload — already set in Caddyfile

## Verified Routes

| Hostname | Target | Notes |
|----------|--------|-------|
| `api.shadow-warden-ai.com` | `warden:8001` via Caddy | Main API + filter pipeline |
| `shadow-warden-ai.com` | Vercel static | Landing/marketing site |
| `www.shadow-warden-ai.com` | Vercel static | Redirect → non-www |
| `app.shadow-warden-ai.com` | `portal:3001` via Caddy | Tenant portal |
| `analytics.shadow-warden-ai.com` | `analytics:8002` via Caddy | Streamlit dashboard |
