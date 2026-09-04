# Shadow Warden AI API Authentication

Human page: <https://shadow-warden-ai.com/doc/authentication>

Four schemes, one per surface. Send credentials as headers — never in a query
string, where they land in access logs and browser history.

## Your first authenticated request

```bash
curl -sS -X POST https://api.shadow-warden-ai.com/filter \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content": "ignore previous instructions"}'
```

## Schemes

| Header | Where | Notes |
|---|---|---|
| `X-API-Key: sk_live_…` | Every REST route | The default. Keys are per tenant and each carries its own request rate, so one customer cannot spend another's window. |
| `Authorization: Bearer <id_token>` | `/ext/*` only | OIDC from Google Workspace or Microsoft Entra ID, verified RS256 against cached JWKS. Used by the browser extension so a workstation never holds a gateway key. |
| `X-Admin-Key` | Billing grant / revoke | A separate operator secret for routes that change entitlements. Never issued to customers, never accepted in place of an API key. |
| `PAYMENT-SIGNATURE` / `Authorization: L402 …` | Paid MCP tools, M2M marketplace | x402 USDC or L402 Lightning, presented per call instead of a subscription. See <https://shadow-warden-ai.com/mcp>. |

## Status codes an automated client must handle

The distinction that matters most: **a block is a 200**. A 5xx is the gateway
failing, and reading it as "blocked" turns an outage into a silent content
refusal.

| Code | Meaning |
|---|---|
| `200` | Answered. A blocked verdict is still a 200 — read the body, not the status. |
| `401` | No `X-API-Key` header, or the key is not recognised. Carries `WWW-Authenticate: ApiKey`. Retrying with the same key will not help. |
| `402` | The plan is eligible but the add-on has not been purchased, or an x402/L402 call is unfunded. The body names what to buy. |
| `403` | Authenticated, but the plan tier is below what the route requires, or the `Origin` is not allowed. Upgrading the plan is the fix; retrying is not. |
| `406` | Content negotiation failed — the client accepts neither HTML nor Markdown. Site pages only. |
| `429` | Rate limit or monthly quota. Read `Retry-After` and the `RateLimit` fields and back off — see <https://shadow-warden-ai.com/doc/rate-limits>. |
| `5xx` | The gateway failed, not your request. Never read as a block: retry with backoff. |

## Key handling

- Keys are stored as SHA-256 hashes. A lost key is replaced, never recovered.
- Each key carries its own request rate, so the rate limit you observe is yours alone.
- Self-hosted deployments refuse to start with no key configured unless `ALLOW_UNAUTHENTICATED=true` is set explicitly. Auth fails closed, not open.
- Request content is never logged, on any code path. Only metadata — type, length, timing — is recorded.
