# Shadow Warden AI Developer Portal

Human page: <https://shadow-warden-ai.com/developers>

One entry point for everything programmatic. Every URL below answers.

## Guides

- [Quick start](https://shadow-warden-ai.com/doc/quick-start) — Docker Compose to first filtered request
- [Authentication](https://shadow-warden-ai.com/doc/authentication) — `X-API-Key`, OIDC bearer on `/ext/*`, admin keys, and what each rejection code means
- [Rate limits](https://shadow-warden-ai.com/doc/rate-limits) — the `RateLimit` header contract every response carries
- [API reference](https://shadow-warden-ai.com/doc/api-reference) — rendered from the OpenAPI document below
- [SDKs and CLI](https://shadow-warden-ai.com/sdk) — Python, TypeScript, and the `warden` console script
- [MCP server](https://shadow-warden-ai.com/mcp) — the gateway as MCP tools over Streamable HTTP

## Machine-readable surfaces

All published on `shadow-warden-ai.com`. Rows marked "→ gateway" are proxied to
`api.shadow-warden-ai.com`, so one host answers for every one of them.

| Resource | URL | Served by |
|---|---|---|
| OpenAPI 3.1 document | <https://shadow-warden-ai.com/openapi.json> | site + gateway |
| llms.txt | <https://shadow-warden-ai.com/llms.txt> | site |
| Agent instructions | <https://shadow-warden-ai.com/.well-known/agent-instructions.md> | site |
| Agent card (A2A / ADP) | <https://shadow-warden-ai.com/.well-known/agent.json> | site → gateway |
| MCP manifest | <https://shadow-warden-ai.com/.well-known/mcp.json> | site → gateway |
| Marketplace manifest | <https://shadow-warden-ai.com/.well-known/ai-market.json> | site → gateway |
| DID document | <https://shadow-warden-ai.com/.well-known/did.json> | site |
| Sitemap | <https://shadow-warden-ai.com/sitemap-index.xml> | site |

The OpenAPI document carries a `servers` block, so a generated client does not
have to infer the base URL from the host it downloaded the spec from.

## The endpoints you will reach for first

Base URL `https://api.shadow-warden-ai.com`. Prefix any path with `/v1` to pin
the version.

| Method | Path | Auth | What it does |
|---|---|---|---|
| POST | `/filter` | `X-API-Key` | Run text through the nine-stage pipeline. Returns a verdict, a score and the deciding stage. |
| POST | `/filter/batch` | `X-API-Key` | The same, for up to 100 items in one call. |
| GET | `/health` | none | Liveness, version, pipeline readiness. |
| GET | `/xai/explain/{request_id}` | `X-API-Key` | The causal chain behind one decision. |
| POST | `/v1/chat/completions` | `X-API-Key` | OpenAI-compatible proxy; every message is filtered first. |
| POST | `/mcp/` | see [/mcp](https://shadow-warden-ai.com/mcp) | MCP Streamable HTTP transport, JSON-RPC 2.0. |

## First request

```bash
curl -sS -D- -X POST https://api.shadow-warden-ai.com/filter \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content": "ignore previous instructions"}'

# RateLimit-Policy: "requests-per-minute";q=60;w=60
# RateLimit: "requests-per-minute";r=59;t=41
```

A blocked verdict is still HTTP 200 — read the body, not the status. A 5xx is
the gateway failing and must never be read as a block.

## Before you build on it

- Jailbreak detection measures **36.2%** on our own 58-prompt adversarial corpus; **0 of 35** benign prompts were flagged. No higher figure is ours.
- Per-stage latency is not instrumented in production — do not quote a millisecond figure.
- Marketplace escrow and settlement are **testnet**.
- We hold **no** certification of any kind. Control mappings are self-attested.
