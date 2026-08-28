# Documentation — Shadow Warden AI

Hub: <https://shadow-warden-ai.com/doc>

## Sections

- [Quick start](https://shadow-warden-ai.com/doc/quick-start) — first filtered request in a few minutes
- [API reference](https://shadow-warden-ai.com/doc/api-reference) — every endpoint, generated from the OpenAPI document
- [Compliance](https://shadow-warden-ai.com/doc/compliance) — GDPR posture, data handling, retention
- [Testing and quality](https://shadow-warden-ai.com/doc/testing-quality) — the gates a change passes before it ships
- [Changelog](https://shadow-warden-ai.com/doc/changelog)

## Machine-readable

- OpenAPI 3.1: <https://shadow-warden-ai.com/openapi.json>
- Machine index: <https://shadow-warden-ai.com/llms.txt>
- Agent instructions: <https://shadow-warden-ai.com/.well-known/agent-instructions.md>
- Agent Card: <https://shadow-warden-ai.com/.well-known/agent.json>
- Sitemap: <https://shadow-warden-ai.com/sitemap-index.xml>

## Calling the gateway

```http
POST /filter HTTP/1.1
Host: api.shadow-warden-ai.com
X-API-Key: sk_live_...
Content-Type: application/json

{"content": "text to inspect", "tenant_id": "acme", "strict": false}
```

The response carries the verdict, the risk score, the stage that decided, and a
request id. Pass that request id to the XAI endpoint to retrieve the causal
chain behind the decision.

Request content is never written to logs — only metadata (type, length,
timing). Any endpoint that would violate that is a bug, not a setting.

## Errors worth handling

| Status | Meaning |
|---|---|
| `402` | Plan is eligible but the required add-on is not purchased |
| `403` | Plan is below the minimum tier for this endpoint |
| `406` | No representation matches the `Accept` header |
| `429` | Rate limit or monthly quota exhausted |
