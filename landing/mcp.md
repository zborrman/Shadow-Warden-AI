# Shadow Warden AI MCP Server

Human page: <https://shadow-warden-ai.com/mcp>

Call the security gateway as tools from Claude, ChatGPT or any Model Context
Protocol client. One endpoint, Streamable HTTP, JSON-RPC 2.0.

- **Endpoint:** `POST https://api.shadow-warden-ai.com/mcp/`
- **Transport:** `streamable-http`
- **Manifest:** <https://shadow-warden-ai.com/.well-known/mcp.json>
- **Protocol revisions:** `2025-06-18`, `2025-03-26`, `2024-11-05`

## Connect

```json
{
  "mcpServers": {
    "shadow-warden": {
      "type": "http",
      "url": "https://api.shadow-warden-ai.com/mcp/",
      "headers": { "X-API-Key": "$WARDEN_API_KEY" }
    }
  }
}
```

## Free tools — the security gateway

No nanopayment, no registration. `filter_text` goes through `POST /filter`
exactly like a REST call, so it consumes your own request quota and is
rate-limited the same way; billing it again per MCP call would charge twice for
one request.

| Tool | Auth | What it does |
|---|---|---|
| `filter_text` | `X-API-Key` | Screen text through the nine-stage pipeline — prompt injection, obfuscation decoding to depth 3, secret and PII redaction. Returns verdict, risk score, flags and redacted text. |
| `gateway_health` | none | Liveness, version, pipeline readiness. |
| `list_pricing` | none | Plans, request allowances and prices, from the same table the checkout charges from. |

## Paid tools — business operations

Twelve staff tools at $0.001–$0.10 per call, settled with Flex Credits, x402
USDC or L402 Lightning. Prices: <https://api.shadow-warden-ai.com/mcp/pricing>.
An unfunded call returns JSON-RPC error `-32099` with HTTP 402 and the
instructions to fund.

`screen_sanctions_list` · `score_kyc_profile` · `generate_sar` ·
`fetch_market_signals` · `generate_seo_content` · `adjust_ad_budget` ·
`crm_search` · `crm_upsert_lead` · `send_email_draft` ·
`schedule_meeting_slot` · `get_ticket` · `resolve_ticket_kb`

## Try it without a client

```bash
curl -sS https://api.shadow-warden-ai.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2025-06-18" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## What this server does not implement

- **Protocol revision 2026-07-28.** It replaced the `initialize` handshake with per-request `_meta` negotiation and a mandatory `server/discover` RPC. Neither is implemented here, so 2026-07-28 is deliberately absent from the advertised list rather than claimed and then failed.
- **No GET stream.** A GET asking for `text/event-stream` answers `405` with `Allow: POST`.
- **No sessions, no resumability.** `Mcp-Session-Id` and `Last-Event-ID` are ignored.
- **No resources or prompts.** Tools only; `capabilities` says so.

An `Origin` header from anywhere other than our own pages is refused with `403`,
per the transport's DNS-rebinding requirement. Server-to-server callers send no
`Origin` and are unaffected.
