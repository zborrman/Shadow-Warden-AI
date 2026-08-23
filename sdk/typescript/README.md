# @shadow-warden/sdk

Official Node.js / TypeScript SDK for [Shadow Warden AI](https://shadow-warden-ai.com).

## Installation

```bash
npm install @shadow-warden/sdk
```

## Authentication

Every request requires an API key sent as `X-API-Key`. Generate one in the
Shadow Warden portal under **Settings → API Keys**.

```typescript
import { ShadowWardenClient } from "@shadow-warden/sdk";

const client = new ShadowWardenClient({
  apiKey: process.env.SHADOW_WARDEN_API_KEY!,
  baseUrl: "https://api.shadow-warden-ai.com", // default
});
```

## Resources

### Filter

```typescript
const result = await client.filter("Explain how to hack a server", "my-tenant");
console.log(result.allowed);     // false
console.log(result.risk_level);  // "high"
console.log(result.flags);       // ["jailbreak_attempt"]
```

### Community

```typescript
// List all communities for a tenant
const communities = await client.community.list("my-tenant");

// Create a community
const community = await client.community.create({
  name: "Acme AI Team",
  visibility: "private",
  tenant_id: "my-tenant",
});

// Invite a member (returns a knock token)
const { knock_token } = await client.community.inviteMember(
  community.id,
  "alice@acme.com",
  "admin",
);
```

### Marketplace

```typescript
// Register an AI agent
const agent = await client.marketplace.registerAgent({
  tenant_id: "my-tenant",
  community_id: community.id,
  public_key: "<base64-encoded-ed25519-pubkey>",
  capabilities: ["marketplace_sell"],
});

// Create a listing
const listing = await client.marketplace.createListing({
  asset_id: "rule-001",
  seller_agent_id: agent.agent_id,
  community_id: community.id,
  tenant_id: "my-tenant",
  asset_type: "rule",
  price_usd: 4.99,
  chain: "sepolia",         // "sepolia" | "polygon_amoy" | "arbitrum_sepolia"
});

// Purchase and settle
const { escrow_id } = await client.marketplace.purchaseListing(
  listing.listing_id,
  buyerAgentId,
);
await client.marketplace.fundEscrow(escrow_id);
await client.marketplace.confirmReceipt(escrow_id);
```

### Compliance

```typescript
const posture = await client.compliance.getPosture("my-tenant");
console.log(posture.overall_score);  // 87
console.log(posture.grade);          // "B"

const gaps = await client.compliance.getGaps("my-tenant");
// [{ control_id: "GDPR-7", severity: "HIGH", description: "..." }]
```

### Semantic Layer

```typescript
const result = await client.semantic.query({
  model_id: "filter_events",
  metrics: ["request_count", "block_rate"],
  dimensions: ["risk_level"],
  limit: 100,
});
console.log(result.sql);

// Natural-language query (Pro+)
const nlResult = await client.semantic.aiQuery(
  "How many requests were blocked this month?",
  "my-tenant",
);
```

### Document Intelligence

```typescript
import * as fs from "fs";

const pdfBase64 = fs.readFileSync("contract.pdf").toString("base64");
const doc = await client.documents.convert({
  fileBase64: pdfBase64,
  filename: "contract.pdf",
  tenantId: "my-tenant",
});
console.log(doc.text);          // Markdown text
console.log(doc.secrets_found); // true if PII/secrets detected
```

## Error Handling

```typescript
import { ShadowWardenError } from "@shadow-warden/sdk";

try {
  await client.filter("...");
} catch (err) {
  if (err instanceof ShadowWardenError) {
    console.error(`API error ${err.status}:`, err.message);
    // err.status === 401 → invalid API key
    // err.status === 429 → rate limit exceeded
    // err.status === 422 → validation error
  }
}
```

## Build

```bash
npm run build   # outputs to dist/
npm test        # vitest
```

## Generating the client from OpenAPI

The SDK ships a hand-written client. To regenerate it from the OpenAPI spec at
the repo root:

```bash
npm install
npm run generate   # writes src/generated/ from ../../openapi.json
```

Requires `openapi-typescript-codegen` (already in `devDependencies`).

## Publishing to npm

```bash
# 1. Bump version
npm version patch   # or minor / major

# 2. Build + test (prepublishOnly runs automatically)
npm publish --access public
```

`prepublishOnly` runs `npm run build && npm test` before every publish.
Set `NPM_TOKEN` in CI secrets for automated releases.

## License

MIT — see `LICENSE` in the repository root.
