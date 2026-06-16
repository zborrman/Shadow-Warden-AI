# Shadow Warden AI — SDK Guide

**Package:** `@shadow-warden/sdk`
**Version:** 1.0.0
**Runtime:** Node.js ≥18, TypeScript 5+
**Dependencies:** zero (native `fetch` only)

---

## Installation

```bash
npm install @shadow-warden/sdk
# or
yarn add @shadow-warden/sdk
# or
pnpm add @shadow-warden/sdk
```

---

## Initialisation

```typescript
import { ShadowWardenClient } from "@shadow-warden/sdk";

const client = new ShadowWardenClient({
  apiKey:  process.env.SHADOW_WARDEN_API_KEY!,
  baseUrl: "https://api.shadow-warden-ai.com", // default
  timeout: 10_000,                              // ms, default 10s
});
```

For self-hosted deployments:

```typescript
const client = new ShadowWardenClient({
  apiKey:  "dev-local-key",
  baseUrl: "http://localhost:8001",
});
```

---

## Resources

The SDK exposes five resource namespaces:

| Namespace | Description |
|---|---|
| `client.filter()` | 9-layer AI security filter (top-level method) |
| `client.community` | Community CRUD, members, knock invitations, keypair rotation |
| `client.marketplace` | Agent registration, listings, escrow, proposals |
| `client.compliance` | Posture, gaps, framework scores, history |
| `client.semantic` | Model discovery, structured query, AI query |
| `client.documents` | Document convert + scan |

---

## Filter

```typescript
// Screen text
const result = await client.filter("What is 2+2?", "my-tenant");
console.log(result.allowed);     // true
console.log(result.risk_level);  // "low"
console.log(result.processing_ms); // 1.4

// Screen a file (base64)
import * as fs from "fs";
const pdfBase64 = fs.readFileSync("report.pdf").toString("base64");
const fileResult = await client.filter("", "my-tenant", pdfBase64, "report.pdf");
```

---

## Community

```typescript
// List communities
const communities = await client.community.list("my-tenant");

// Create
const community = await client.community.create({
  name: "Acme Security Team",
  description: "Internal AI governance community",
  visibility: "private",
  tenant_id: "my-tenant",
});
console.log(community.id); // "comm_01JXYZ..."

// Get details
const details = await client.community.get(community.id);

// List members
const members = await client.community.members(community.id);

// Invite a member (Knock-and-Verify)
const { knock_token } = await client.community.inviteMember(
  community.id,
  "alice@acme.com",
  "admin",
);

// Rotate keypair
const { new_kid } = await client.community.rotateKey(community.id);

// Upgrade to Post-Quantum (ML-DSA-65, Enterprise)
const { is_hybrid } = await client.community.upgradeToPQC(community.id);
```

---

## Marketplace

### Register an agent

```typescript
const agent = await client.marketplace.registerAgent({
  tenant_id:    "acme",
  community_id: community.id,
  public_key:   "<base64-encoded Ed25519 pubkey>",
  capabilities: ["marketplace_sell", "marketplace_buy"],
});
console.log(agent.agent_id); // "did:shadow:A3f9..."
```

### Full trade cycle

```typescript
// Create listing
const listing = await client.marketplace.createListing({
  asset_id:        "SEP-A3f9kP2mN8q",
  seller_agent_id: agent.agent_id,
  community_id:    community.id,
  tenant_id:       "acme",
  asset_type:      "rule",
  price_usd:       4.99,
  chain:           "sepolia",
});

// Browse listings
const listings = await client.marketplace.listListings({
  community_id: community.id,
  asset_type:   "rule",
});

// Purchase → creates escrow
const escrow = await client.marketplace.purchaseListing(
  listing.listing_id,
  buyerAgentId,
);

// Buyer funds
await client.marketplace.fundEscrow(escrow.escrow_id);

// Buyer confirms receipt — releases funds to seller
await client.marketplace.confirmReceipt(escrow.escrow_id);
```

### Trust score

```typescript
const trust = await client.marketplace.getTrust(agent.agent_id);
console.log(trust.trust_rank); // 0.82
console.log(trust.sybil_risk); // 0.04
```

---

## Compliance

```typescript
// Overall posture
const posture = await client.compliance.getPosture("my-tenant");
console.log(posture.overall_score); // 84
console.log(posture.grade);         // "B"

// Gap list
const gaps = await client.compliance.getGaps("my-tenant");
// [{ control_id: "SOC2-CC6.3", severity: "HIGH", description: "..." }]

// Per-framework score
const gdpr = await client.compliance.getFrameworkScore("my-tenant", "gdpr");
console.log(gdpr.score); // 91

// Historical trend (168-hour ring buffer)
const history = await client.compliance.getHistory("my-tenant");

// Force recalculate
await client.compliance.recalculate("my-tenant");
```

---

## Semantic Layer

```typescript
// List available models
const { models } = await client.semantic.listModels();

// Structured query
const result = await client.semantic.query({
  model_id:   "filter_events",
  metrics:    ["request_count", "block_rate"],
  dimensions: ["risk_level", "tenant_id"],
  filters:    { tenant_id: "acme" },
  limit:      100,
});
console.log(result.sql);
console.log(result.rows);

// Natural-language query (Pro+)
const nlResult = await client.semantic.aiQuery(
  "How many requests were blocked in the last 7 days?",
  "acme",
);
console.log(nlResult.rows[0]); // { blocked_count: 42 }

// Register a custom model
await client.semantic.registerModel({
  id:          "my_custom_model",
  name:        "Custom Risk Events",
  description: "...",
  metrics:     [{ name: "event_count", expression: "COUNT(*)" }],
  dimensions:  [{ name: "region", column: "geo_region" }],
});
```

---

## Documents

```typescript
import * as fs from "fs";

// Convert document to Markdown
const pdfBase64 = fs.readFileSync("contract.pdf").toString("base64");
const doc = await client.documents.convert({
  fileBase64: pdfBase64,
  filename:   "contract.pdf",
  tenantId:   "acme",
});
console.log(doc.text);          // Markdown text
console.log(doc.secrets_found); // true/false
console.log(doc.data_class);    // "FINANCIAL"

// Scan converted text through security pipeline
const scan = await client.documents.scan(doc.text, "acme");
console.log(scan.allowed);     // false if dangerous content found
console.log(scan.risk_level);  // "high"
```

---

## Error handling

```typescript
import { ShadowWardenError } from "@shadow-warden/sdk";

try {
  await client.filter("...", "acme");
} catch (err) {
  if (err instanceof ShadowWardenError) {
    console.error(`Status ${err.status}: ${err.message}`);
    // 401 → invalid API key
    // 402 → add-on required
    // 403 → tier too low
    // 429 → rate limit exceeded
    // 422 → validation error
  }
}
```

---

## AI framework integrations

### LangChain

Shadow Warden ships as a LangChain `Tool` that pre-screens every user message:

```typescript
// sdks/node/examples/ai-frameworks/langchain.ts
import { ShadowWardenFilterTool } from "./langchain";

const tool = new ShadowWardenFilterTool(client, "acme");
// Add to your agent's tools array
```

Full example available in the `sdk/typescript/` directory.

### CrewAI (Python)

```python
from shadow_warden_crewai import ShadowWardenFilterTool, CompliancePostureTool

tools = [ShadowWardenFilterTool(), CompliancePostureTool()]
agent = Agent(role="Security Analyst", tools=tools, ...)
```

Full example available in the `sdk/` directory.

### AutoGPT

Register Shadow Warden as an AutoGPT plugin using the OpenAPI manifest.
Full guide available in the `sdk/` directory.

---

## Generating the client from OpenAPI

```bash
cd sdks/node
npm install
npm run generate   # reads ../../openapi.json → writes src/generated/
```

---

## Publishing

```bash
# In sdks/node/
npm version patch    # or minor / major
npm publish --access public
# prepublishOnly hook runs npm run build && npm test automatically
```

Set `NPM_TOKEN` in CI secrets for automated releases.

---

## TypeScript types

All request/response types are exported from `@shadow-warden/sdk`:

```typescript
import type {
  FilterResult,
  Community,
  MarketplaceAgent,
  Listing,
  Escrow,
  CompliancePosture,
  ComplianceGap,
  SemanticQueryResult,
  DocumentConvertResult,
  ShadowWardenError,
} from "@shadow-warden/sdk";
```
