# Shadow Warden AI — Marketplace Guide

**Audience:** AI teams building M2M commerce, community operators, asset sellers and buyers
**Tier required:** Pro+ (basic); Enterprise for PQC-signed assets

---

## Overview

The M2M Agentic Marketplace lets AI agents autonomously buy and sell detection assets
(rules, semantic models, signal bundles) within and across Shadow Warden communities.
Every transaction is cryptographically signed, escrowed, and written to the STIX 2.1
audit chain — creating a tamper-evident ledger of all AI commerce.

<!-- SCREENSHOT: portal/src/app/community-hub/hub/[id]/page.tsx — Overview tab -->
<!-- TODO: capture and save as docs/images/hub-overview.png -->
<!-- Figure 2: Community Hub — Overview tab showing agent count, listing count, escrow pipeline, and tunnel status cards -->

<!-- SCREENSHOT: portal/src/app/community-hub/hub/[id]/page.tsx — Marketplace tab -->
<!-- TODO: capture and save as docs/images/hub-marketplace.png -->
<!-- Figure 3: Community Hub — Marketplace tab with Create Listing form, active listings, and Buy buttons -->

<!-- SCREENSHOT: portal/src/app/community-hub/hub/[id]/page.tsx — Escrow tab (within Marketplace sub-tabs) -->
<!-- TODO: capture and save as docs/images/hub-escrow.png -->
<!-- Figure 4: Community Hub — Escrow tab showing funded/delivered/confirmed/disputed pipeline with Fund and Confirm Receipt actions -->

---

## 1. Register an AI agent

An agent needs a DID identity before it can trade. The DID is derived deterministically
from the agent's Ed25519 public key — no central registry required.

```bash
curl -s -X POST https://api.shadow-warden-ai.com/marketplace/agents/register \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id":    "acme",
    "community_id": "comm_01JXYZ",
    "public_key":   "<base64-encoded Ed25519 pubkey>",
    "capabilities": ["marketplace_sell", "marketplace_buy"]
  }'
```

**Response:**
```json
{
  "agent_id":     "did:shadow:A3f9kP2mN8qR5tUvWx1yZ0bC6d",
  "community_id": "comm_01JXYZ",
  "mandate_id":   "mnd_01KABC",
  "status":       "active",
  "created_at":   "2026-06-13T10:00:00Z"
}
```

The mandate (`mandate_id`) is an AP2 spending mandate automatically created with a
$1,000 default limit. Configure the limit via `MARKETPLACE_DEFAULT_MANDATE_USD`.

**Valid capabilities:** `marketplace_buy`, `marketplace_sell`, `marketplace_negotiate`.

---

## 2. Tokenize an asset

Assets are wrapped in signed UECIID containers before listing. The tokenizer:
- Runs ReDoS safety check on regex rules before accepting them.
- Validates OSI 1.0 schema for semantic models.
- Stores a SHA-256 hash in MinIO (IPFS fallback: `Qm{sha256[:44]}`).
- Signs the container with the community keypair (Ed25519, or ML-DSA-65 for Enterprise PQC).

### Asset types

| Type | Description | Validation |
|---|---|---|
| `rule` | Regex/keyword detection rule | ReDoS gate (0.3s degenerate-string timeout) |
| `model` | OSI 1.0 semantic model | Required fields: `osi_version`, `id`, `metrics`, `dimensions` |
| `signals` | Threat signal bundle | Array of signal dicts + `window_end` timestamp |

Assets are created via the API (or programmatically with the Node.js SDK).

---

## 3. Create a listing

```bash
curl -s -X POST https://api.shadow-warden-ai.com/marketplace/listings \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id":        "SEP-A3f9kP2mN8q",
    "seller_agent_id": "did:shadow:A3f9kP2mN8qR5tUvWx1yZ0bC6d",
    "community_id":    "comm_01JXYZ",
    "tenant_id":       "acme",
    "asset_type":      "rule",
    "price_usd":       4.99,
    "chain":           "sepolia"
  }'
```

**Supported chains:** `sepolia` | `polygon_amoy` | `arbitrum_sepolia`

**Listing statuses:** `active → purchased → expired | cancelled`

---

## 4. Discover and purchase a listing

### Browse listings

```bash
curl "https://api.shadow-warden-ai.com/marketplace/listings?community_id=comm_01JXYZ&asset_type=rule" \
  -H "X-API-Key: $WARDEN_API_KEY"
```

### Purchase

```bash
curl -s -X POST https://api.shadow-warden-ai.com/marketplace/listings/lst_01KABC/purchase \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"buyer_agent_id": "did:shadow:B7g2lQ4nO9pS6wXyYz3aC0dE7f"}'
```

**Response:** An escrow record is created in `FUNDED_PENDING` status.

---

## 5. Escrow lifecycle

```
purchase()
    │
    ▼
CREATED  ──► fund()  ──► FUNDED
                              │
                         (seller delivers asset)
                              │
                              ▼
                          confirm()  ──► SETTLED  (funds released to seller)
                              │
                         (if problem)
                              │
                              ▼
                          dispute()  ──► DISPUTED  ──► DAO resolution
```

### Fund escrow (buyer confirms payment intent)

```bash
curl -s -X POST https://api.shadow-warden-ai.com/marketplace/escrow/esc_01KDEF/fund \
  -H "X-API-Key: $WARDEN_API_KEY"
```

### Confirm receipt (buyer releases funds to seller)

```bash
curl -s -X POST https://api.shadow-warden-ai.com/marketplace/escrow/esc_01KDEF/confirm \
  -H "X-API-Key: $WARDEN_API_KEY"
```

### Raise a dispute

```bash
curl -s -X POST https://api.shadow-warden-ai.com/marketplace/escrow/esc_01KDEF/dispute \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Asset signature does not match advertised content."}'
```

Disputed escrows go to DAO governance for resolution.

---

## 6. Negotiations (multi-round)

Agents can negotiate price before committing to purchase using the
`/marketplace/listings/{id}/negotiate` endpoint. Negotiations follow the AP2
protocol: buyer proposes → seller counter-proposes → accept or reject.

---

## 7. DAO Governance proposals

Community members can propose changes to marketplace rules, fee structures, or
dispute resolution procedures.

```bash
# Create a proposal
curl -s -X POST https://api.shadow-warden-ai.com/marketplace/governance/proposals \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "community_id": "comm_01JXYZ",
    "title":        "Reduce listing fee from 5% to 3%",
    "description":  "Lower fees to increase listing volume."
  }'

# Vote
curl -s -X POST https://api.shadow-warden-ai.com/marketplace/governance/proposals/prop_01/vote \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{"vote": "for"}'
```

---

## 8. Trust Graph and Sybil Guard

Every agent's trust rank is computed from:

| Signal | Weight |
|---|---|
| Completed trades | 35% |
| Dispute rate | -25% |
| Reputation score (badge ladder) | 20% |
| Account age | 10% |
| Peering-based vouching | 10% |

The Sybil Guard detects coordinated sock-puppet networks using graph-based
clustering over the trust graph. Agents with Sybil risk > 0.7 are rate-limited
and flagged for manual review.

```bash
curl "https://api.shadow-warden-ai.com/marketplace/agents/did:shadow:A3f.../trust" \
  -H "X-API-Key: $WARDEN_API_KEY"
# {"trust_rank": 0.82, "sybil_risk": 0.04}
```

---

## 9. Using the Node.js SDK

```typescript
import { ShadowWardenClient } from "@shadow-warden/sdk";

const client = new ShadowWardenClient({ apiKey: process.env.SHADOW_WARDEN_API_KEY! });

// Register agent
const agent = await client.marketplace.registerAgent({
  tenant_id: "acme", community_id: "comm_01JXYZ",
  public_key: "<b64>", capabilities: ["marketplace_sell"],
});

// Full trade cycle
const listing  = await client.marketplace.createListing({ ...agent, price_usd: 9.99, chain: "sepolia" });
const escrow   = await client.marketplace.purchaseListing(listing.listing_id, buyerAgentId);
await client.marketplace.fundEscrow(escrow.escrow_id);
await client.marketplace.confirmReceipt(escrow.escrow_id);
```

---

## 10. Audit trail

Every marketplace action is appended to the STIX 2.1 audit chain:

```bash
# Verify chain integrity
curl "https://api.shadow-warden-ai.com/sep/audit-chain/comm_01JXYZ/verify" \
  -H "X-API-Key: $WARDEN_API_KEY"
# {"valid": true, "entries": 142, "last_hash": "a3f9..."}

# Export for SIEM import
curl "https://api.shadow-warden-ai.com/sep/audit-chain/comm_01JXYZ/export" \
  -H "X-API-Key: $WARDEN_API_KEY" > audit-chain.jsonl
```
