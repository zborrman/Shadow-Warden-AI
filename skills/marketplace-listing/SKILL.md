---
name: marketplace-listing
description: Asset tokenization and listing lifecycle on Shadow Warden marketplace. Asset types: rule (detection rule) / model (Semantic Layer model) / signals (threat signal batch). Dynamic pricing: price = base * (1 + demand_factor * demand_score). Auto-delist stale signals after 48h. Ed25519 + IPFS hash tokenization via AssetTokenizer. UECIID (SEP-{11 base-62}) as canonical asset ID. Use when creating listings, pricing assets, managing the tokenization pipeline, or debugging stale signal delist.
---

## Asset types

| Type | Content | Import chain after purchase |
|---|---|---|
| `rule` | EvolutionEngine detection rule (keyword or regex) | `EvolutionEngine.inject_rule()` hot-reload |
| `model` | Semantic Layer model (OSI 1.0 JSON schema) | `SemanticEngine.register_model()` hot-reload |
| `signals` | Timed batch of threat signal dicts | `ingest_marketplace_signals()` → corpus + Redis |

## Asset tokenization

```
POST /marketplace/assets
{ tenant_id, seller_agent_id, asset_type, raw_data }
→ { asset_id: "SEP-abc1234567z", ipfs_hash, signature }
```

`AssetTokenizer` in `warden/marketplace/tokenizer.py`:
1. Canonical JSON (sorted keys)
2. SHA-256 content hash
3. Ed25519 signature with community keypair
4. IPFS pin (falls back to SHA-256 CID simulation if IPFS unavailable)
5. UECIID via `snowflake_id → base62 → SEP-{11}` 

## Listing lifecycle

```
POST /marketplace/listings
{ asset_id, seller_agent_id, community_id, tenant_id, asset_type,
  price_usd, pricing_strategy: "fixed"|"dynamic" }
→ { listing_id, status: "active" }

GET /marketplace/listings?asset_type=rule&max_price=50&community_id=comm-xyz
GET /marketplace/listings/{listing_id}

POST /marketplace/listings/{listing_id}/purchase
{ buyer_agent_id }
→ { purchase_id, escrow_id, price_paid }
```

## Dynamic pricing

```python
effective_price = base_price * (1 + demand_factor * demand_score)
# demand_score = min(competing_listings / 10.0, 1.0)
# demand_factor = MARKETPLACE_DEMAND_FACTOR (default 0.5)
```

## Stale signal auto-delist

`SellerAgent.delist_if_stale()` marks `signals` listings older than `MARKETPLACE_SIGNAL_STALE_HOURS` (default 48h) as `"stale"`. Stale listings are excluded from search results.

## Sybil gate on publish

`POST /marketplace/listings` runs `SybilGuard.is_flagged(seller_agent_id)` before accepting. Flagged agents receive HTTP 403.

## Env vars

| Var | Default | Effect |
|---|---|---|
| `MARKETPLACE_DEMAND_FACTOR` | `0.5` | Dynamic price multiplier |
| `MARKETPLACE_SIGNAL_STALE_HOURS` | `48` | Auto-delist threshold |
| `MARKETPLACE_RATE_LIMIT_PER_MINUTE` | `100` | Per-tenant rate limit |
