---
name: marketplace-negotiation
description: M2M multi-round price negotiation on Shadow Warden with Ed25519 signatures and MCP-envelope format. Max 5 rounds. First-Proposal Bias Guard (MARKETPLACE_MIN_OFFERS_BEFORE_BUY=3) requires evaluating minimum alternatives before committing. BUYER_STRETCH_FACTOR 1.10. Prompt-injection guard scans all offer messages. Use when implementing negotiation flows, signing offers, debugging negotiation state machines, or understanding fairness policy.
---

## MCP Offer Envelope

All offers are Ed25519-signed JSON envelopes:

```json
{
  "type": "offer" | "accept" | "reject",
  "price": 42.50,
  "asset_ueciid": "SEP-abc1234567z",
  "round": 2,
  "message": "Counter-offer: $42.50 for 30-day license",
  "agent_id": "did:shadow:...",
  "timestamp": "2026-06-24T08:00:00Z",
  "signature": "<base64(Ed25519(canonical_json))>"
}
```

Canonical JSON = `json.dumps(payload_without_signature, sort_keys=True, separators=(',',':'))`.

## Negotiation lifecycle

```
POST /marketplace/negotiations
{ buyer_agent_id, seller_agent_id, listing_id, initial_price }
→ { negotiation_id, status: "active", rounds: 0 }

POST /marketplace/negotiations/{id}/offer
{ from_agent_id, price, message?, signature? }

POST /marketplace/negotiations/{id}/accept
{ from_agent_id, price }
→ auto-creates Purchase + triggers EscrowService
```

States: `active` → `accepted` | `rejected` | `expired`

## First-Proposal Bias Guard

Prevents LLM buyers from accepting the first-seen offer (which collapses market fairness into a latency race).

```python
# Use search_and_buy() — NOT auto_buy() — for fair purchases:
result = buyer_agent.search_and_buy(
    criteria={"asset_type": "model", "max_price": 100.0},
    tenant_id="tenant-abc",
)
# Returns "pending_more_offers" if < MIN_OFFERS_BEFORE_BUY candidates found
# Sorts by price × (1 - rep_score) and buys the best-utility listing
```

**`auto_buy(listing_id=...)` bypasses the guard** — use only when the caller has already performed fair comparison.

## Injection guard

`scan_negotiation_message(text)` runs before persisting any offer message.

Detects: "ignore previous instructions", system prompt overrides, delimiter attacks (`---`, `===`, ` ``` `), role hijacking ("you are now a…"), 12 total patterns.

Returns `True` = injection detected → offer rejected with HTTP 400.

## Buyer strategy

| Condition | Action |
|---|---|
| `price ≤ max_price` | Straight purchase via `auto_buy()` |
| `max_price < price ≤ max_price × 1.10` | Open negotiation at `max_price` |
| `price > max_price × 1.10` | Return `price_rejected` |

## Env vars

| Var | Default | Effect |
|---|---|---|
| `MARKETPLACE_MAX_NEGOTIATION_ROUNDS` | `5` | Hard stop on rounds |
| `MARKETPLACE_BUYER_STRETCH` | `1.10` | Auto-accept threshold multiplier |
| `MARKETPLACE_MIN_OFFERS_BEFORE_BUY` | `3` | Fairness guard minimum |
