---
name: marketplace-escrow
description: Trustless escrow lifecycle for M2M trades on Shadow Warden. States: pending_deposit → funded → delivered → confirmed | disputed → resolved_buyer | resolved_seller | cancelled. 48-hour delivery timeout. DAO governance for dispute resolution with weighted TrustRank voting. Use when implementing escrow flows, handling disputes, integrating the DAO layer, or debugging stuck escrows.
---

## Escrow lifecycle

```
POST /marketplace/escrow
{ listing_id, buyer_agent_id, seller_agent_id, amount_usd, purchase_id? }
→ { escrow_id, contract_address, status: "pending_deposit" }

POST /marketplace/escrow/{id}/fund    → status: "funded"
POST /marketplace/escrow/{id}/deliver { asset_hash }  → status: "delivered"
POST /marketplace/escrow/{id}/confirm → status: "confirmed" (finalizes purchase)
POST /marketplace/escrow/{id}/dispute { reason } → status: "disputed"
POST /marketplace/escrow/{id}/resolve { release_to_buyer: bool } → resolved
```

## Delivery timeout

`ESCROW_DELIVERY_TIMEOUT_HOURS` (default 48h). Expired funded escrows are auto-cancelled by the Flink watchdog (`FlinkAgentRunner._watchdog_loop`, every 5 min) and funds returned to buyer.

Check stuck escrows: `GET /marketplace/escrows?status=funded&agent_id=<id>`

## Contract deployment

- Real: deploys `warden/blockchain/contracts/Escrow.sol` via Web3 (Sepolia / Ganache / eth_tester)
- Simulation: `contract_address = keccak256(buyer|seller|listing|nonce)[:20]` (deterministic)
- Circuit breaker: 3 RPC retries → `EscrowDeploymentError` → HTTP 502

Set chain via `chain` field in listing (default `"sepolia"`).

## Dispute resolution via DAO

```
POST /marketplace/proposals
{ community_id, proposer_id, proposal_type: "dispute_resolution", target_id: escrow_id }

POST /marketplace/proposals/{id}/vote
{ voter_id, choice: 0 }  # 0 = release to buyer, 1 = release to seller

POST /marketplace/proposals/{id}/execute
```

Vote weight = `TrustRank × 100` (minimum 1). Quorum: `max(2, ceil(15% × member_count))`.

## Prometheus metrics

- `warden_marketplace_escrow_created_total`
- `warden_marketplace_escrow_disputed_total`
- `warden_marketplace_escrow_resolved_total`
- `warden_marketplace_trade_volume_usd_total`

## Env vars

| Var | Default | Effect |
|---|---|---|
| `ESCROW_DELIVERY_TIMEOUT_HOURS` | `48` | Auto-cancel after this period |
| `DAO_GOVERNANCE_ENABLED` | `false` | Enable DAO dispute voting |
| `DAO_QUORUM_PCT` | `0.15` | Minimum quorum fraction |
| `DAO_PROPOSAL_TTL_HOURS` | `72` | Proposal expiry |
