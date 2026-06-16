# Agent Tokenomics (WAT ERC-20) — MKT-11

**Version:** v6.6  
**Tier:** Enterprise  
**Add-on:** `agent_tokenomics_pack` — $39/mo

## Overview

ERC-20 Warden Agent Token (WAT) on Polygon Amoy. Agents earn tokens for successful task completion and spend them to purchase detection rules, semantic models, and signal bundles on the marketplace. Outcome-based pricing settles payment proportional to KPI achievement.

## Architecture

```
AgentToken.mint(agent_id, amount)
    ├── [WAT_SIMULATE=true]  → Redis incrbyfloat wat:balance:{agent_id}
    └── [Web3 mode]          → ERC-20 contract.mint() via Web3.py

OutcomePricingService.settle_outcome(listing_id, buyer_agent_id, achieved_value)
    → final_price = base_price * min(achieved / target, 1.0)
    → AgentToken.transfer(seller → buyer, final_price)
    → SQLite outcome_listings.status = "SETTLED"
```

## Files

| File | Role |
|------|------|
| `warden/tokenomics/__init__.py` | Package init |
| `warden/tokenomics/agent_token.py` | `AgentToken` — mint, transfer, balance; dual-rail (Web3 + simulation) |
| `warden/tokenomics/outcome_pricing.py` | `OutcomePricingService` — KPI-gated settlement SQLite |
| `warden/tokenomics/api.py` | FastAPI router `/tokenomics/*` |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/tokenomics/mint` | Mint WAT tokens to an agent (admin) |
| `GET` | `/tokenomics/balance/{agent_id}` | Query token balance |
| `POST` | `/tokenomics/listings/outcome` | Create an outcome-priced listing |
| `GET` | `/tokenomics/listings/outcome` | List all outcome listings |
| `POST` | `/tokenomics/listings/{listing_id}/settle` | Settle outcome with achieved KPI value |

## Outcome Pricing Formula

```
final_price_usd = base_price_usd × min(achieved_value / target_value, 1.0)
```

Settlement is capped at 100% of `base_price_usd` regardless of overachievement.

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `WAT_SIMULATE` | `true` | Use Redis ledger instead of blockchain |
| `WAT_CONTRACT_ADDRESS` | — | ERC-20 contract on Polygon Amoy |
| `POLYGON_AMOY_RPC_URL` | — | Polygon Amoy JSON-RPC endpoint |
| `WAT_DB_PATH` | `/tmp/warden_wat.db` | SQLite for outcome listings |

## Prometheus Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `warden_wat_transfers_total` | `rail` | Token transfers (`simulation` or `on_chain`) |
