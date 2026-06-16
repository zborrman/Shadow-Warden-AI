# USDC Multi-Rail Payments — MKT-12

**Version:** v6.6  
**Tier:** Enterprise  
**Add-on:** `usdc_payments_pack` — $29/mo

## Overview

USDC stablecoin payment processing via Coinbase Commerce or direct on-chain settlement. Supports multiple chains (Polygon, Ethereum, Arbitrum). Simulation mode auto-confirms on first `verify_payment()` call for testing.

## Architecture

```
POST /payments/usdc/intent
    → USDCService.create_payment_intent(amount_usd, merchant_wallet)
    ├── [USDC_SIMULATE=true]   → Redis SETEX usdc:intent:{id} (24h TTL)
    └── [Coinbase Commerce]    → _create_coinbase_charge() → Hosted payment URL

GET /payments/usdc/intent/{intent_id}
    → USDCService.verify_payment(intent_id)
    ├── [USDC_SIMULATE=true]   → auto-confirm first call → status CONFIRMED
    └── [Coinbase Commerce]    → GET /charges/{charge_code} → map status
```

## Files

| File | Role |
|------|------|
| `warden/payments/__init__.py` | Package init |
| `warden/payments/usdc.py` | `USDCService`, `PaymentIntent` dataclass; singleton `get_usdc_service(chain)` |
| `warden/payments/api.py` | FastAPI router `/payments/usdc/*` |

## PaymentIntent Fields

| Field | Type | Description |
|-------|------|-------------|
| `intent_id` | str | UUID4 unique identifier |
| `amount_usd` | float | Payment amount in USD |
| `merchant_wallet` | str | Receiving wallet address |
| `status` | str | `PENDING` → `CONFIRMED` → `FAILED` |
| `payment_rail` | str | `coinbase_commerce` or `on_chain` |
| `chain` | str | `polygon`, `ethereum`, `arbitrum` |
| `tx_hash` | str | On-chain transaction hash (when available) |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/payments/usdc/intent` | Create payment intent |
| `GET` | `/payments/usdc/intent/{intent_id}` | Verify / poll payment status |

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `USDC_SIMULATE` | `true` | Auto-confirm without blockchain |
| `COINBASE_COMMERCE_API_KEY` | — | Coinbase Commerce API key |
| `USDC_INTENT_TTL_S` | `86400` | Redis TTL for payment intents (24h) |
| `USDC_DEFAULT_CHAIN` | `polygon` | Default settlement chain |

## Prometheus Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `warden_usdc_intents_total` | `chain`, `status` | Payment intents by chain and final status |
