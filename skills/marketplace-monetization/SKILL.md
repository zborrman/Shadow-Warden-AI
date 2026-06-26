---
name: marketplace-monetization
description: Guide for implementing and testing monetization features in the Shadow Warden AI M2M marketplace. Covers x402 nanopayments, platform take rate, sponsored listings, and agent discovery protocol.
---

# Marketplace Monetization Skill

## Key rules

1. **x402 headers**: Server returns `PAYMENT-REQUIRED` (base64 JSON). Client sends `PAYMENT-SIGNATURE` (base64 JSON with `agent_id`). Never use `X-Payment-Token`.

2. **Take rate math**: Always use `Decimal` with `ROUND_HALF_UP`. Never float arithmetic in billing code.
   ```python
   from decimal import Decimal, ROUND_HALF_UP
   fee = (Decimal(str(price)) * Decimal("0.015")).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
   ```

3. **Sponsored boost**: Apply +0.15 in Python AFTER fetching results with pure vector index. Never add boost in SQL `ORDER BY`.

4. **Agent Discovery Protocol**: `/.well-known/agent.json` is served by the A2A router (`warden/protocols/a2a/api.py`). Do not add duplicate routes.

5. **Fail-open gates**: `require_payment()` exceptions â†’ warn + allow. `deduct_payment()` exceptions â†’ warn + return True.

## Testing

```bash
# x402 gate
X402_GATE_ENABLED=true pytest warden/tests/test_marketplace*.py -k "x402" -v

# Sponsored boost
pytest warden/tests/test_marketplace_three_layer_db.py -k "sponsored" -v

# Take rate
MARKETPLACE_TAKE_RATE=0.015 pytest warden/tests/test_marketplace_m2m_lifecycle.py -k "clear" -v

# Full suite
ALLOW_UNAUTHENTICATED=true WARDEN_API_KEY="" REDIS_URL="memory://" \
  pytest warden/tests/test_marketplace*.py -v --tb=short --no-cov
```

## Env vars

| Var | Default | Notes |
|-----|---------|-------|
| `X402_GATE_ENABLED` | `false` | Enable per-search payment gate |
| `MARKETPLACE_SEARCH_FEE_USD` | `0.000001` | Per-search USDC cost |
| `MARKETPLACE_X402_DB_PATH` | `/tmp/warden_x402_marketplace.db` | Gate DB |
| `MARKETPLACE_TAKE_RATE` | `0.015` | Platform commission (1.5%) |
| `PLATFORM_WALLET_ADDRESS` | `` | Settlement wallet (v2) |

