# warden/marketplace — Project Memory

## Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Python 3.11+, FastAPI, ARQ (async jobs) |
| Storage | SQLite (`MARKETPLACE_DB_PATH`, default `/tmp/warden_marketplace.db`) |
| Crypto | Ed25519 signing (`cryptography` library), Fernet for vault secrets |
| Identity | DID format: `did:shadow:{base62(sha256(pubkey_bytes)[:32])}` |
| Assets | UECIID: `SEP-{11 base-62 chars}` from Snowflake ID via `sep.py` |
| Escrow | Web3 / eth_tester simulation; `warden/blockchain/contracts/Escrow.sol` |
| Threat detection | MAESTRO: GoalMisalignmentDetector + CollusionDetector + ModelPoisoningDetector |
| Loop state | `data/AGENTS.md` — written by `sova_marketplace_state_sync` every 15 min |

## M2M Base Endpoints (all required)

```
POST /marketplace/register             ← Stage 1: first-contact DID registration
GET  /marketplace/protocol             ← Stage 1: capability manifest + X-Protocol-Version header
GET  /marketplace/protocol/schema/{a}  ← Stage 1: JSON Schema download for action payload validation
POST /marketplace/action               ← Stages 2-4: unified action dispatcher (14 action types)
POST /marketplace/clear                ← Stage 4: ClearingEngine — winner + auto-reject losers
POST /marketplace/analytics/query      ← MCP/SOVA: SELECT-only SQL gate (500 row cap)
```

## 4-Stage M2M Lifecycle

| Stage | Action Types | Key Module |
|-------|-------------|-----------|
| **1** Registration | `register_agent` | `api.py` → `api_agents.py` |
| **2** Search | `search` | `api.py` → `vector_search.py` |
| **3** Negotiate | `send_proposal`, `send_message`, `send_offer`, `accept_offer`, `negotiate` | `api.py` + `brand_agent.py` |
| **4** Clear | `sending_payments`, `reject_proposal` + `POST /clear` | `api.py` + `clearing.py` |

## File Map

| File | Responsibility |
|------|----------------|
| `agent.py` | `MarketplaceAgent` dataclass, `register_agent()`, `pubkey_to_agent_id()`, `update_agent()` |
| `buyer_agent.py` | `BuyerAgent`: `search_and_buy()` (fairness guard), `auto_buy()`, `search_assets_semantic()` |
| `seller_agent.py` | `SellerAgent`: `publish_listing()`, `delist_if_stale()`, `update_price()` |
| `listing.py` | `Listing` dataclass, `get_listings()`, `buy_listing()`, dynamic pricing |
| `negotiations.py` | `Negotiation`, `start_negotiation()`, `send_offer()`, `accept_offer()` |
| `escrow.py` | `Escrow`, `EscrowService`, lifecycle state machine |
| `tokenizer.py` | `AssetTokenizer`: Ed25519 + IPFS-hash → UECIID container |
| `reputation.py` | `ReputationEngine`: TrustRank PageRank + Sybil detection |
| `maestro.py` | Three threat detectors + `_run_isolation_pipeline()` |
| `analytics.py` | `fairness_stats()`, `marketplace_summary()` |
| `brand_agent.py` | `BrandAgentFilter`: 4-gate seller-side validation (deny-list, TrustRank, rate limit, capability) |
| `clearing.py` | `ClearingEngine`: auto-reject losers + dual-write SQLite+PostgreSQL |
| `memory.py` | `AgentHandoffMemory` Layer 2: Redis+SQLite, compact_prompt(), ~61% token savings |
| `vector_search.py` | Layer 3: pgvector semantic search + SQLite keyword fallback |
| `api.py` | All aggregator endpoints + inline Stage 2-4 handlers + protocol schemas |
| `api_agents.py` | Full agent CRUD + key rotation + capabilities |
| `api_listings.py` | Listing CRUD + purchase + Sybil gate |
| `api_negotiations.py` | Negotiation lifecycle + injection guard |
| `api_escrow.py` | Escrow lifecycle + dispute |
| `api_maestro.py` | MAESTRO report + flags + auto-isolation trigger |

## Security Rules (non-negotiable)

1. **Every offer must be Ed25519-signed.** `scan_negotiation_message()` runs on every offer body before persist. Unsigned or injection-flagged offers → HTTP 400.
2. **First-Proposal Bias Guard is mandatory for LLM buyers.** Always call `search_and_buy()`, never `auto_buy()` directly unless the caller has already evaluated ≥ `MARKETPLACE_MIN_OFFERS_BEFORE_BUY` alternatives.
3. **`POST /analytics/query` is SELECT-only.** Any non-SELECT statement returns `{"error": "..."}` immediately. The `caller_agent_id` field scopes results — a query referencing another agent's DID is rejected (Confused Deputy guard).
4. **Sybil gate fires on every `POST /listings`.** `SybilGuard.is_flagged()` before accept. Flagged agents → HTTP 403.
5. **Escrow is required for all purchases.** `EscrowService` is invoked automatically on `accept_offer()`. Direct payment without escrow is not a supported flow.
6. **MAESTRO auto-isolation is fail-open.** All 7 isolation steps catch exceptions independently — partial failure must not block the remaining steps.
7. **No DDL/DML through the analytics gate.** Pattern: `stmt.upper().startswith("SELECT")` check in `analytics_sql_query()`.
8. **Federation deny-list fires before registration.** `check_threat_hash()` in `api_agents.register_agent()` — HTTP 403 if flagged.
9. **Brand Agent is fail-open.** All 4 gates catch exceptions independently. `BRAND_AGENT_MIN_TRUST=0.0` (default) disables TrustRank gate until reputation data exists. Rate limit skipped when `REDIS_URL=memory://`.
10. **ClearingEngine dual-write is fail-open.** SQLite write always runs first; PostgreSQL write is async and silently skipped if `DATABASE_URL` is unset.

## Testing Conventions

Run all marketplace tests (71 total, all must pass):
```bash
ALLOW_UNAUTHENTICATED=true WARDEN_API_KEY="" ANTHROPIC_API_KEY="" \
LOGS_PATH="/tmp/warden_test_logs.json" DYNAMIC_RULES_PATH="/tmp/dr.json" \
REDIS_URL="memory://" MODEL_CACHE_DIR="/tmp/warden_test_models" \
python -m pytest warden/tests/test_marketplace*.py -v --tb=short --no-cov
```

Test files:
- `test_marketplace_m2m.py` — 23 tests: protocol shape, action dispatcher, fairness guard, Confused Deputy
- `test_marketplace_three_layer_db.py` — 21 tests: Layer 2 handoff memory, Layer 3 vector search
- `test_marketplace_m2m_lifecycle.py` — 27 tests: 4-stage lifecycle, Brand Agent, ClearingEngine

### Test isolation pattern

Use `tmp_path` fixture for DB isolation — every test class gets its own SQLite file:
```python
os.environ["MARKETPLACE_DB_PATH"] = str(tmp_path / "mkt.db")
```

Do **not** share `MARKETPLACE_DB_PATH` across test classes — concurrent writes corrupt SQLite.

### BuyerAgent constructor

```python
BuyerAgent(agent_id="test-buyer-001", db_path=str(tmp_path / "mkt.db"))
```
`agent_id` is required (positional).

## Monetization (v6.6+)

Three access tiers for marketplace participation:

| Tier | Model | Details |
|------|-------|---------|
| Pay-per-Use | x402/1.0 USDC nanopayments | `$0.000001` per search call; `PAYMENT-SIGNATURE` header |
| Enterprise Take Rate | 1.5% of GMV | Applied at ClearingEngine with Decimal math (no float drift) |
| Verified TrustRank | Custom | Sponsored listing boost (+0.15 similarity), security-audit badge |

### Monetization Security Rules

11. **Take rate is logged-only in v1.** `ClearingResult.platform_fee_usd` is computed and persisted, but no on-chain USDC transfer occurs until Circle Gateway integration (v2). Never call `usdc.py` from `clearing.py` in v1.
12. **Sponsored boost max +0.15.** Applied in Python after vector index fetch — never in SQL ORDER BY (would disable HNSW index). Every search result must include `"sponsored": bool` so UIs can render "Ad" labels.
13. **x402 gate is fail-open.** Gate errors in `require_payment()` must never raise exceptions to the caller. Exceptions → `log.warning()` and return `None` (allow).
14. **x402 deductions are batched.** `deduct_payment()` writes to `x402_pending_deductions` queue. Do not attempt per-call on-chain settlement.
15. **PAYMENT-SIGNATURE and PAYMENT-REQUIRED are the canonical x402 header names.** Do not use `X-Payment-Token` or any other custom header name.
16. **Credits take priority over x402.** `require_payment()` checks Flex Credits FIRST; if balance ≥ 1 credit, deducts and returns None (allow). x402 USDC path is only reached when credits are exhausted.
17. **Autonomy check fires before payment acceptance.** REQUIRE_APPROVAL → HTTP 202 + `X-Requires-Approval: pending`. BLOCK → HTTP 403. Both return before any credit or x402 deduction.
18. **KYA registration is fail-open.** `register_market_agent()` proceeds even if KYA screening fails; `kya_status` defaults to "PENDING" on error.
19. **KYA revoke requires X-Admin-Key.** `POST /marketplace/agents/{id}/kya/revoke` uses `ADMIN_KEY` env var, same as `/billing/addons/grant`.
20. **MasterAgent autonomy check is fail-open.** `check_action()` exceptions → fall through to text-scan for REQUIRES_APPROVAL. Never block MasterAgent execution on autonomy policy errors.
21. **KYB enforcement is opt-in and fail-conservative, never fail-open toward ALLOW.** `KYB_ENFORCEMENT_ENABLED` defaults `false` — existing tenants are never retroactively capped by shipping `kyb.py`. Once enabled, a KYA/KYB lookup failure caps the agent at REQUIRE_APPROVAL (same as an unverified owner), it never resolves to ALLOW. But if the flag itself can't be read, behavior must still fall back to "enforcement off" — never let a broken flag read silently cap every agent in production.
22. **Sanctions screening never blocks or delays clearing.** `clearing.py::clear_async()` calls `sanctions.screen_settlement_party()` after the outbox relay step; any exception is caught inside `_screen_sanctions()` and only logged. A HIT opens a `COMPLIANCE` incident via `incident_register.log_incident()` — it never raises, blocks, reverses, or holds the transaction. Opt-in via `SANCTIONS_SCREENING_ENABLED` (default `false`).

### Monetization Modules

| File | Responsibility |
|------|----------------|
| `x402_gate.py` | x402/1.0 middleware — credits-first check, autonomy gate, `require_payment()`, `deduct_payment()` |
| `clearing.py` | Take rate with Decimal math — `ClearingResult.platform_fee_usd`, `seller_net_usd` |
| `listing.py` | Sponsored listing fields — `is_sponsored`, `sponsored_until`, `kya_status` |
| `vector_search.py` | Sponsored boost in Python — fetch with HNSW index, apply +0.15 in memory |
| `api_listings.py` | `POST /listings/{id}/sponsor` — admin-grant sponsored status |
| `kya.py` | KYA framework — `KYARecord`, register/screen/revoke, Bayesian risk score via ERS |
| `kyb.py` | KYB framework (FT-5) — `KYBRecord`, owner (tenant) manual-review queue, sits behind KYA |
| `sanctions.py` | Sanctions screening at settlement (FT-5) — reuses staff `screen_sanctions_list()`, buyer-only, opens `incident_register` case on a hit, never blocks |
| `credits.py` | Flex Credits — prepaid balances, Redis DECRBY atomic deduct, SQLite persistence |
| `autonomy.py` | Progressive autonomy — `AutonomyPolicy`, L1/L2/L3 `check_action()`, Redis + SQLite; KYB-gates via `_owner_kyb_unverified()` |

## KYA Framework (v7.1)

Know Your Agent: owner-linking, risk scoring, compliance status badges.

```
register_agent(agent_id, owner_tenant_id) → KYARecord{PENDING}
screen_agent(agent_id)                    → KYARecord{VERIFIED | FLAGGED}
get_kya_status(agent_id)                  → "PENDING" | "VERIFIED" | "FLAGGED" | "REVOKED"
revoke_agent(agent_id, reason)            → None (status → REVOKED, Redis cleared)
```

Risk scoring v1: ERS Redis score proxy (`ers:{agent_id}` ≥ 0.75 → HIGH_VELOCITY flag).
v2: Persona/Crossmint external identity API integration.

## KYB Framework (FT-5)

Know Your Business: verifies the legal entity that *owns* an agent's DID —
sits one level up from KYA, which only screens the agent's own behavior.

```
submit_for_review(tenant_id, business_name) → KYBRecord{PENDING}   # queues for manual review
approve_kyb(tenant_id, reviewer)            → KYBRecord{VERIFIED}
reject_kyb(tenant_id, reviewer, reason)     → KYBRecord{REJECTED}
flag_kyb(tenant_id, reviewer, reason)       → KYBRecord{FLAGGED}
get_kyb_status(tenant_id)                   → "PENDING" | "VERIFIED" | "FLAGGED" | "REJECTED"
```

v1 has one `KYBProvider`: `ManualReviewProvider`, which always defers to
PENDING — there is no auto-verification path yet. The pluggable interface
exists so a Persona/Sumsub adapter can be dropped in later (v2) without
touching call sites.

**Enforcement is opt-in** (`KYB_ENFORCEMENT_ENABLED=false` default): when
on, `autonomy.check_action()` caps an agent at REQUIRE_APPROVAL — the L1
behavior — whenever its KYA-registered owner isn't KYB-VERIFIED, regardless
of the agent's own configured L2/L3 policy. "Agent inherits the owner's
compliance status." A KYB/KYA lookup failure while enforcement is on fails
toward capped (conservative), never toward silently allowing — but if
enforcement is off, or even unreadable, behavior is always unchanged from
before this framework existed. No payout-hold half exists: `docs/
licensing-posture.md` found no real payout mechanism anywhere in the
codebase for KYB status to gate.

## Sanctions Screening at Settlement (FT-5)

Screens the buyer of every clearing run against the (stub) sanctions
denylist, reusing the existing STAFF-05 `screen_sanctions_list()` tool.

```
clear_async() → _screen_sanctions(buyer_agent_id, clearing_id)
              → sanctions.screen_settlement_party(buyer_agent_id, clearing_id)
                  1. resolve owner tenant via kya.get_kya_record()
                  2. resolve display name via kyb.get_kyb_record().business_name
                  3. screen_sanctions_list(tenant_id, subject_name)
                  4. HIT → incident_register.log_incident(category="COMPLIANCE")
```

Opt-in (`SANCTIONS_SCREENING_ENABLED=false` default) and purely
observational — a HIT never blocks, delays, or reverses the clearing
transaction; it opens a case for human follow-up. Buyer-only in this slice:
seller screening needs a listing→seller_agent_id path `ClearingResult`
doesn't expose yet.

## Flex Credits (v7.1)

Prepaid balance system — 1 credit = $0.001 = 1 marketplace search.
Enterprise buyers get budget-predictable access without a crypto wallet.

```python
CREDIT_PACKAGES = {
    "credits_100":  {"credits": 100,  "price_usd": 0.10},
    "credits_500":  {"credits": 500,  "price_usd": 0.45},
    "credits_1000": {"credits": 1000, "price_usd": 0.85},
    "credits_5000": {"credits": 5000, "price_usd": 4.00},
}
```

Redis: `marketplace:credits:{tenant_id}` integer (DECRBY atomic).
SQLite: `marketplace_credits` in `MARKETPLACE_DB_PATH`.

## Progressive Autonomy L1/L2/L3 (v7.1)

```
L1 (Shadow):     all actions → REQUIRE_APPROVAL (safe default, no policy)
L2 (Supervised): amount < threshold AND action in allowed → ALLOW; else → REQUIRE_APPROVAL
L3 (Autonomous): amount <= max_spend AND action in allowed → ALLOW; else → BLOCK
```

Redis: `marketplace:autonomy:{agent_id}` JSON (24h TTL).
SQLite: `marketplace_autonomy_policies` in `MARKETPLACE_DB_PATH`.
`check_action(agent_id, action, amount_usd)` is fail-open — exceptions → REQUIRE_APPROVAL.

## Env Vars

| Var | Default | Effect |
|-----|---------|--------|
| `MARKETPLACE_DB_PATH` | `/tmp/warden_marketplace.db` | SQLite location |
| `MARKETPLACE_MIN_OFFERS_BEFORE_BUY` | `3` | First-Proposal Bias Guard minimum |
| `MARKETPLACE_MAX_NEGOTIATION_ROUNDS` | `5` | Hard stop on negotiation rounds |
| `MARKETPLACE_BUYER_STRETCH` | `1.10` | Auto-accept at max_price × 1.10 |
| `MARKETPLACE_DEMAND_FACTOR` | `0.5` | Dynamic pricing multiplier |
| `MARKETPLACE_SIGNAL_STALE_HOURS` | `48` | Auto-delist threshold for signals |
| `ESCROW_DELIVERY_TIMEOUT_HOURS` | `48` | Escrow auto-cancel timeout |
| `AGENT_KEY_ROTATION_MAX_DAYS` | `90` | Key rotation deadline |
| `MAESTRO_HIGH_THRESHOLD` | `0.7` | MAESTRO high-threat cutoff |
| `AGENTS_MD_PATH` | `data/AGENTS.md` | Loop state file path (gitignored, written every 15 min) |
| `BRAND_AGENT_MIN_TRUST` | `0.0` | TrustRank gate threshold (0 = off) |
| `BRAND_AGENT_MAX_RPM` | `60` | Rate limit per DID per minute |
| `MARKETPLACE_VECTOR_SEARCH` | `false` | Enable pgvector semantic search (Layer 3) |
| `HANDOFF_MEMORY_TTL` | `3600` | AgentHandoffMemory TTL in seconds (Layer 2) |
| `HANDOFF_DB_PATH` | `/tmp/warden_handoff.db` | SQLite fallback for handoff memory |
| `X402_GATE_ENABLED` | `false` | Enable x402 nanopayment gate for search |
| `MARKETPLACE_SEARCH_FEE_USD` | `0.000001` | Per-search fee (x402) |
| `MARKETPLACE_X402_DB_PATH` | `/tmp/warden_x402_marketplace.db` | x402 balance/deduction SQLite |
| `MARKETPLACE_X402_PAYMENT_ADDRESS` | `0x000...` | USDC recipient address |
| `MARKETPLACE_TAKE_RATE` | `0.015` | Platform take rate (1.5% default) |
| `PLATFORM_WALLET_ADDRESS` | `` | Platform wallet for fee settlement (v2) |
| `KYA_VERIFIED_ONLY` | `false` | Reject non-VERIFIED agents from search results |
| `KYA_AUTO_VERIFY_SCORE_THRESHOLD` | `0.3` | Auto-VERIFIED when risk_score ≤ this value |
| `KYB_ENFORCEMENT_ENABLED` | `false` | Cap `autonomy.check_action()` at REQUIRE_APPROVAL when the agent's owner isn't KYB-VERIFIED |
| `SANCTIONS_SCREENING_ENABLED` | `false` | Screen the buyer of every `clear_async()` run against the sanctions list |
