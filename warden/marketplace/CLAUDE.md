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
