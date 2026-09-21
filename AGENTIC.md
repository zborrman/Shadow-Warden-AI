# AGENTIC.md — the M2M Agentic Marketplace

Orientation for anyone (human or coding agent) working on the machine-to-machine
commerce surface of Shadow Warden AI. `CLAUDE.md` governs the whole repo and
`warden/marketplace/CLAUDE.md` holds the 31 non-negotiable marketplace rules —
this file is the layer above both: **what the subsystem is, what is actually
running, and where its seams are.**

Every number below was measured on **2026-09-20** against `main` and the live
gateway. Nothing here is projected. Where a claim would exceed its row in
[docs/capability-matrix.md](docs/capability-matrix.md), the matrix wins.

---

## 1. The one-paragraph version

Shadow Warden runs a marketplace whose participants are **software agents, not
people**: an agent registers a DID derived from its own Ed25519 key, discovers a
machine-readable protocol manifest, searches listings, negotiates in signed
rounds, funds an escrow, and a clearing engine settles one winner and rejects the
losers. Five protocol surfaces speak to it (native M2M, A2A, ACP, UCP/AP2, MCP).
The security model is the product: every stage has a gate, and the gates
distinguish *identity* from *entitlement* from *authorization to spend*.

**It has never traded.** Production reports `agents 0, listings 0, trades 0,
volume $0`, `settlement_mode: simulated`, and `ready_to_trade: false`. The code
is real and tested; the market is empty. Treat those as two separate facts and
never let a document blur them.

---

## 2. Measured state

### Code

| Surface | Path | Modules | LOC |
|---|---|---|---|
| Marketplace core | [warden/marketplace/](warden/marketplace/) | 43 | 15,032 |
| Agentic commerce (UCP/AP2/MCP) | [warden/business_community/agentic_commerce/](warden/business_community/agentic_commerce/) | 11 | 1,963 |
| Protocols (A2A + ACP) | [warden/protocols/](warden/protocols/) | 11 | 1,580 |
| M2M storefront | [warden/m2m_store/](warden/m2m_store/) | 7 | 1,022 |

### Live API (`https://api.shadow-warden-ai.com`, v7.9.0, 663 paths total)

| Prefix | Paths |
|---|---|
| `/marketplace/*` | 59 |
| `/business-community/commerce/*` | 13 |
| `/acp/*` | 11 |
| `/m2m-store/*` | 9 |
| `/a2a/*` | 5 (+ `/.well-known/agent.json`) |

**113 HTTP operations** across those prefixes.

### Tests

53 test files, **712 test functions**. The four core M2M suites
(`test_marketplace_m2m`, `_m2m_lifecycle`, `_offer_signing`, `_route_auth`) run
**76 passed in 71 s**.

### Production posture, read from the live manifest

```
GET /marketplace/protocol   -> signature_enforced: true
                               settlement_mode:    "simulated"
                               chains:             ["base", "base_sepolia"]
                               min_offers_before_buy: 3, max_rounds: 5
GET /marketplace/stats      -> agents 0 - listings 0 - trades 0 - volume $0
GET /marketplace/readiness/default
                            -> ready_to_trade: false
                               missing: community_not_found, keypair_not_generated,
                                        audit_not_enabled, no_agents_registered
GET /.well-known/agent.json -> 200, A2A v1.0, version 7.9.0
GET /acp/manifest           -> 200, USD + USDC, max token $10,000
https://marketplace.shadow-warden-ai.com -> 404 (the Cloudflare Worker in
                                            workers/shadow-warden-marketplace/
                                            has never been deployed)
```

---

## 3. Five surfaces, one economy

They are **not** alternative implementations of the same thing. Know which one
owns a concept before you add to any of them — the feature freeze (`CLAUDE.md`,
P0) refuses a sixth.

| Surface | Owns | Entry point | Identity it trusts |
|---|---|---|---|
| **Marketplace core** | Listings, negotiation, escrow, clearing, trust, KYA/KYB | `POST /marketplace/action` | `did:shadow:*` Ed25519 signature |
| **A2A v1.0** | Task delegation between *foreign* agents | `POST /a2a/tasks` | API key or W3C VC; server E2E key |
| **ACP** | Shared Payment Tokens, carts, checkout, refunds | `/acp/*` | Authenticated tenant + HMAC SPT |
| **UCP / AP2** | Multi-agent procurement, auctions, mandates | `/business-community/commerce/*` | Tenant + signed AP2 mandate |
| **M2M storefront** | A merchant-side catalog an agent can buy from | `/m2m-store/*` | Tenant API key + FIDO2 token |

The marketplace core is canonical for **value transfer**. The other four either
delegate to it or settle in their own ledger; if you are about to add a second
way to move money, stop and read rules #5 and #23 in
[warden/marketplace/CLAUDE.md](warden/marketplace/CLAUDE.md).

---

## 4. The 4-stage lifecycle

All of stages 2–4 funnel through one dispatcher —
[api.py:634](warden/marketplace/api.py#L634) — so a gate added there covers
fourteen action types at once. That is deliberate, and it is why the dispatcher
is the highest-blast-radius function in the subsystem.

```
Stage 1  REGISTER     POST /marketplace/register      (deliberately unauthenticated:
         DISCOVER     GET  /marketplace/protocol       first contact, D-5)
                      GET  /marketplace/protocol/schema/{action}
             |  federation deny-list - first-registration-wins INSERT - KYA screen

Stage 2  SEARCH       POST /action {"action_type":"search"}
             |  Brand Agent (4 gates) - x402/credits gate - vector or keyword search
             |  sponsored boost applied in Python, never in ORDER BY (rule #12)

Stage 3  NEGOTIATE    send_proposal - send_message - send_offer - accept_offer - negotiate
             |  _assert_actor(): Ed25519 over build_offer_canonical(), fail-CLOSED
             |  injection scan - max 5 rounds - First-Proposal Bias guard (>= 3 offers)

Stage 4  CLEAR        create_escrow -> fund_escrow ("sending_payments") -> deliver_asset
                      -> confirm_receipt | raise_dispute
                      POST /marketplace/clear
             |  authorize_payment() -> reject losers -> Decimal take rate -> outbox -> PG
             |  sanctions screen (observational) - AssetImporter hot-loads the asset
```

An agent id **is** its public key: `did:shadow:{base62(sha256(pubkey))}`
([agent.py::pubkey_to_agent_id](warden/marketplace/agent.py)). That single design
choice is what lets a signature prove identity without a session — and it is why
rule #25 forbids trusting a body-supplied `agent_id` on its own.

---

## 5. Three identities, and the mistake of confusing them

The most common defect class in this subsystem's history is treating one of
these as another.

| Identity | Proves | Established by | Wrong use |
|---|---|---|---|
| **Tenant** | *Who is calling* | `X-API-Key` → `require_api_key` | Attributing an action to an agent |
| **Agent DID** | *Which agent acts* | Ed25519 signature over a canonical envelope | Reading it from the request body |
| **Payout address** | *Where money lands* | secp256k1 address bound by the agent's own signature | Any unsigned writer (rule #28) |

Nothing derives a payout address from a DID — different curves, no relation. An
unsigned writer for that field is a theft primitive, which is why
`PUT /marketplace/agents/{id}/payout-address` is fail-CLOSED with **no**
enforcement flag, and why `test_no_unsigned_writer_of_payout_address_exists`
greps for a reintroduction.

Three things that are **not** authentication, each of which has already been
mistaken for it here: a rate limiter, a feature/tier gate, and `if secret and
provided != secret`.

---

## 6. The money path

```
search      -> credits first (rule #16) -> x402 USDC -> charge only verified_payer()
purchase    -> autonomy L1/L2/L3 -> Budget Guardian -> escrow (one creator only)
clearing    -> authorize_payment() -> Decimal take rate 1.5% -> outbox -> PostgreSQL
settlement  -> ESCROW_SETTLE_CHAINS gate -> preflight -> contract call -> tx hash pinned
```

Four properties worth internalising before touching any of it:

1. **Idempotency is structural, not retried.** `clearing_id = f"clear-{winner_neg_id}"`,
   and `purchase_listing()` holds the FT-3c `Idempotency-Key`. A retry replays; it
   does not mint.
2. **Decimal, never float.** A take rate computed in float is a billing defect by
   construction.
3. **A price that cannot be read is not $0.00.** `_fetch_agreed_price()` raises.
   Clearing once settled every trade at zero because a bare `except` swallowed a
   column-name error — the money analogue of a silent ALLOW.
4. **A `TradeExists()` revert on `deposit` means funded, not failed** (rule #30).
   Reading it as a failure strands real funds.

---

## 7. Enforcement flags — the posture table

Every one of these is **off by default**, and all have explicit `docker-compose.yml`
passthroughs (warden has no `env_file`, so `.env`-only is a silent no-op).

| Flag | Default | Prod today | What it gates |
|---|---|---|---|
| `MARKETPLACE_REQUIRE_SIGNED_OFFERS` | `false` | **true** | Rejects unsigned offers (verification runs either way) |
| `ESCROW_SETTLE_CHAINS` | *(empty)* | *(empty)* | A **list**, never a boolean — nothing is sent on an unlisted chain |
| `AUTHORIZE_PAYMENT_ENFORCED` | `false` | `false` | The FT-6 payment chokepoint |
| `KYB_ENFORCEMENT_ENABLED` | `false` | `false` | Caps an agent at REQUIRE_APPROVAL when its owner isn't KYB-verified |
| `SANCTIONS_SCREENING_ENABLED` | `false` | `false` | Buyer screening at clearing (never blocks) |
| `X402_GATE_ENABLED` | `false` | `false` | Per-search nanopayment |
| `KYA_VERIFIED_ONLY` | `false` | `false` | Drops non-VERIFIED agents from search |

**Read the metric, not the code shape.**
`warden_payment_authorization_total{verdict,enforced}` distinguishes *allowed
because the checks passed* from *allowed because enforcement is off*. A path that
reads as gated may be evaluating nothing.

---

## 8. Fail-open vs fail-closed — the map

This is the table to consult before changing any `except` block here.

**Fail-CLOSED (a failure must deny):**
- Offer signature verification (`_assert_actor`) — unknown agent, missing key,
  absent signature, stale timestamp, verify error all reject.
- Payout-address binding — no flag, no bake-in mode.
- Every signing key via `resolve_key(..., purpose=...)` — unresolvable key denies.
- SAC URL screening at tool dispatch — SSRF/exfil blocks.
- The settle-chain gate — an unlisted chain sends nothing, for all six contract
  functions (gating only `deposit` would strand escrows).
- Marketplace write routes — `require_api_key`, ratcheted by
  [test_marketplace_route_auth.py](warden/tests/test_marketplace_route_auth.py),
  whose baseline may only shrink.

**Fail-OPEN by decision (a failure must not block):**
- Brand Agent's four gates, individually.
- MAESTRO auto-isolation, all seven steps independently.
- x402 gate errors, clearing's PostgreSQL relay, sanctions screening, KYA
  registration, the model router, GSAM telemetry.

**Fail-conservative (a failure caps, never allows):** KYB enforcement, and
autonomy's "no policy" ⇒ REQUIRE_APPROVAL. Never "fix" a blocked agent by making
no-policy resolve to ALLOW — that deletes the default the whole model rests on.

The asymmetry is the rule: **security decisions fail closed, telemetry fails
open.** Both halves appear in one function in `warden/sac/guard.py`; copy that
shape, not one half of it.

---

## 9. Data layer

| Store | Holds | Notes |
|---|---|---|
| `MARKETPLACE_DB_PATH` | agents, listings, negotiations, escrow, clearing, outbox, credits, autonomy, KYA/KYB | **Turso in production** (`TURSO_URL_MARKETPLACE`) |
| `MARKETPLACE_X402_DB_PATH` | x402 balances + pending deductions | Shares the `x402_balances` primitive with voice |
| `HANDOFF_DB_PATH` | Layer-2 agent handoff memory | Redis first, SQLite fallback |
| PostgreSQL / pgvector | Layer-3 long-term records + semantic search | Optional; `MARKETPLACE_VECTOR_SEARCH` |

**Turso makes every statement an HTTPS round trip.** Schema work on the
per-connection path cost ~16 round trips and turned an empty `GET /listings` into
9.5 s. Schema belongs to the database, not the connection: `open_db()` +
`ddl_registry.ensure_schema` + `_run_migrations_once`. Guarded by
[test_marketplace_migration_memo.py](warden/tests/test_marketplace_migration_memo.py),
which counts statements — a results-only test cannot see this defect at all.

---

## 10. Scheduled work (ARQ, `arq-worker`)

| Job | Schedule | Purpose |
|---|---|---|
| `relay_clearing_outbox` | every 5 min | Drains the transactional outbox to PostgreSQL |
| `settle_x402_deductions` | every 15 min | Batch-settles queued nanopayments |
| `sova_marketplace_state_sync` | every 15 min | Writes loop state to `data/AGENTS.md` |
| `nightly_ledger_recon` | 04:00 UTC | Ledger reconciliation |
| `nightly_order_mirror_recon` | 04:20 UTC | The only producer of FT-6 Phase C evidence |
| `nightly_aml_scan` | 04:20 UTC | Structuring sweep |
| `purge_clearing_outbox` | Sun 05:00 UTC | Outbox retention |

---

## 11. Open work — stated plainly

- **No counterparty has ever traded.** Registration, DID, KYA/KYB and sanctions
  are `BUILT`, never executed against a real counterparty. Safe to describe;
  never imply usage.
- **Settlement is `simulated`.** `warden/web3/smart_contract.py` deploys nothing
  and signs nothing, so the manifest cannot honestly read `onchain` until that
  stub is replaced. Rollout is gated on *counted verified trades*, not elapsed
  time (`docs/onchain-settlement-design.md` §7).
- **`authorize_payment()` is off.** Flipping it is Track F's call, not a local
  decision; its Budget Guardian half short-circuits to `ALLOW` for tenants
  without agentic commerce configured (capability matrix, "every money-moving
  action" row).
- **FT-6 order-model consolidation is at Phase B.** `m2m_store` and
  `agentic_commerce` dual-write a mirror row; **every reader still queries the
  source tables.** Do not read `marketplace_purchases` for their data yet.
- **The marketplace Worker is undeployed** — `marketplace.shadow-warden-ai.com`
  returns 404, and `CLOUDFLARE_API_TOKEN` is unset, so the CF deploy job reports
  success while doing nothing.
- **Mainnet is out of scope** pending a human audit of `Escrow.sol` and a multisig
  arbiter. Slither clean at medium-and-above is not an audit.

---

## 12. Extending this subsystem

**The feature freeze applies** (`CLAUDE.md`, P0, active since 2026-08-18): no new
subsystems, no new routers, no fifth frontend, no new chains or integrations
until the existing one settles a real transaction. New endpoints go into an
existing router under `/v1`. Exempt: security fixes, numbered launch-programme
phases, repairs to something already shipped. When declining under this rule,
name it.

Before writing code:

1. **Grep for a production caller.** `warden/marketplace/CLAUDE.md` carries its
   own warning that four of its rules once described code that did not exist. A
   rule with no caller is a plan, not a guarantee.
2. **Decide the failure direction first**, from §8 — and write the test that
   fails against the *pre-fix* artifact. Twelve escrow tests passed against a
   contract anyone could drain, because each test called each function as the
   party entitled to call it.
3. **Never dispatch a tool by reaching into `TOOL_HANDLERS`.** Internal agents go
   through `agentic_gate()`; external agents go through the Brand Agent plus a
   signature. Those are the two doors.
4. **Run the ratchets before pushing:** route inventory, `test_marketplace_route_auth`,
   counterless-failopen, suppressions.

```bash
ALLOW_UNAUTHENTICATED=true WARDEN_API_KEY="" ANTHROPIC_API_KEY="" \
LOGS_PATH="/tmp/warden_test_logs.json" DYNAMIC_RULES_PATH="/tmp/dr.json" \
REDIS_URL="memory://" MODEL_CACHE_DIR="/tmp/warden_test_models" \
python -m pytest warden/tests/test_marketplace*.py warden/tests/test_escrow*.py \
  warden/tests/test_clearing*.py warden/tests/test_x402*.py warden/tests/test_acp_protocol.py \
  -q --no-cov
```

Re-check the live posture after any settlement, manifest or flag change:

```bash
curl -s https://api.shadow-warden-ai.com/marketplace/protocol | python -m json.tool
python scripts/capability_probe.py      # the probe wins any disagreement with the matrix
```

---

## 13. Where the authoritative detail lives

| Question | File |
|---|---|
| The 31 marketplace rules, env vars, KYA/KYB/credits/autonomy detail | [warden/marketplace/CLAUDE.md](warden/marketplace/CLAUDE.md) |
| What may be claimed publicly, and its status | [docs/capability-matrix.md](docs/capability-matrix.md) |
| Track M audit and its MP-0…MP-8 closure | [docs/marketplace-modernization-plan.md](docs/marketplace-modernization-plan.md) |
| Custody model, trade id, rounding, preflight, rollout gates | [docs/onchain-settlement-design.md](docs/onchain-settlement-design.md) |
| FT-6 Phase C cutover | [docs/order-model-consolidation-plan.md](docs/order-model-consolidation-plan.md) |
| Operator-facing walkthrough | [docs/marketplace-guide.md](docs/marketplace-guide.md) |
| Repo-wide invariants | [CLAUDE.md](CLAUDE.md) |
