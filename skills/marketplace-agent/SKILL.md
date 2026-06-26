---
name: marketplace-agent
description: Shadow Warden M2M marketplace agent registration, DID management (did:shadow:{32 base-62} from SHA-256 of Ed25519 pub key), key rotation (90-day deadline enforced — overdue agents lose all capabilities), capability gating (marketplace_buy / marketplace_sell / marketplace_negotiate), TrustRank PageRank scoring, AP2 mandate auto-creation on registration, budget_limit column. Use when registering marketplace agents, rotating Ed25519 keys, checking TrustRank/Sybil status, or managing agent capabilities and monthly budgets.
---

## DID Format

```
agent_id = did:shadow:{base62(sha256(public_key_bytes)[:32])}
```

Alphabet: `0-9A-Za-z` (62 chars). Derived from `pubkey_to_agent_id()` in `warden/marketplace/agent.py`.

## Registration endpoint

```
POST /marketplace/agents/register
{
  "tenant_id":    "tenant-abc",
  "community_id": "comm-xyz",
  "public_key":   "<base64 Ed25519 pub key>",
  "capabilities": ["marketplace_buy", "marketplace_sell", "marketplace_negotiate"]
}
→ 201 { agent_id, community_id, mandate_id, ... }
```

**Federation deny-list check fires before registration** — if the agent DID is flagged across peered communities, returns HTTP 403.

## Capabilities

| Capability | Required for |
|---|---|
| `marketplace_buy` | purchasing listings, `auto_buy()`, `search_and_buy()` |
| `marketplace_sell` | publishing listings |
| `marketplace_negotiate` | sending/accepting offers |

Update via `PUT /marketplace/agents/{agent_id}/capabilities`.

## Key rotation

- Deadline: `AGENT_KEY_ROTATION_MAX_DAYS` (default 90 days)
- Overdue agents: capabilities set to `[]` until rotated
- Endpoint: `POST /marketplace/agents/{agent_id}/rotate-key`
- Old X.509 cert added to CRL on rotation

## TrustRank + Sybil

```
GET /marketplace/agents/{agent_id}/trust
→ { trust_score, trust_rank, sybil_flag, sybil_reason, transitive_peers }
```

TrustRank = weighted PageRank (damping 0.85, max 100 iter) over the trade graph (buyer→seller edges, weight: completed=1.0, disputed=0.3).

Sybil detection: circular trades (A↔B within 24h) or volume Z-score > 3.0. Flagged agents are penalized in reputation.

## Budget + Mandate

- `budget_limit` column on `marketplace_agents` (default $1000/month)
- `mandate_id` links to AP2 spending mandate (auto-created on registration)
- Budget checked via `semantic_budget.check_budget()` before every purchase (fail-open)
- Update budget: `PATCH /marketplace/agents/{agent_id}` `{ "budget_limit": 500.0 }`

## Env vars

| Var | Default | Effect |
|---|---|---|
| `MARKETPLACE_DB_PATH` | `/tmp/warden_marketplace.db` | SQLite location |
| `MARKETPLACE_DEFAULT_MANDATE_USD` | `1000` | AP2 mandate limit |
| `AGENT_KEY_ROTATION_MAX_DAYS` | `90` | Rotation deadline |
| `MARKETPLACE_MIN_SELLER_REP` | `0.0` | Min seller score before buyer skips |
