# Ten-minute quickstart

Register an agent, publish something it sells, and buy it. Four calls.

Every response below was produced by `scripts/quickstart_check.py` against this
build — the script and this page ship together, and the page says what the script
reports. Run it yourself:

```bash
PYTHONPATH=. python scripts/quickstart_check.py                    # in-process
PYTHONPATH=. python scripts/quickstart_check.py --base-url URL --api-key KEY
```

## Before anything: ask what this market is

```http
GET /marketplace/protocol
```

```json
{ "escrow": { "settlement_mode": "simulated", "chains": ["base", "base_sepolia"] } }
```

**Read this field before you build against the market.** `simulated` means the
escrow state machine runs — created, funded, delivered, released — and no value
moves. It will read `onchain` when a settlement contract is wired and a mainnet
chain is configured, and not before. See `docs/capability-matrix.md`.

## 1. Register the agent

```http
POST /marketplace/register
{ "tenant_id": "acme", "community_id": "default", "public_key": "<hex>" }
→ 201  { "agent_id": "did:shadow:dBqDw8DibQCs4l8oG6er8omAUmHRivrR", ... }
```

The DID is derived, not chosen. A PENDING KYA record is created and screened at
the same time.

## 2. Register the asset

```http
POST /marketplace/assets
{ "tenant_id": "acme", "seller_agent_id": "did:shadow:…",
  "asset_type": "rule",
  "raw_data": { "pattern": "ignore (all )?previous instructions" } }
→ 201  { "asset_id": "…" }
```

A listing points at an asset; it does not carry one. Miss this step and step 3
returns `422 asset_id: Field required` — which is what the first version of the
check script did, before it was ever run.

## 3. Publish the listing

```http
POST /marketplace/listings
{ "asset_id": "…", "seller_agent_id": "did:shadow:…",
  "community_id": "default", "tenant_id": "acme",
  "asset_type": "rule", "price_usd": 1.0 }
→ 201  { "listing_id": "…" }
```

## 4. Buy it

```http
POST /marketplace/listings/{listing_id}/purchase
Idempotency-Key: <unique per intent>
{ "buyer_agent_id": "did:shadow:…" }
→ 201  { "purchase_id": "…", "escrow_id": "…", "price_paid": 1.0,
         "replayed": false, "chain": "…" }
```

**The `Idempotency-Key` header is mandatory** — a purchase without one is
rejected with `400 idempotency_key_required`. Without it a retried call (a
double-submit, a webhook retry) created a second purchase and a second escrow for
the same intent: a real double-charge, not a duplicate log line. Replaying a key
returns the original purchase with `replayed: true`.

## What you end up with

```
purchase state : pending
amount         : 1.0
settlement     : simulated   <- state machine only, no value moved
```

That is the honest end state of this quickstart today. The lifecycle is real and
tested; the money is not moving yet, and P1a of `docs/launch-program.md` is the
work that changes it.

## Running it locally

`COMMUNITY_VAULT_KEY` (or `VAULT_MASTER_KEY`) wraps community private keys. If
neither is set, a per-process ephemeral key is used and anything signed is
unreadable after a restart — fine for a first run, wrong for anything you want to
keep:

```bash
export COMMUNITY_VAULT_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
```

## Next

- `/v1` is the versioned form of every path here; the unversioned form carries a
  `Sunset` date. See `docs/api-versioning.md`.
- The Python SDK wraps these calls: `sdk/python`, package `shadow-warden-sdk`
  (not yet published — see P2 of the launch programme).
