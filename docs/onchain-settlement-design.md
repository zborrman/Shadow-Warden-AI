# On-chain settlement — design

**Status:** proposed · **Date:** 2026-08-26 · **Phase:** closes P1a's last exit
criterion · **Estimate:** ~2 days

P1a deployed an escrow contract to a public chain and settled a real trade
through it (`scripts/deploy_escrow.py`, PR #390).
The gateway cannot do the same thing, and this document says exactly why and
what closes the gap.

The programme previously recorded on-chain settlement as four environment
variables away. That was wrong, and the correction is the reason this document
exists: **`settlement_mode: simulated` is an accurate description of the
software, not a configuration gap.** Setting the variables would have turned an
honest word into a false one.

---

## 1. What is actually missing

Six facts, each verified against the tree at `24589bbb`.

| # | Fact | Where |
|---|---|---|
| 1 | `deposit(bytes32 tradeId, address buyer, address seller, address token, uint256 amount, uint64 deliveryWindowSeconds)` — the gateway calls it with `{}`. No trade id, no addresses, no amount. | `contracts/Escrow.sol:82` vs `escrow.py:303` |
| 2 | `marketplace_escrow` stores `buyer_agent`/`seller_agent` as **agent DIDs** and `amount_usd REAL`. There is no address, no token, no trade id, and no integer amount. | `escrow.py:82` |
| 3 | `marketplace_agents.public_key` is a base64 **Ed25519** key. An Ethereum address cannot be derived from it — this needs a new column, not a computation. | `agent.py:140` |
| 4 | `sepolia.usdc_address` is `""`. The chain P1a deployed on **cannot settle USDC at all**. `base_sepolia` and `base` are the only configured chains that can. | `chains.py` |
| 5 | `contracts/` is not in the warden image — compose builds `warden` with `context: ./warden`, and `contracts/` is at the repo root. `ESCROW_ABI_PATH` has nothing to point at. Confirmed live: `ls contracts/` → no such file. | `docker-compose.yml` |
| 6 | Of the six call sites, only `deliverAsset` passes anything the ABI wants (`assetHash`). The other five pass nothing usable. | `escrow.py` |

Fact 1 is the one that matters. The rest are consequences of it never having
been true.

### What is *not* missing

`call_escrow()` builds, signs, sends and reads the receipt, and **fails closed**
(PR #388). `_call_contract()` now returns that answer and all six callers honour
it (PR #400). `settlement_capability(chain)` names which piece of configuration
is absent rather than guessing. The transport is finished; the payload is not.

---

## 2. Custody: the decision this turns on

Two shapes, and the choice is regulatory before it is technical.

**Model A — custodial.** A gateway treasury wallet is the on-chain `buyer`.
Buyers pay in Flex Credits, which already exist and are explicitly sold as
"budget-predictable access without needing a crypto wallet"
(`credits.py`). One new counterparty field:
the seller's payout address. The gateway is already the arbiter, so the
`msg.sender` checks in `deposit` and `confirmReceipt` pass without further work.

**Model B — non-custodial.** The buyer's own wallet holds the USDC and grants
the escrow an ERC-20 allowance. The gateway relays `deposit` as arbiter, which
the contract already permits by design. No custody at any point.

### Recommendation: **Model B.**

Model A is faster to a demo, needs one schema column instead of two, and is
what `credits.py` appears to have been written for. It loses on two counts.

**It takes custody before there is an entity to take custody.** Holding buyer
funds pending delivery is a money-transmission posture. P1b exists precisely to
defer that until a company exists; Model A would import the hardest part of P1b
into P1a while claiming P1a needs no legal entity.

**It adds a second money ledger.** Credits are debited in SQLite and Redis;
tokens move on-chain; something has to reconcile them, including on refund. This
codebase has already shipped that exact bug twice — clearing settled every trade
at $0.00 for months, and the ledger read-cutover gate passed with zero tenants
verified. A design that avoids a second source of truth for money is worth real
friction.

The usual argument for A is cold-start friction: every buyer must hold USDC and
`approve` before their first trade. **That argument does not apply here.** Every
marketplace database currently holds one row — `_warden_ddl_applied` — and zero
users. There is no cohort to lose. The first counterparty is a testnet buyer who
needs testnet USDC regardless.

Model A stays viable and should be reconsidered **after** P1b, when there is an
entity, as the retail on-ramp. It is not the first implementation.

---

## 3. Schema

All additive, via the existing `_ensure_columns` suppress-per-connect pattern —
`ALTER TABLE … ADD COLUMN` is not idempotent and cannot live in registered DDL.

### `marketplace_agents`

```
payout_address  TEXT NOT NULL DEFAULT ''
```

EIP-55 checksummed, validated with `Web3.is_checksum_address()` at write, not at
send. An agent without one can buy but cannot sell, and `register_asset` should
say so at listing time rather than at settlement time.

### `marketplace_escrow`

```
trade_id        TEXT NOT NULL DEFAULT ''      -- 0x… keccak(escrow_id)
buyer_address   TEXT NOT NULL DEFAULT ''
seller_address  TEXT NOT NULL DEFAULT ''
token_address   TEXT NOT NULL DEFAULT ''
token_decimals  INTEGER NOT NULL DEFAULT 0
amount_minor    TEXT NOT NULL DEFAULT ''      -- integer minor units, as TEXT
fund_tx         TEXT NOT NULL DEFAULT ''
deliver_tx      TEXT NOT NULL DEFAULT ''
settle_tx       TEXT NOT NULL DEFAULT ''
```

Addresses are **snapshotted onto the escrow at creation**, not looked up at send
time. A seller who changes their payout address mid-trade must not redirect a
deposit that is already funded.

`amount_minor` is **TEXT holding an integer**, not REAL. `uint256` does not fit
in a float, and `REAL` is how `amount_usd` came to be a float in the first
place. `amount_usd` stays as the human-facing figure; `amount_minor` is what
settles.

The three `*_tx` columns are not decoration. They let an operator verify a
transition on a block explorer, and they let a retry ask the chain what happened
instead of sending again.

---

## 4. The two conversions that lose money quietly

### Trade id

```python
trade_id = Web3.keccak(text=f"shadow-warden:escrow:{escrow_id}")
```

Deterministic, so a retry after a timeout produces the same id. The contract
reverts `TradeExists()` on a second `deposit` — that revert must be **decoded
and treated as success**, not as a failure. Otherwise the first network hiccup
turns one funded trade into a permanently stuck escrow.

### USD → minor units

```python
from decimal import Decimal, ROUND_HALF_UP

minor = int(
    (Decimal(str(amount_usd)) * (10 ** decimals))
    .quantize(Decimal("1"), rounding=ROUND_HALF_UP)
)
if minor <= 0:
    raise SettlementRefused(f"${amount_usd} rounds to 0 {symbol}; refusing")
```

`Decimal(str(x))`, never `Decimal(x)` — the latter inherits the binary float's
error and reintroduces exactly what Decimal is here to prevent.

The `minor <= 0` refusal is not defensive padding. Settling a trade for zero
tokens and recording it as released is the same defect as clearing every trade
at $0.00, one layer down, and it would pass every test that only checks state
transitions.

`decimals` is read from the chain by `verify_usdc_contract()`, not assumed to be
6. A token address is the one constant where being wrong costs money in silence.

---

## 5. Preflight

`settlement_preflight(escrow) -> Preflight` runs before any transaction is
built. If it fails, the escrow **stays in its current state** with a named
reason; it does not advance and it does not send.

| Check | Why it is separate from a revert |
|---|---|
| `settlement_capability(chain).can_settle` | Already exists; names the missing piece. |
| Both addresses present and checksum-valid | A malformed address is a config error, not a chain error. |
| `token_address` non-empty for this chain | **`sepolia` has none** — this is the check that catches fact 4. |
| `verify_usdc_contract()` symbol and decimals match stored | Guards against a token address that is plausible and wrong. |
| `allowance(buyer, escrow) >= amount_minor` | Otherwise the operator sees `REVERTED` and nothing else. |
| `balanceOf(buyer) >= amount_minor` | Same. |
| signer native balance > 0 | Out of gas looks identical to a rejected transaction. |

`deposit` reverts with `TransferFailed()` for both allowance and balance. Those
are the two most likely first-trade failures and the two the receipt cannot tell
apart — which is the whole reason preflight exists rather than trusting the
revert.

---

## 6. Packaging and chain

**Ship the ABI, not the contract.** `contracts/escrow.abi.json` is a build
artifact of the Solidity source and is the only thing `call_escrow` needs. Copy
it to `warden/web3/abi/escrow.abi.json` and default `ESCROW_ABI_PATH` to it.

The alternative — flipping compose to `context: .` — changes the build context
for every service to pull in one JSON file, and this repo has already taken a
production outage from a build-context change. Bytecode stays out of the image:
only `scripts/deploy_escrow.py` needs it, and that runs on an operator's
machine.

**Deploy the settling instance to `base_sepolia`.** It is the only configured
testnet with a USDC address and it is P1a's stated target. The existing Sepolia
instance at `0x42Cb99A842a5bb6848Ef96b9f7070E348BD9b913` stays as the P1a
evidence artifact and is never pointed at by config.

⚠️ The **first** Sepolia deployment, `0x349f6361…`, is the pre-Slither
vulnerable contract. It must never appear in configuration.

---

## 7. Rollout

The gate is **counted verified trades, not elapsed time.** The ledger
read-cutover gate passed on a shadow period that concluded because the clock ran
out, with zero tenants actually verified. This does not repeat that.

**Phase 1 — preflight only.** Preflight runs and logs on every escrow; nothing
is sent. Exit: for at least 5 escrows, preflight's verdict was reproduced by a
manual `deposit` from the operator's own machine. This is where a preflight that
passes but shouldn't gets caught, before it can cost anything.

**Phase 2 — per-chain enable.** `ESCROW_SETTLE_CHAINS=base_sepolia`, a list, not
a global boolean. A boolean is a kill switch pointed the wrong way: it turns
settlement on everywhere at once, including chains with no token configured.

**Exit:** ≥3 escrows reaching `Released` on-chain, each verified by reading
state back through a **second, independent RPC** — not from the gateway's own
logs. That practice is what made the P1a trade credible and is the standing rule
for anything that grades its own homework.

**Mainnet is not in scope here.** It needs a human audit of `Escrow.sol` and a
multisig arbiter; the current single-key arbiter is flagged as a deliberate
simplification in the source header. Slither being clean at medium-and-above is
not an audit.

---

## 8. Test obligations

The standing practice applies without exception: **every new guard is validated
against the pre-fix artifact.** Twelve escrow tests passed against a contract
anyone could drain standing allowances from, because each test called each
function as the party entitled to call it. A guard no test exercises is
indistinguishable from no guard.

Specifically:

1. **The test that would have caught this defect.** Load the ABI, read each
   function's declared input names, and assert every call site in `escrow.py`
   supplies exactly those. `deposit` with `{}` must fail this test. Nothing
   weaker generalises — a hand-written list of expected params is another copy
   of the vocabulary, and this codebase has already shipped a marketplace enum
   written out twice where the two copies disagreed.
2. **Rounding refusal.** `$0.0001` against 6-decimal USDC refuses; it does not
   settle zero.
3. **Idempotency.** A second `fund_escrow` on a funded escrow does not send a
   second transaction, and `TradeExists()` is read as success.
4. **Preflight blocks.** Each of the seven checks failing leaves the escrow in
   its prior state, with the reason recorded.
5. **Simulated deployments stay inert.** Everything above is a no-op where
   `can_settle` is false — which is production today, and is what
   `settlement_mode: simulated` exists to tell a counterparty.

---

## 9. Out of scope

Fiat settlement (P1b — needs a registered company); a multisig arbiter and the
human audit that precedes mainnet; Model A custody and credit↔chain
reconciliation; any chain beyond `base_sepolia` for the first cutover.
