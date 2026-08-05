# Monetization Plan — Shadow Warden AI

**Date:** 2026-08-03 · **Track:** FM-7 (FinOps / Monetization) · **Status:** analysis complete, slice 1 shipped

This document is the single narrative for how the product makes money, what it
costs to serve, and what changes when. Every figure below is produced by
`python scripts/finops_report.py` from the code's own source of truth — nothing
here is typed in by hand.

---

## 1. Executive summary

The product is structurally high-margin: the `/filter` pipeline is CPU-only, so
the marginal cost of the thing customers actually buy is roughly $10⁻⁶ per
request. The risk is not the pipeline — it is the **agentic surface** bolted
onto it. One Opus MasterAgent turn costs **$0.12**, which is **60× the entire
revenue of one Pro request**. Nothing measured that, and nothing capped it.

Five findings, in order of money at stake:

| # | Finding | Exposure |
|---|---------|----------|
| 1 | Annual plans sold at a **41% discount on a 15% plan** — three price lists disagreed | ~$316/yr leaked per annual Pro seat |
| 2 | Request overage rated against a **key that does not exist** | **Every** overage on every tier charged $0.00 |
| 3 | MasterAgent and the Evolution Engine recorded **no cost at all** | Gross margin per tenant was unknowable |
| 4 | `claude-opus-4-6` was **missing from the price book** → rated as Sonnet | Largest variable cost understated **5×** |
| 5 | Evolution Engine had a rate cap but **no spend ceiling** | ~$750/day worst case under a sustained attack |

All five are fixed. The wider plan is in §5.

---

## 2. Current unit economics

```
tier                      $/mo        $/yr      req/mo       $/req   LLM budget   max $/req
starter                  $0.00           -       1,000           -        $0.50           -
individual               $5.00      $51.00       5,000   $0.001000        $1.25   $0.000500
community_business      $39.99     $407.90      10,000   $0.003999       $10.00   $0.001999
pro                     $99.99   $1,019.90      50,000   $0.002000       $25.00   $0.001000
enterprise             $249.00   $2,539.80   unlimited           -            -           -
```

`$/req` is revenue per included request. `max $/req` is the most a request may
cost and still clear the 50% per-request margin floor. `LLM budget` is the
monthly inference allowance derived from the list price at a 75% target gross
margin.

**Cost of one representative agent turn** (2 000 fresh input + 800 output +
20 000 cached tokens):

| Model | $/turn | Turns a Pro plan's allowance buys |
|-------|--------|-----------------------------------|
| Haiku 4.5 | $0.0064 | 3 906 |
| Sonnet 4.6 | $0.0240 | 1 041 |
| Opus 4.8 | $0.1200 | **208** |

208 Opus turns per month is the real ceiling on "MasterAgent included in Pro".
That is a fine product promise — but only once something is counting.

**Pricing inversion worth noting:** Community Business earns $0.0040/request
while Pro earns $0.0020. Pro gives away 500 requests per dollar against
Community Business's 250. Pro is the volume plan, so some inversion is
intended; a 2× gap is larger than intended and is a repricing candidate (§5.1).

---

## 3. What was wrong

### 3.1 Three price lists, no owner

`billing/router.py` served $39.99/$99.99 to the pricing page. `feature_gate.py`
held a hand-written `ANNUAL_PRICING` built against a $19/$69 list the product had
already moved off. `finops/margin.py` kept a third private copy. The site,
README, CLAUDE.md and eleven Astro pages quoted the old numbers.

The consequence was not cosmetic. The annual plan is advertised at −15%:

| Plan | Monthly × 12 | Annual sold at | Actual discount |
|------|--------------|----------------|-----------------|
| Community Business | $479.88 | $194 | **−60%** |
| Pro | $1 199.88 | $703 | **−41%** |

And because `margin.py` rated revenue from its own copy, every margin decision
was computed against a price that was not being charged.

### 3.2 Request overage has never charged anything

`OVERAGE_PRICES` stores **cents** per 1 000 excess requests — 50 for Pro, 10 for
Enterprise. `_calculate_overage()` read `per_1k_requests_usd`, a key that has
never existed in that table. `dict.get(..., 0.0)` did what it was asked:

```
rate_per_k   = overage_rate.get("per_1k_requests_usd", 0.0)   # always 0.0
charge       = round(overage / 1000 * rate_per_k, 4)          # always 0.00
"overage_enabled": bool(rate_per_k)                           # always False
```

So BL-19 has shipped, run its monthly ARQ cron, posted its Slack summary and
reported `$0.00` for every tenant on every tier since it landed. A Pro tenant
25% over quota should have been billed $6.25; the system computed nothing and
told the operator overage was disabled.

### 3.3 The expensive paths were the unmeasured ones

`TokenCostTracker` existed and worked — but only Digital Staff and SOVA called
it. MasterAgent (Opus, fanned out across four sub-agents, sold inside Pro) and
the Evolution Engine (Opus, on the `/filter` hot path, triggered by any tenant
including free ones) wrote nothing. The two most expensive code paths in the
product were invisible to the only system that tracks cost.

### 3.4 The price book had a hole

`PRICE_BOOK` listed `claude-opus-4-8` but not `claude-opus-4-6` — the model
MasterAgent, the Evolution Engine, `rag_evolver` and the red-team runner all
actually call. An unknown id fell through to the Sonnet default of $3/$15
against Opus's real $15/$75. Anything rated on that path was **5× too cheap**.

### 3.5 Rate limits are not spend limits

The Evolution Engine's gate caps calls per 5-minute window (10). Sustained,
that is ~2 900 Opus calls a day, ≈$750/day, on a code path with no revenue
attached — and a flood of *novel* blocked prompts is exactly what an attack
campaign produces.

---

## 4. Shipped in this slice

| Change | File |
|--------|------|
| Canonical price list; annual prices **derived**, never typed | `warden/billing/pricing.py` (new) |
| Overage rate read from the table it lives in (was always $0.00) | `warden/billing/router.py` |
| `feature_gate`, `billing/router`, `finops/margin` all read from it | 3 files, private copies deleted |
| Tier-alias table unified so pricing and gating cannot disagree | `pricing.canonical_tier` |
| `claude-opus-4-6` priced; family-prefix fallback so a new snapshot never rates as Sonnet again | `warden/finops/rating.py` |
| MasterAgent records cost on every turn (supervisor, sub-agents, batch, fallback) | `warden/agent/master.py` |
| Evolution Engine records cost to a `system:evolution` cost centre | `warden/brain/evolve.py` |
| Evolution daily spend ceiling, `EVOLUTION_DAILY_BUDGET_USD` (default $5) | `warden/brain/evolve.py` |
| SOVA passes prompt-cache reads so cached tokens bill at 10%, not 100% | `warden/agent/sova.py` |
| Per-tenant LLM allowance + soft model gate (Opus→Sonnet→Haiku) | `warden/finops/llm_budget.py` (new) |
| `GET /billing/margin` — revenue vs. month-to-date inference cost | `warden/billing/router.py` |
| `warden_llm_cost_usd_total`, `warden_llm_budget_downgrade_total` | `warden/metrics.py` |
| `scripts/finops_report.py` — unit economics, model cost, node capacity | new |
| 64 tests: pricing-coherence ratchet (incl. the Astro price sources), overage rating, budget gate | 2 new test files |

### The gate's guarantees

The budget gate is **soft, additive and fail-open**, matching the Track C rule
that margin logic never weakens a boundary:

- It never blocks a request. Worst case it serves a cheaper model.
- It never routes below `candidates[0]` — the caller's declared capability floor.
- It never returns a model the caller did not offer.
- Any internal fault (cost DB down, plan unresolvable) resolves to the **most
  capable** model. A FinOps outage must not degrade a paying customer's answers.
- Enterprise and unresolved plans are uncapped by design.

A rising `warden_llm_budget_downgrade_total` is the signal that a tier is
**under-priced for how it is actually used** — that is a repricing input, not a
throttling target.

---

## 5. Roadmap

### 5.1 Pricing (decision-required)

| Item | Recommendation |
|------|----------------|
| Pro's request allowance | 50 000 req at $99.99 gives 2× worse unit revenue than Community Business. Either cut Pro to 35 000 req or lift CB to 15 000 to make the ladder monotone. |
| Marketplace search fee | x402 charges **$0.000001**/search; a prepaid credit charges **$0.001** for the same action — a 1 000× gap for identical work. One of the two is wrong. Recommend aligning x402 to the credit price and keeping credits as the no-wallet convenience path. |
| Agent surface metering | "MasterAgent included" is really "208 Opus turns included". Publish it as an allowance with a metered overage (suggested $0.15/turn beyond it) rather than leaving it implicit. |
| Annual enterprise | Now $2 539.80. Confirm against any signed contracts before the next renewal cycle. |

### 5.2 Metering and billing

- Extend the DDL for `staff_action_costs` with a `cached_tokens` column so cache
  savings are reportable, not just applied.
- Overage now *rates* correctly, but the monthly cron still only computes and
  Slacks the number — actual collection is delegated to a `/billing/overage/record`
  call that nothing invokes automatically. Close that loop before counting the
  revenue.
- `overage.py` still describes the retired $49 Business / $199 MCP tiers and
  `get_upgrade_url()` routes to plan names that no longer exist. Repoint it at
  `pricing.py`.

### 5.3 COGS

- Route the remaining hardcoded `claude-opus-4-6` callers (`rag_evolver`,
  `nemo_bridge`, red-team) through the budget gate's ladder.
- Give the Evolution Engine a per-tenant fairness slice: today one free-tier
  attacker can consume the whole global evolution budget, starving paying
  tenants of new rules.
- Report `cache_savings_usd` on `/billing/margin`. On the representative turn in
  §2, prompt caching takes input spend from $0.33 to $0.06 — an **82% saving on
  input** that nothing currently surfaces.

### 5.4 Infrastructure efficiency

```
container memory committed :     18,176 MB across 20 services
schedulable RAM            :      7,680 MB (node 8,192 MB less OS reserve)
headroom                   :    -10,496 MB   [OVER-COMMITTED]
largest limits             : warden 8,192M, clickhouse 2,048M, redis 1,280M
```

Summed container limits are **2.4× the node's RAM**. Nothing is broken today
because the limits are ceilings, not reservations — but under load the kernel
OOM-killer, not the scheduler, picks which service dies. `warden` alone is
allowed 8 GB on an 8 GB box.

This is deliberately **not** changed in this slice: right-sizing a limit without
measured RSS risks OOM-killing the gateway on deploy. The sequence is measure
(`docker stats` over a week) → set `warden` to measured peak + 50% → re-run
`scripts/finops_report.py` until headroom is positive.

Capacity for reference: at a 12 ms mean service time the node sustains **63
req/s** — about 164 M requests/month, or 3 280 Pro plans' worth of quota. Compute
is not the constraint on revenue; it is nowhere close.

### 5.5 Growth

`warden/finops/growth.py` already implements LTV, CAC payback, NRR and the viral
coefficient, and `referral.py` runs the referral flywheel. None of it is fed by
live data. Wire the funnel to real signup/trial/conversion events so the LTV:CAC
ratio is measured rather than modelled.

---

## 6. Deliberately not done

- **No price was raised or lowered.** The $39.99/$99.99 list already existed in
  the API; this work made every other surface tell the truth about it.
- **No hard spend blocks.** The gate degrades model choice; it never returns 402
  or refuses an agent run.
- **No container limits touched.** See §5.4 — that needs a week of measurement
  first.
- **No changes to security gates.** The budget gate runs after them and is
  additive only.
