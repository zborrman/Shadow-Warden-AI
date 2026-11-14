# Surface decision — 2026-11-14

Status: **decided**. Supersedes nothing; constrains stages R1–R3 of the M2M
reconstruction.

## What was measured

Not opinion — the numbers below come from enumerating the live app
(`warden.main.app`, fresh subprocess, canonical env) and from walking the
consumer trees.

| | |
|---|---|
| route surface | **793 routes** across **87 top-level prefixes** |
| write routes | **393** (`POST`/`PUT`/`PATCH`/`DELETE`) |
| non-test Python in `warden/` | **170,713 lines**, **642 files** |
| maintainers | 1 |
| registered users | 0 |
| prefixes with **no reference** in `site/`, `portal/`, `dashboard/`, `sdk/`, or the agent tool tables | **17 prefixes, 67 routes** |

Seven of those orphans were checked individually. All have **zero** clients and
are nevertheless **published** in `site/public/openapi.json`, i.e. advertised:

```
/integrations/jira   clients:0  in published spec:2
/agents/packs        clients:0  in published spec:3
/tokenomics          clients:0  in published spec:4
/whitelabel          clients:0  in published spec:3
/wallet              clients:0  in published spec:5
/msp                 clients:0  in published spec:2
/web3                clients:0  in published spec:3
```

## The problem this names

The R0 probe found two live authentication holes and six more open write
surfaces. Every one of them sits on a subsystem with **no client, no user and
no roadmap owner**. That is the shape of the whole fix stream: the work is not
caused by bad code, it is caused by **surface that serves nobody and is
maintained by no one**. The P0 feature freeze (2026-08-18) stopped the surface
*growing*. Nothing has yet made it *shrink*.

`/integrations/*` is the clearest illustration. Four anonymous outbound writers
(Jira, Notion, Teams, Zapier). They read as harmless because an anonymous probe
gets `502`/`503` — but that is the **credentials being unset**, in the probe and
in production alike, not a gate. The hole is real and merely latent: it arrives
the day someone sets `JIRA_BASE_URL`, and nothing would have announced it.

## Options weighed

1. **Gate everything, keep everything.** Cheap per route (~4 lines). Removes
   anonymous access and nothing else: the maintenance cost, the published
   claim, the migration cost of every future cross-cutting change, and the
   next latent hole all survive. *Treats the symptom.*
2. **Delete the orphans.** Cheapest long term, irreversible, and with zero
   users there is no signal about what mattered. *Too destructive to be
   reversible-by-default.*
3. **Withdraw the orphans from the mounted surface, keep the code.** Attack
   surface and published claim go to zero; the code and its tests stay; a flag
   brings any of it back. *Chosen.*
4. **Do nothing; proceed to R1/R2 as planned.** See the reordering below for
   why this is the expensive option, not the neutral one.

## Decision 1 — a three-state surface manifest

Every router declares which of three states it is in, and the state is
mechanically enforced rather than remembered:

| state | mounted in production | code | tests | published in `openapi.json` | claims allowed |
|---|---|---|---|---|---|
| `product` | yes | yes | yes | yes | per the capability matrix |
| `lab` | **no**, unless `WARDEN_LAB_SURFACES=true` | yes | yes | no | none |
| `retired` | no | deleted | deleted | no | none |

The seam already exists: 87 of the mounts go through
`app_factory.register_router_safe(app, RouterSpec(...))`. `RouterSpec` gains a
`surface` field and the registrar skips `lab` unless the flag is set, logging
what it withheld so an operator can see it. The remaining 37 direct
`app.include_router` calls migrate onto the same seam as each cohort lands.

Rules that follow:

* **A route with no client is not a product.** Shipping it is a claim, and the
  Claims Rule applies to `openapi.json` exactly as it applies to site copy.
* **`lab` is not a parking space for undecided work.** Entering `lab` requires
  naming the condition for leaving it, in the manifest.
* **Withdrawal happens cohort by cohort**, each its own PR with its own
  baseline updates — never one sweep. The route-inventory fixture, the
  anonymous-write baseline and the published spec all move with it.

## Decision 2 — narrowing moves ahead of R1 and R2

The recorded order was R0 → R1/R2 (+R5) → R7 → **R3** (narrowing) → …

R1 is "one identity model" and R2 is "one money core". Both are **per-route
migrations**: their cost is a function of how many routes exist when they run.
Roughly a third of the current surface has no client. Running R1 and R2 across
793 routes and then narrowing means paying the identity and money migration
cost on code that is about to be withdrawn.

So: **the narrowing mechanism and its first cohorts land before R1/R2 begin.**
This is a reordering of the owner's plan, made deliberately and recorded here
rather than done quietly. It does not change what R1 and R2 are, only how much
surface they have to cross.

## What landed with this decision

Immediate gating, because `lab` withdrawal is later and these must not be
anonymous in the meantime:

* `/integrations/*` — router-level `require_api_key` (all 8 endpoints; the
  `/health` ones disclose whether an integration is configured).
* `POST /agents/packs/{name}/deploy` and `/analyze` — gated; `GET /agents/packs`
  stays public, like the rest of marketplace discovery.
* `POST /billing/referral/redeem` — the credited tenant now comes from the key
  via `_caller_tenant`, not from a `new_tenant_id` body field. This is the same
  shape H-5 closed across this router in #597; the route escaped that audit
  because it took its tenant from a **body field** rather than the
  `X-Tenant-ID` header H-5 grepped for.

Two referral tests were updated: both posted anonymously and asserted success,
so they had been pinning the defect.

`POST /scan/extensions` is **kept public** — it is a stateless scanner over
caller-supplied input, the same class as `/scan/email`, which PR #248 left
public by decision. Whether to meter it is a pricing question, not a security
one.

## Falsifiable exit

* `warden/tests/test_anonymous_write_probe.py` — the anonymous-write baselines
  may only shrink. After this change: **14** routes execute anonymously (down
  from 16 at R0's start), **23** inconclusive (down from 30).
* The narrowing has a number attached: **17 orphan prefixes / 67 routes** is the
  starting measurement. A cohort is done when its prefix leaves that list by
  entering `lab` or `retired` — not by acquiring a client it does not have.
