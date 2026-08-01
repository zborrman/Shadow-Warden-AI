# Marketplace Modernization Plan — Track M (`MP-*`)

**Scope:** the M2M Agentic Marketplace cluster — `warden/marketplace/` (41 files,
12.5k LOC), `warden/m2m_store/`, `warden/business_community/agentic_commerce/`,
and the marketplace-facing edges of `warden/payments/`, `warden/protocols/{acp,a2a}/`,
`warden/blockchain/`. **114 routes, 55 of them writes.**

**Source:** structural audit 2026-07-31 → 2026-08-01, branch `sr-7.2-coverage-85`,
410 cluster tests green. Registered in `docs/unified-modernization-roadmap.md` as
**Track M** (conflict rows C6/C7).

**Prefix rule:** commits and PR titles carry `MP-<n>`, never a bare "Phase N".

---

## 1. Thesis

The marketplace is feature-broad and structurally clean — DDL registry, `open_db()`
seam, real compliance modules, 114 routes. What it lacks is **enforcement of its own
stated invariants**.

`warden/marketplace/CLAUDE.md` lists 22 "non-negotiable" security rules. **Four of them
describe code that does not exist.** Because that file is the spec both humans and
agents read before editing this subsystem, the gap is self-propagating: every new change
is written on top of guarantees that were never there.

**Track M closes the distance between the documented marketplace and the running one.**
It adds no marketplace features. Money *semantics* stay with Track F, cost/margin math
with Track C, detection math with Track B.

### Scoring — current vs. target

| Dimension | Before | After | Owner item |
|---|---|---|---|
| Structure / decomposition | 8 | 8 | — (untouched; Track M changed no structure) |
| Authn / authz on request path | **2** | 8 | MP-1, MP-8 — 25 write routes bound to an identity, offers cryptographically attributed. Not 9: no global auth middleware yet (Track A) |
| Doc ↔ code fidelity | **3** | 9 | MP-0, MP-3, MP-7 — all four false invariants resolved; manifest reports real mode |
| Test coverage of live gates | 6 | 8 | MP-4 — the gate, not just the detector |
| Data-model coherence | 5 | 7 | MP-5 — dead projection removed; FT-6 Phase C still owns the order-model merge |
| Payment-posture clarity | 4 | 7 | MP-6 — posture now measurable; the flip itself is Track F's |
| **Composite** | **≈5** | **≈8** | |

Not 10, and deliberately so. What remains is owned elsewhere or needs production
data: a global auth middleware (Track A), the `AUTHORIZE_PAYMENT_ENFORCED` flip
(Track F / P-6), `MARKETPLACE_REQUIRE_SIGNED_OFFERS` going true after a bake
period (D-3), FT-6 Phase C, and the pre-existing cross-file test pollution in
`test_hub_marketplace_flow.py`.

---

## 2. Evidence (measured, reproducible)

Everything below was produced by running the code, not by reading it.

### 2.1 The exploit — proven end to end

With `WARDEN_API_KEY` set, `ALLOW_UNAUTHENTICATED=false`, and **no key presented**:

```
listing: LST-DFE5E7A95E0C | asking price $1000 | seller=VICTIM_SELLER
1) start_negotiation, no API key      -> 201
2) offer $0.01 as ATTACKER            -> 201 | signature = ''
3) ACCEPT impersonating VICTIM_SELLER -> 200 | signature = ''
=> status: accepted | settled price: $0.01 (asked $1000)
```

Three independent defects compose:

| # | Defect | Location |
|---|---|---|
| D1 | No auth on the negotiation router | `api_negotiations.py:13` — only `marketplace_rate_limit` |
| D2 | `_verify_offer_signature()` defined, called from **nowhere** | `negotiation.py:225` |
| D3 | `send_offer`/`accept_offer` default `keypair=None`; routes never pass one ⇒ `signature=''` persisted | `negotiation.py:289,352` · `api_negotiations.py:46,61` |

There is no global auth middleware in `main.py` — the same root cause as the
`/communities/*` split-brain (PR #239).

### 2.2 Route-auth inventory — **30 of 55 cluster write routes have no auth dependency**

Enumeration must follow `test_route_inventory.py`'s method: under starlette ≥ 1.0,
`include_router()` leaves a `fastapi.routing._IncludedRouter` placeholder, so a naive
`app.routes` walk sees **129** routes while OpenAPI reports **657**. Any audit that
skips this undercounts by ~80%.

| Surface | Open writes | Note |
|---|---|---|
| `/marketplace/negotiations/*` | 3 | **the exploit path** — MP-1 |
| `/marketplace/agents/*` (register, PATCH, DELETE, capabilities, rotate-key) | 5 | identity mutation incl. **key rotation** — MP-1 |
| `/marketplace/proposals/*` (create, vote, execute) | 3 | DAO governance — MP-1 |
| `/marketplace/{assets,register,certificates/verify,credits/purchase,agents/{id}/kya/revoke}` | 5 | mixed — MP-1c |
| `/acp/*` (token, cart, items, checkout, refund, resolve, token DELETE) | 7 | **entitlement gate only** — MP-8 |
| `/business-community/commerce/*` | 7 | incl. `webhooks/ap2` with no dependency at all — MP-8 |

The pattern is **drift, not design**: within the same cluster, `/marketplace/escrow/*`,
`/marketplace/listings/*`, `/marketplace/clear`, `/marketplace/action`,
`/marketplace/autonomy/*`, all of `/m2m-store/*` and `/a2a/*` **do** carry
`require_api_key`. Neighbouring routes in the same files do not.

### 2.3 Two "looks-authenticated-but-isn't" patterns

Both are the same class of error as the already-documented *"a rate-limit dependency is
not auth"*, and both should be named explicitly so they stop recurring:

1. **A feature gate is not auth.** `/acp/*` carries `_Gate` =
   `billing/feature_gate.py::require_feature(...)`. It resolves a tier and 403s if too
   low — it never establishes identity. **Corrected during MP-8 execution:** these
   routes are *not* anonymously reachable (measured on `origin/main`: 403, and the
   tier cannot be spoofed via `X-Tenant-Tier` — SR-1.1 closed that). The real defect
   is narrower: `tenant_id` arrives as caller-supplied body text, so any caller whose
   plan clears the gate can act **against another tenant**; and access control rests
   on a side effect of tier resolution, so an entitlement change silently becomes an
   access change.
2. **An empty secret disables the check.** `api.py:1237` —
   `admin_key = os.getenv("ADMIN_KEY",""); if admin_key and request.headers.get(...) != admin_key:`
   With `ADMIN_KEY` unset, `POST /marketplace/agents/{id}/kya/revoke` skips its admin
   check entirely. This is precisely the fail-open shape the Phase-7 key rule bans
   (`resolve_key(..., purpose=...)`, unresolvable ⇒ deny).

### 2.4 The four false invariants

| Rule in `marketplace/CLAUDE.md` | Claim | Reality | Item |
|---|---|---|---|
| #1 signing | "Every offer must be Ed25519-signed… unsigned → HTTP 400" | verifier is dead code; every API offer stored `''` | **MP-1** |
| #1 injection | "`scan_negotiation_message()` runs on every offer body" | that module is dead (0% cov); a weaker private substring dupe `_scan_injection` runs instead | **MP-2** |
| #5 escrow | "`EscrowService` invoked automatically on `accept_offer()`" | `negotiation.py` has **zero** escrow references | **MP-3** |
| SEM-02 | 5 Semantic Layer models over `mp_*` | projector has no production caller ⇒ models serve permanently-empty tables | **MP-5** |

### 2.5 Coverage of live gates

⚠️ **Corrected during MP-4 execution.** The audit reported `sybil_guard.py` at
**0%**. That was a measurement artifact: the coverage run selected only
`test_marketplace_*` files, and the existing `warden/tests/test_sybil_guard.py`
(14 tests, 74%) does not match that glob. The detector internals were covered all
along.

What genuinely had no test was the thing rule #4 asserts — the **gate at the
request boundary**. No test called `POST /marketplace/listings`, so nothing
verified that a flagged agent is refused, that a clean one is not, or that the
documented fail-open posture holds. **Treat every other "0%" in this section as
unverified until re-measured the same way.**

Also reported 0% and still to be re-checked: `trust_graph`, `seller_agent`,
`service.py`, `auto_responder`, `bayesian_stats`, `payments/l402.py`,
`agentic_commerce/{service,ucp,multi_agent/*}`.

Note the Track A interlock: SR-7.2 raised the gate to `--cov-fail-under=83` (PR #266)
and its own notes name `marketplace/` as a remaining gap on the road to 85%. **MP-4
directly serves SR-7.2** — coordinate rather than duplicate.

---

## 3. Threat model

| # | Scenario | Enabled by | Impact | Sev | Closed by |
|---|---|---|---|---|---|
| T1 | Anonymous caller settles a listing far below ask by impersonating the seller on accept | D1+D2+D3 | direct financial loss; forged agreement in `marketplace_offers` | **Critical** | MP-1 |
| T2 | Attacker rotates a victim agent's signing key | `POST /agents/{id}/rotate-key` open | full agent takeover | **Critical** | MP-1a |
| T3 | Attacker mutates/deletes another agent's registration or capabilities | `PATCH`/`DELETE /agents/{id}` open | denial of service, capability escalation | **High** | MP-1a |
| T4 | DAO proposal created, voted and executed by an unauthenticated caller | `/proposals/*` open | governance capture | **High** | MP-1a |
| T5 | KYA revoked on any agent when `ADMIN_KEY` is unset | empty-secret fail-open | compliance-state tampering | **High** | MP-1c |
| T6 | ACP/commerce payment token minted, cart checked out or refund filed **against another tenant** by any entitled caller (`tenant_id` is body text) | entitlement gate ≠ identity | cross-tenant money movement | **Medium-High** | MP-8 |
| T7 | Injection payload passes the weaker substring matcher into an LLM-backed buyer/seller agent | MP-2 gap | prompt injection into an agent with spend authority | **Medium** | MP-2 |
| T8 | Counterparty agent trusts `"signature_type":"Ed25519"` + `"injection_guard":true` from `/marketplace/protocol` | manifest asserts unimplemented capabilities | misplaced trust by an external agent | **Medium** | MP-1, MP-2, MP-7 |

---

## 4. Items

Each item states: goal · evidence · files · sketch · acceptance · tests · metrics ·
rollback · risk · size · **model**.

---

### MP-0 — Reconcile `marketplace/CLAUDE.md` with reality
*Do first. Zero risk. Unblocks everything.*

**Goal.** No rule in that file asserts an enforcement `grep` cannot tie to a live caller.

**Sketch.** Mark the four rules **`⚠️ NOT IMPLEMENTED — see MP-n`** *in place* (they stay
as intended targets; deleting them loses the design intent). Add the two anti-patterns
from §2.3 as named rules: *a rate limiter is not auth · a feature gate is not auth · an
empty secret must not disable a check*.

**Files.** `warden/marketplace/CLAUDE.md` only.
**Acceptance.** Every remaining "non-negotiable" rule has a named production caller.
**Rollback.** `git revert`. **Risk.** None. **Size.** 1 PR, docs-only.

> **Model: Sonnet 5.** Mechanical rewrite against a fixed evidence list — but it is
> judgement about what is true, not transcription, so not Haiku.

---

### MP-1 — Authenticate the negotiation path 🔴 *critical, first code slice*

**Goal.** T1–T5 closed. The §2.1 demo returns 401 unauthenticated and 400 when
authenticated but signed by the wrong key.

Three sub-slices, **separate PRs**, in order.

#### MP-1a — Transport auth on the open marketplace routers

Add `AuthDep = Depends(require_api_key)` (`warden/auth_guard.py:151`) — the pattern
already used at `warden/gsam/api.py:34` — to the 16 open `/marketplace/*` write routes
in §2.2. Keep `marketplace_rate_limit`: complementary, not a substitute.

*Deliberately paired with 1b:* an API key proves **a tenant**, not **which agent**.
1a alone stops the anonymous internet; it does not stop tenant A impersonating agent B.

**Files.** `api_negotiations.py`, `api_agents.py`, `api_assets.py`, `api_governance.py`,
`api.py` (register / certificates / credits).

#### MP-1b — Actor proof via offer signatures *(the real fix)*

The key insight, from `agent.py:60`: **`agent_id` is derived from the public key** —
`did:shadow:{base62(sha256(pubkey))}`. The DID *is* a key fingerprint. A signature that
verifies against `marketplace_agents.public_key` is therefore proof of the claimed
`from_agent_id`, with **no extra binding table**.

- Require a `signature` over the existing `_canonical_offer()` envelope on
  `send_offer`/`accept_offer`.
- Call the already-written `_verify_offer_signature()` against the looked-up pubkey.
  Reject **HTTP 400** — exactly what rule #1 always claimed.
- **Fail-CLOSED**: unknown agent, missing key, empty signature, verify error ⇒ reject.
  Governed by the Phase-7 signing rule, **not** the x402 fail-open rule (§6).
- **Replay guard**: the envelope already carries `round` + `timestamp`. Reject a reused
  `(negotiation_id, round)` and a timestamp outside a bounded skew window.
- Also assert `from_agent_id ∈ {buyer_agent, seller_agent}` of that negotiation — a
  valid signature from an *uninvolved* agent must not move someone else's negotiation.

**Migration.** Legacy rows carry `signature=''`. Gate *rejection* behind
`MARKETPLACE_REQUIRE_SIGNED_OFFERS` (default **false** on ship) — the
`KYB_ENFORCEMENT_ENABLED` / `SANCTIONS_SCREENING_ENABLED` precedent. Verification and
its metric run **either way**, so an operator can watch the unsigned rate fall to zero
before flipping. Flag-read failure ⇒ enforcement **off** (never silently cap everyone —
the explicit FT-5 KYB lesson).

#### MP-1c — Kill the empty-secret bypass

`api.py:1237` → resolve the admin secret through
`resolve_key("ADMIN_KEY", purpose="marketplace_admin")`; unresolvable ⇒ **deny**.
Sweep the cluster for the `if secret and ...` shape.

**Acceptance (MP-1 overall).**
1. §2.1 demo → 401 without a key; 400 with a key but a wrong-key signature.
2. Signed-by-uninvolved-agent → 400.
3. Replayed `(negotiation_id, round)` → 400.
4. With the flag off, an unsigned offer still succeeds **and** increments the
   unsigned-offer counter (proves the bake path works).
5. `ADMIN_KEY` unset ⇒ `kya/revoke` **denies** (today it allows).

**Tests.** `test_marketplace_offer_signing.py` (new, ~20) · extend
`test_marketplace_security.py` · **ratchet** `test_no_unauthenticated_marketplace_write.py`
— enumerate cluster write routes via the `_IncludedRouter` walk, assert each carries an
auth dependency, baseline **may only drop** (pattern: `test_route_inventory.py`).

**Metrics.** `warden_marketplace_offer_signature_total{result=valid|invalid|absent}`,
`warden_marketplace_unauthenticated_write_total{route}`.

**Rollback.** `MARKETPLACE_REQUIRE_SIGNED_OFFERS=false` disables rejection without a
deploy. 1a/1c are not flag-gated — they are the "stop the bleeding" half; revert by PR.

**Risk.** *Medium-high, and the highest in this track.* Any live integration sending
unsigned offers breaks the moment the flag flips — that is what the bake period is for.
1a can break an existing unauthenticated client immediately; check prod logs for
anonymous `/marketplace/*` writes **before** merging.

**Size.** 3 PRs. **Do not batch MP-1 with any other item.**

> **Model: Opus 5** for 1b and 1c — cryptographic verification, fail-closed posture, a
> migration flag, and a cross-cutting ratchet; the exact profile where a subtle mistake
> re-opens the hole silently. **Sonnet 5** is acceptable for 1a alone (mechanical
> dependency addition against an explicit 16-route list) **provided** an Opus review
> pass runs before merge.

---

### MP-2 — One injection guard

**Goal.** Rule #1's injection half becomes true; no second implementation exists.

**Sketch.** Delete `negotiation.py::_scan_injection()` and its two constant lists; route
`send_offer` — plus the `send_message`/`send_proposal` handlers in `api.py` — to
`injection_guard.scan_negotiation_message()`. Keep HTTP 422 at the API edge and the
`ValueError` contract inside `negotiation.py` so its unit contract is unchanged.

**Behavior change worth a changelog line:** the regex guard is strictly stronger, so
offers that previously passed will now be rejected. That is the point.

**Acceptance.** `injection_guard.py` has a production caller and >0% coverage; one
implementation cluster-wide. **Tests.** Reuse `test_injection_guard.py` corpus against
the live route. **Size.** 1 PR.

> **Model: Sonnet 5.** Well-specified consolidation, existing test corpus, no
> cryptography and no migration.

---

### MP-3 — Escrow on accept: implement or retract ⚖️ *owner decision*

Rule #5 says escrow is automatic on `accept_offer()`. It is not.

- **(a) Implement** — `accept_offer()` calls `EscrowService`; the negotiation path
  converges with `purchase_listing()`, which *does* create escrow.
- **(b) Retract** — negotiation-accept is a price agreement; escrow belongs to the
  purchase/clearing path. Correct the doc.

**Recommendation: (b), revisit later.** `purchase_listing()` already owns escrow
creation *and* the FT-3c idempotency key. A second escrow-creating path invites exactly
the double-escrow bug FT-3c just fixed. Product question, not a refactor.

**Depends on MP-1** — an unauthenticated accept must never be able to open escrow.
**Size.** (b) = docs. (a) = 1 PR + idempotency design.

> **Model: Opus 5** to write the decision memo (it must reason about the FT-3c
> double-charge precedent and escrow lifecycle). Execution of (b) is then Haiku-tier.

---

### MP-4 — Test the gates that are live but unmeasured

**Goal.** Every module reachable from a marketplace request path has coverage on **both**
branches of its decision — accept *and* reject.

Prioritise by **reachability from an attacker-controlled request**, not by percentage:
`sybil_guard` (0%, live on listing-create and agent-register) → `brand_agent` →
`trust_graph`. This is the SR-7.2 method applied to this cluster, and it feeds SR-7.2's
83→85% push directly. **Coordinate with Track A; do not open a parallel coverage effort.**

**Acceptance.** `sybil_guard.py` ≥ 90% with an explicit "flagged agent is rejected with
403" test. **Size.** 1–2 PRs.

> **Model: Sonnet 5** — high-volume, pattern-following test authoring against existing
> fixtures. Haiku 4.5 for mechanical fixture/parametrize expansion once a Sonnet-written
> first test establishes the shape.

---

### MP-5 — Resolve the dead `mp_*` projection *(needs Track F sign-off)*

Ten `record_*` functions in `m2m_store/analytics.py` have no production caller, so five
Semantic Layer models serve empty results — silently, as "no data" rather than
"not wired".

- **(a)** wire the projector into the marketplace write paths;
- **(b)** re-point the five models at the real `marketplace_*` tables, delete the projector.

**Recommendation: (b).** The cluster already carries four order-shaped models
(`marketplace_*`, the `*_orders` blobs, the `marketplace_purchases` mirror, `mp_*`) and
**FT-6 is actively reducing that count**. Adding a live fifth writer runs against it.

**Interim, regardless of choice:** an unwired model must fail loudly, not return `[]`.
**Size.** 1 PR + F sign-off.

> **Model: Opus 5** for the decision + the loud-failure design (it must hold the FT-6
> Phase C cutover in view, and getting this wrong writes to money-adjacent tables).
> Sonnet 5 for the mechanical re-point once the target is fixed.

---

### MP-6 — Authorization posture: make the default explicit *(Track F owns the flip)*

`AUTHORIZE_PAYMENT_ENFORCED` defaults **false**, and both call sites
(`clearing.py:135`, `listing.py:706`) additionally fail-soft to "proceed" on error. As
shipped, the FT-6 chokepoint enforces nothing in production. That may be intentional —
it matches every other compliance gate here — but it is undocumented at the marketplace
level, so the chokepoint *reads* as active when it is not.

**MP-6 scope is observability + documentation only:** a metric distinguishing
allow-because-**disabled** from allow-because-**checked**, and an explicit statement of
the production default in `marketplace/CLAUDE.md`. The flip itself belongs to Track F
under `docs/master-kickoff-plan.md`; **P-6 already tracks deadlines** for the default-OFF
gates.

**Explicitly out of scope:** flipping x402/autonomy to fail-closed — proposed in FT-3 and
**rejected by the project owner 2026-07-20**; contradicts root `CLAUDE.md` and
marketplace rules #13/#20. **Size.** 1 small PR.

> **Model: Sonnet 5.** Narrow, additive, well-bounded — one metric plus a doc paragraph.

---

### MP-7 — Stop reporting simulations as capabilities

Escrow (no RPC ⇒ simulation, fail-open), `usdc._check_onchain` ("not implemented"),
`l402` BOLT-11 stub, IPFS pseudo-CID, `mandate_contract` stub bytecode, and the
logged-only 1.5% take rate all run in simulation by default. Each is individually
documented; collectively they are invisible at runtime.

Surface real mode in `GET /health/pipeline` and `GET /marketplace/protocol`. That
manifest currently advertises `"injection_guard": true` and `"signature_type":"Ed25519"`
— **both false advertising to a counterparty agent today** (T8). MP-1/MP-2 make those
two true; MP-7 makes the rest honest.

**Acceptance.** No manifest key asserts a capability that is stubbed in the running
configuration. **Size.** 1 PR.

> **Model: Sonnet 5**, with a Haiku 4.5 pass to enumerate the stub sites mechanically.

---

### MP-8 — ACP + agentic-commerce: an entitlement gate is not auth

**Goal.** T6 closed. 14 open write routes across `/acp/*` (7) and
`/business-community/commerce/*` (7), including payment-token issuance, cart checkout,
refund resolution, mandate creation/deletion, and `webhooks/ap2` (no dependency at all).

**Sketch.** Add `require_api_key` alongside the existing `_Gate` — entitlement and
identity are orthogonal and both are needed. `webhooks/ap2` is an inbound webhook and
needs **signature verification**, not an API key; treat it separately and do not paper
over it with a key.

**Why separate from MP-1.** Different files, different owner adjacency (Track F money
semantics), and it must not delay the critical path. **Depends on:** MP-1 landing first
(same pattern, proven there).

**Size.** 2 PRs (ACP; commerce + webhook signature).

> **Model: Opus 5** — payment-token issuance and refund resolution are money movement,
> and the webhook needs a signature scheme designed rather than copied.

---

## 5. Sequencing

```
MP-0  doc truth ─────────────┐  (immediate, docs-only)
                             ├──> MP-1a auth ──> MP-1b signatures ──> MP-1c empty-secret   🔴 CRITICAL PATH
MP-2  injection guard ───────┘                        │
                                                      ├──> MP-3  escrow decision
                                                      ├──> MP-4  gate coverage  (⇄ SR-7.2)
                                                      ├──> MP-7  honest manifest
                                                      └──> MP-8  ACP + commerce auth
MP-5  mp_* projection ── blocked on Track F sign-off
MP-6  authorize posture ── Track F owns the flip; MP-6 ships metric + doc only
```

**Critical path: MP-0 → MP-1a → MP-1b.** MP-1 is the only item closing an actively
exploitable hole; it ships alone. MP-2 can run in parallel (disjoint files).

---

## 6. Model routing

### Rubric

| Signal | Model |
|---|---|
| Cryptography, fail-closed posture, auth boundaries, money movement | **Opus 5** |
| Irreversible or hard-to-detect-if-wrong (a silent re-opening of a hole) | **Opus 5** |
| Cross-module design decision, or a call the project owner will act on | **Opus 5** |
| Well-specified refactor with an existing test corpus | **Sonnet 5** |
| High-volume test authoring against established fixtures | **Sonnet 5** |
| Mechanical enumeration/expansion after the shape is set | **Haiku 4.5** |
| Docs-only rewrite against a fixed evidence list | **Sonnet 5** (Haiku if purely transcription) |

Mirrors the project's own staff convention (`_MODEL_BY_LEVEL`: L1 Haiku · L2 Sonnet ·
L3 Opus) — Track M items are rated by *blast radius if wrong*, not by size.

### Assignment

| ID | Item | Model | Why |
|---|---|---|---|
| MP-0 | Doc reconciliation | **Sonnet 5** | judgement about truth, no code risk |
| MP-1a | Transport auth, 16 routes | **Sonnet 5** + Opus review | mechanical against an explicit list; review because it is an auth boundary |
| **MP-1b** | **Offer signature verification** | **Opus 5** | crypto · fail-closed · migration flag · ratchet — highest blast radius in the track |
| MP-1c | Empty-secret bypass | **Opus 5** | fail-open auth shape; same class as the FT-3a key hotfix |
| MP-2 | Injection-guard consolidation | **Sonnet 5** | bounded, existing corpus |
| MP-3 | Escrow decision memo | **Opus 5** → Haiku to execute (b) | must weigh the FT-3c double-charge precedent |
| MP-4 | Gate coverage | **Sonnet 5** (+ Haiku expansion) | volume test authoring |
| MP-5 | `mp_*` resolution | **Opus 5** decide → Sonnet 5 execute | money-adjacent data model, FT-6 interlock |
| MP-6 | Posture metric + docs | **Sonnet 5** | narrow, additive |
| MP-7 | Manifest honesty | **Sonnet 5** (+ Haiku enumeration) | mostly plumbing |
| MP-8 | ACP + commerce auth | **Opus 5** | payment tokens, refunds, webhook signature design |

**Not delegated to any model:** MP-3's choice and MP-5's/MP-6's Track F sign-off. Those
are owner decisions; a model writes the options, a human picks.

**Subagent note.** These assignments are for whoever drives execution. I do not spawn
subagents unless you ask — say the word and I'll dispatch a given item at its rated model.

---

## 7. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | MP-1a breaks an existing unauthenticated integration | Medium | High | grep prod logs for anonymous `/marketplace/*` writes **before** merge; 1a is revert-by-PR |
| R2 | MP-1b flag flipped before clients sign ⇒ mass 400s | Medium | High | verification+metric run with rejection off; flip only after the unsigned counter reads zero over a bake period |
| R3 | MP-2's stronger regex rejects legitimate traffic | Low-Med | Medium | measure match rate in shadow before enforcing; changelog entry |
| R4 | MP-4 collides with Track A's SR-7.2 sweep | Medium | Low | coordinate; MP-4 is a contribution to SR-7.2, not a parallel effort |
| R5 | MP-5 writes to money-adjacent tables mid-FT-6-Phase-C | Low | High | blocked on Track F sign-off; recommendation (b) adds no writer |
| R6 | Ratchet added in MP-1 reddens `main` from an unrelated PR | Medium | Low | run the five ratchets + full-tree ruff/mypy locally before every push (standing lesson) |
| R7 | Route enumeration undercounts via naive `app.routes` | High if unguided | Medium | the `_IncludedRouter` walk is mandatory — documented in §2.2 |

---

## 8. Invariants this track must not break

- **x402 stays fail-open** (root `CLAUDE.md`; marketplace #13/#20; owner decision
  2026-07-20). MP-1's fail-closed applies to **signature verification only**.
- **MAESTRO auto-isolation stays fail-open**, all 7 steps independent (#6).
- **KYA registration fail-open** (#18); **KYB fail-conservative, never toward ALLOW**
  (#21); **sanctions never block or delay clearing** (#22).
- **Signing keys via `resolve_key(..., purpose=...)`**, resolved per call, never at
  import — `test_no_new_raw_signing_key.py`.
- **DDL through `warden/db/ddl_registry.py`**; `db_key` per *physical file*.
- Never reintroduce a third copy of the x402 balance SQL — import from
  `payments/x402_balance.py`.
- **GDPR:** offer/negotiation content is never logged — metadata only.

## 9. Track boundaries

| Surface | Owner | MP's role |
|---|---|---|
| Order model, ledger, settlement, `authorize_payment` semantics | **Track F** | consumer; MP-5/MP-6/MP-8 need F sign-off |
| Cost/margin math, `finops/rating.py` | **Track C** | none |
| MAESTRO/reputation math, GSAM quarantine, storage seam | **Track B** | none |
| Global auth middleware (the `/communities` root cause) | **Track A** | MP-1a is the marketplace-local fix; a global middleware subsumes it — **MP-1b remains required either way** |
| Coverage gate (`--cov-fail-under`) | **Track A (SR-7.2)** | MP-4 contributes |
| Image/config/API surface | **Track P** | P-6 tracks the default-OFF gate deadlines |

## 10. Verification for every MP slice

```bash
ALLOW_UNAUTHENTICATED=true WARDEN_API_KEY="" ANTHROPIC_API_KEY="" \
LOGS_PATH="/tmp/warden_test_logs.json" DYNAMIC_RULES_PATH="/tmp/dr.json" \
REDIS_URL="memory://" MODEL_CACHE_DIR="/tmp/warden_test_models" \
python -m pytest warden/tests/test_marketplace*.py warden/tests/test_x402*.py \
  warden/tests/test_clearing*.py warden/tests/test_payments*.py \
  warden/tests/test_acp_protocol.py warden/tests/test_agentic_commerce.py -q --no-cov
```

Before **every** push (these live outside the quick slice and have reddened `main`
before): `test_route_inventory.py`, `test_no_new_counterless_failopen.py`,
`test_no_new_suppressions.py`, `test_no_raw_sqlite_connect.py`,
`test_no_new_raw_signing_key.py` — plus full-tree `ruff` + `mypy`.

## 11. Open decisions for the owner

| # | Decision | Blocks | Recommendation |
|---|---|---|---|
| D-1 | Escrow on `accept_offer()`: implement or retract? | MP-3 | **Retract** — avoid a second escrow-creating path |
| D-2 | `mp_*`: wire the projector or re-point the models? | MP-5 | **Re-point + delete** — FT-6 is reducing order-shaped models |
| D-3 | When does `MARKETPLACE_REQUIRE_SIGNED_OFFERS` flip to true? | MP-1b close-out | ✅ **resolved 2026-08-01: flipped now.** The bake period had nothing to bake — production has never used the marketplace (0 agents, 0 credits, listings/negotiations/purchases/escrow tables do not exist), so the `absent` counter would read zero indefinitely regardless. Waiting bought no information; flipping closed MP-1b's remaining half at zero risk. Required a `docker-compose.yml` passthrough, not just `.env` |
| D-4 | Does `AUTHORIZE_PAYMENT_ENFORCED` stay false in prod? | MP-6 / P-6 | Track F's call; MP-6 only makes it visible |

## 12. Status

| ID | Item | Model | Status |
|---|---|---|---|
| MP-0 | Reconcile `marketplace/CLAUDE.md` | Sonnet 5 | ✅ done — 4 false rules tagged in place, 3 anti-patterns named, rules #23/#24 added (`2795def7`) |
| MP-1a | Transport auth on open marketplace writes | Sonnet 5 + Opus review | ✅ done — 12 routes closed, verified 401; **found worse than catalogued: `POST /credits/purchase` had no auth and took the tenant from an `X-Tenant-ID` header, so an anonymous POST minted 1000 spendable credits to any tenant, free.** Ratchet added and proven to fail on a real regression (`4397039d`, `5b2c6b66`) |
| MP-1b | Offer signature verification 🔴 | **Opus 5** | ✅ done — `_assert_actor` before any state change; envelope gained `negotiation_id` (signatures were portable across negotiations); `build_offer_canonical` exported; skew window; fail-CLOSED under `MARKETPLACE_REQUIRE_SIGNED_OFFERS` (default off + metric for the bake). Original exploit re-run end-to-end: 400, negotiation stays open, real seller still settles (`43210365`) |
| MP-1c | Empty-secret admin bypass | **Opus 5** | ✅ done — `admin_guard.require_admin_key`, 503 when unconfigured, constant-time, read per call (`f752e8fe`). ⚠️ Same shape found and **not** fixed (out of cluster): `api/rotation.py:134`, `streams/api.py:55`, `tokenomics/api.py:69` |
| MP-2 | Single injection guard | Sonnet 5 | ✅ done — `_scan_injection` delegates to `injection_guard`; private lists deleted; `send_message`/`send_proposal` had **no** screening at all and now return 422 (`29097654`) |
| MP-3 | Escrow-on-accept: implement or retract | Opus 5 (memo) | ✅ done — **D-1 resolved: retract.** Accepting an offer is a price agreement; escrow stays owned by `purchase_listing()`, which holds the FT-3c idempotency key. Rule #5 rewritten to say so and to forbid a second escrow-creating path (`d1a80d09`) |
| MP-4 | Coverage for live gates | Sonnet 5 | ✅ done — covered the **gate at the request boundary** (403 path), which no test reached. ⚠️ Audit's "0%" was a measurement artifact: `test_sybil_guard.py` (14 tests, 74%) exists but doesn't match the `test_marketplace_*` glob used. Combined now 79% (`d51ccf47`) |
| MP-5 | Resolve dead `mp_*` projection | Opus 5 → Sonnet 5 | ✅ done — **D-2 resolved: re-point + delete.** 8 models moved onto real `marketplace_*` tables and **executed** against a live DB (16 queries, 0 errors — SQL-text assertions cannot catch a bad column). `marketplace_reputation` + `marketplace_cross_chain` deleted: nothing persists TrustRank, no cross-chain table exists. Projector deleted (`d1a80d09`) |
| MP-6 | Authorization-posture metric + documented default | Sonnet 5 | ✅ done — `warden_payment_authorization_total{verdict,enforced}` separates allowed-because-checked from allowed-because-off; marketplace rule #23 states the default. Flip stays Track F's call (`7851d900`) |
| MP-7 | Manifest/health honesty about simulation mode | Sonnet 5 | ✅ done — `negotiation.signature_enforced` + `escrow.settlement_mode`; derived from config, never by probing (`_check_rpc_with_retry` backs off 2/4/8s) (`7851d900`) |
| MP-8 | ACP + agentic-commerce write auth | **Opus 5** | ✅ done — 13 routes bound to the authenticated tenant. ⚠️ **Audit overstated this**: they were *not* anonymously reachable (403 on main); the real defect was body-supplied `tenant_id` ⇒ cross-tenant. `webhooks/ap2` deliberately left open (inert; an API key is the wrong control for a provider callback) (`1fc5e216`) |
