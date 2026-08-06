# Database Architecture — Analysis & Target Design (2026-08-02)

Supersedes `docs/data-layer-analysis.md` (2026-07-18), which was written before
DE-6 P1 landed. Every number below is measured from source at commit `d0c2d7cf`,
not carried over from the previous document.

> **Revision note (same day).** The first draft named float money the top finding
> and proposed rewriting the `REAL` columns in place. That was wrong: Track F's
> `warden/ledger/` already provides an exact integer-µUSD `Money` type and a
> double-entry journal, a ratchet already freezes the float surface, and FT-2
> deliberately chose opening-balance journal entries over in-place rewrites. F4
> and the roadmap are corrected accordingly. The finding that replaced it as
> highest-severity — **the Alembic tree has never been executed, leaving two
> shipped features without tables (F1)** — is verified by grep across the repo.

---

## 1. Measured inventory

| Store | Version / image | What it actually holds today | Footprint |
|-------|-----------------|------------------------------|-----------|
| **SQLite** (per-module files) | stdlib `sqlite3` | **49 distinct `.db` files, 47 DDL-registry keys, 172 tables** — marketplace, SEP/communities, staff, commerce, GSAM rollup, BI cache, auth, x402 balances | Primary OLTP |
| **PostgreSQL** | `timescale/timescaledb:2.26.2-pg16` | `warden_core` schema: `portal_users`, `portal_api_keys`, 4 syndicate tables, 3 community tables, `threat_intel_*`, `rule_ledger`, `billing_usage`, uptime hypertable, `marketplace_embeddings` (pgvector) | 1 hypertable, low QPS, **no memory limit set** |
| **Redis** | `redis:7-alpine` | cache, ERS sliding window, shadow-ban, SOVA memory, settings, approval tokens, GSAM quarantine flags, knock tokens | 1 GB `maxmemory`, `noeviction`, AOF on |
| **ClickHouse** | `24.8-alpine` | GSAM observation stream **only** — and the read APIs deliberately query the SQLite rollup instead | 2 GB limit, **write-only in practice** |
| **MinIO + offsite S3** | `minio:latest` | evidence bundles, log ship, encrypted nightly backups (R1/R6) | Fail-open, verified restorable |
| **Turso** (libsql HTTP) | opt-in | remote mirror for 6 logical DBs (`billing_audit, acp, marketplace, sep, staff, gsam`) | Off unless env set |
| **`logs.json`** (NDJSON) | file | every `/filter` decision record | **25 modules read it**, whole-file |

### What DE-6 P1 already fixed (do not re-litigate)

| Metric | 2026-07-18 | Today |
|--------|-----------:|------:|
| Files calling raw `sqlite3.connect` | 138 | **9 sites** (2 legitimate — `Connection.backup()` pair) |
| Modules on the `open_db()` seam | 0 | **116** |
| `executescript(DDL)` per connection | ~62 files | **8** |
| WAL + `busy_timeout=5000` coverage | 13 files | **every `open_db` caller** |

The connection seam (`warden/db/connect.py`) is good work and is the foundation
everything below builds on. The remaining problems are **not** connection
hygiene — they are *placement*: the wrong data is in the wrong engine.

---

## 2. Scorecard

| Dimension | Score | Rationale |
|-----------|:-----:|-----------|
| Connection hygiene | **9/10** | One seam, pragmas + DDL-once enforced by ratchet |
| Schema governance | **2/10** | Three partially-overlapping Postgres sources, and the Alembic tree **never runs** — two shipped features have no tables (F1) |
| Transactional integrity | **5/10** | Exact `Money` + double-entry journal exist (Track F) but dual-write is off; money still spans single-writer SQLite files with no cross-file transaction (F4) |
| Data-model coherence | **4/10** | Accounts and communities exist in two engines simultaneously (F2, F3) |
| Analytical read path | **4/10** | 25 modules O(n)-scan one NDJSON file (F5) |
| Operational economy | **5/10** | Five engines on one VPS, two of them serving ~one feature each (F6, F7) |
| Unit cost | **9/10** | Single Hetzner box, self-hosted, no managed-DB fees |

---

## 3. Findings

### F1 — The Alembic tree has never run, and two features depend on it ⚠️

Four parallel schema mechanisms exist:

1. `warden/db/ddl_registry.py` — SQLite, 47 keys, checksum drift detection. **Correct.**
2. `data/init.sql` — 10 `warden_core`/`warden_analytics` tables, applied **once**
   by the Postgres entrypoint on first container init only.
3. `warden/db/connection.py::create_schema()` — 13 tables of hand-maintained
   idempotent DDL, called from the FastAPI lifespan (`main.py:490-492`).
4. `warden/db/migrations/` — Alembic, chain `0001 → 0010 → 0011`.

The three Postgres sources only partially overlap: init.sql has 6 tables
`create_schema()` lacks (`api_keys`, `filter_audit`, `dynamic_rules`,
`hourly_stats`, `waitlist`, `cert_applications`); `create_schema()` has 9
init.sql lacks (`portal_users`, `portal_api_keys`, 4 syndicate, 3 community).

**And `alembic upgrade head` is invoked nowhere** — not in CI, not in
`entrypoint.sh`, not in the Dockerfile, not in the deploy workflow. Verified by
grep across the whole repo. The migration tree is dead code, so the tables that
exist *only* in it were never created in production:

| Table | Defined in | Consumed by | Production state |
|-------|-----------|-------------|------------------|
| `warden_core.monitors` | `0010` | `warden/api/monitor.py` — router **is mounted** at `/monitors` | **missing → every endpoint 500s** |
| `warden_core.probe_results` (hypertable) | `0010` | `warden/workers/probe_worker.py` | **missing** |
| `marketplace_embeddings` (pgvector) | `0011` | `warden/marketplace/vector_search.py` | **missing → fails open, semantic search silently degraded** |

This is the same failure shape as the Track P finding that PQC had never worked
in any deployed image: a shipped, mounted, documented feature that cannot
function because a schema step nothing runs was assumed to run. Ad-hoc
`ALTER TABLE … ADD COLUMN` in `try/except` inside module code
(`marketplace/clearing.py:126-128`) is a fifth, informal mechanism on top.

### F2 — Split-brain account model (highest business risk)

Two independent user stores, two password hashes, two tenant-ID issuers:

| Path | Store | Session |
|------|-------|---------|
| `warden/auth/router.py` (site sign-up/login) | **SQLite** `warden_auth.db` | `sw_session` cookie |
| `warden/portal_router.py` (portal) | **Postgres** `warden_core.portal_users` | `AsyncSession` / `Depends(get_db)` |

Consequences: GDPR Art. 17 erasure must hit both and will miss one; a tenant can
exist in one and not the other; API-key authority is ambiguous. This is the data
mirror of the already-fixed `/communities/*` dual-router authz bug — same root
cause, one layer down.

### F3 — `communities` exists in both engines

`warden_core.communities` / `community_members` / `community_key_archive` in
Postgres, and a `communities` table written by `communities/community_factory.py`
and `communities/registry.py` in SQLite. Two schemas, different column sets, no
sync. Whichever is authoritative, the other is a trap for the next reader.

### F4 — Money: precision is **already owned by Track F**; concurrency is not

An earlier draft of this document called the 41 `REAL`-typed money columns the
top finding and proposed converting them in place. **That was wrong on two
counts** and is corrected here:

- `warden/ledger/` already exists and is complete: `money.py` (`Money`, integer
  micro-USD, `float` rejected at the type boundary, `split_fee()` with exact
  conservation), plus `journal.py`, `accounts.py`, `holds.py`, `operations.py`,
  `rollup.py`, `dual_write.py`. `warden/tests/test_no_new_real_money_columns.py`
  already ratchets the float surface, and `docs/money-mutation-inventory.md`
  already inventories it.
- The FT-2 strategy is explicitly **"legacy `REAL` rows are frozen read-only and
  migrated via opening-balance journal entries — never rewritten in place."**
  Rewriting live money columns in place is the *riskier* option; Track F chose
  correctly and this document should not have contradicted it.

What is genuinely open here, and what this document stands behind:

- **Dual-write is off.** `settings.ledger_dual_write` defaults to false, so the
  journal is a shadow that is not running. Consumers wired up so far:
  `marketplace/credits.py`, `sac/preflight.py`, `finops/ledger_recon.py`.
  Turning it on, reconciling, and cutting over is **Track F's call, not a
  data-layer slice** — noted here, not scheduled here.
- **No cross-file atomicity** (unchanged, and data-layer-owned). `x402_balances`
  lives in `warden_x402_marketplace.db`; purchases/escrow/clearing live in
  `warden_marketplace.db`. A settle that debits a balance and writes an order
  spans two files — SQLite cannot make that one transaction. The outbox table is
  a partial mitigation, not a substitute.
- **One writer per file.** `warden_marketplace.db` has 28 tables and ~30 writer
  modules. WAL + 5 s `busy_timeout` turns contention into latency, then into
  `SQLITE_BUSY` under a burst. No `SELECT … FOR UPDATE`, no row-level locking,
  no serializable isolation across the credits/escrow/clearing triangle.

So the money finding is **placement (single-writer files), not precision**.
Precision has an owner and a better plan already.

### F5 — `logs.json` is the analytics substrate for 25 modules

Compliance posture, BI, XAI (`build_chain()` per record), public stats, billing,
GDPR, Art.30, SOC 2 collector, retention and the Streamlit dashboards all
re-read the full NDJSON file. There is **no rotation** — only GDPR
`purge_before()`. Read cost grows linearly and forever; a compliance dashboard
refresh is O(all history).

### F6 — Postgres is under-used and unbounded

It serves uptime probes, portal users, syndicates and embeddings — real, but
small. It is the only service in `docker-compose.yml` with **no
`deploy.resources.limits.memory`**, on a host where `warden` is already allowed
8 GB. A Timescale image is loaded to run one hypertable.

### F7 — ClickHouse has one producer and zero readers (observation, not a verdict)

The GSAM ingest writes to it (fail-open, NDJSON spool); every read surface —
`/gsam/heatmap`, `/gsam/agents/{id}/stats`, `compliance/score`, the semantic
model — reads the **SQLite rollup** by design. A 2 GB-limited OLAP container is
therefore a write-only sink today.

**This is Track B's decision, not this document's.** `docs/modernization-plan-v8.md`
deliberately enabled ClickHouse for GSAM in prod as part of DE-6, and the
rollup-not-ClickHouse read path is a stated design choice (it keeps the read
surface testable without an OLAP dependency). The observation stands; the
question — "does the raw stream earn its container, or should it fold into a
Timescale hypertable?" — is put to Track B rather than answered here.

### F8 — Cross-module reads bypass every contract

`compliance/soc2_collector.py` opens 5 peer DB files directly;
`business_intelligence/service.py` opens 3; `integrations/smb_suite.py` opens 3.
`open_db_readonly()` made this safe against accidental creation, but the coupling
is still "file path + assumed column names". Owner-side schema change breaks
readers silently.

### F9 — 49 files is a real operational tax

49 WAL/SHM sets, 49 backup objects per snapshot, 49 fds, and a long tail of
single-table DBs (`warden_push.db`, `warden_oauth.db`, `warden_quota.db`,
`warden_bdr.db`, `warden_growth.db`, `warden_support.db`, `warden_handoff.db`,
`warden_lifecycle.db`, …) that gain nothing from isolation.

---

## 4. Target architecture

**Principle: three engines, chosen by durability requirement — not five engines
chosen by feature.**

```
                        ┌──────────────────────────────────────────┐
   hot path             │  Redis 7  — ephemeral, reconstructible    │
   (µs, fail-open)      │  cache · ERS window · shadow-ban · sessions│
                        │  quarantine flags · approval tokens · SOVA │
                        └──────────────────────────────────────────┘
                                          │
   ┌──────────────────────────────────────┴───────────────────────────────┐
   │  PostgreSQL 16 + TimescaleDB + pgvector — SYSTEM OF RECORD           │
   │                                                                       │
   │  identity     portal_users · api_keys · tenants   (one table each)    │
   │  money        ledger · escrow · credits · x402_balances · clearing    │
   │               billing_audit_chain   (amounts stay integer µUSD — the  │
   │               warden/ledger Money type; Postgres buys atomicity here, │
   │               not precision, which Track F already solved)            │
   │  multi-tenant communities · members · SEP transfers · peerings        │
   │  timeseries   filter_events · gsam_observations · uptime_probes       │
   │               (hypertables + continuous aggregates)                   │
   │  vectors      marketplace_embeddings (pgvector, already migration 0011)│
   └───────────────────────────────────────────────────────────────────────┘
                                          │
   ┌──────────────────────────────────────┴───────────────────────────────┐
   │  SQLite (per-module, via open_db) — MODULE-LOCAL, LOW-CONSEQUENCE     │
   │  healer recipes · BI cache · semantic-layer cache · staff drafts      │
   │  threat store · frameworks · webhooks queue · push tokens             │
   │  Rule: single writer, no money, tolerable to lose and rebuild         │
   └───────────────────────────────────────────────────────────────────────┘

   MinIO + offsite S3 — evidence bundles · log ship · encrypted backups (keep as-is)
```

### Placement rule (write this into `CLAUDE.md`)

> A table goes to **Postgres** if losing or corrupting one row costs money,
> breaks an audit chain, or is written by more than one module.
> Otherwise it stays in **SQLite**. Nothing that must survive a restart goes
> only in **Redis**.

### Classification of the 49 existing SQLite files

**Class A → Postgres (money / identity / audit) — 12 files, non-negotiable**
`warden_marketplace.db`, `warden_marketplace_clearing.db`,
`warden_x402_marketplace.db`, `warden_voice_x402.db`, `warden_billing_audit.db`,
`warden_acp.db`, `warden_commerce.db`, `warden_m2m_store.db`, `warden_ledger.db`,
`warden_auth.db`, `warden_stripe_billing.db`, `warden_costs.db`

**Class B → Postgres (multi-tenant shared, >1 writer) — 5 files**
`warden_sep.db` (31 tables, ~15 modules), `warden_communities.db`,
`warden_community_registry.db`, `warden_entity_store.db`, `warden_quota.db`

**Class C → stays SQLite — ~32 files**, of which ~10 should be **merged** per
domain: fold `push/oauth/webhooks/notif` → `warden_platform.db`, and
`bdr/growth/support/handoff/staff_a2a/staff_economics` → `warden_staff.db`.

### What to delete

- ✅ **`connection.py::create_schema()`** — removed (2026-08-06). Alembic is the only Postgres schema authority, guarded by `test_one_postgres_schema_authority.py`. `data/init.sql` stays for a brand-new container's first boot, with revision `0012` a strict superset of it. Originally stated as:
- **`connection.py::create_schema()` and the Postgres half of `data/init.sql`** —
  Alembic becomes the only Postgres schema authority, and it is actually
  executed. (F1 — do this first; it is the one item that restores working
  features.)
- **ClickHouse** — *candidate*, Track B's decision (F7). If retired, the GSAM
  observation stream folds into a Timescale hypertable on the Postgres you
  already run, and continuous aggregates replace `gsam/rollup.py`'s hand-rolled
  hourly upsert: −1 container, −2 GB RAM budget, −1 OLAP dialect.
- **`logs.json` as a read source** — it stays as the write-side journal (the
  GDPR purge machinery works and is audited); all 25 readers move to a
  `filter_events` hypertable + continuous aggregates. (F5)
- **Turso** — keep opt-in as DR mirror only. Never a primary for hot tables:
  per-statement HTTP is ~tens of ms against local SQLite's µs.

### What NOT to add (asked-and-answered, so it is not re-litigated)

| Tempting | Why not |
|----------|---------|
| MongoDB / DynamoDB | The data is relational and money-bearing; you need constraints, not schemaless |
| Neo4j | `marketplace/trust_graph.py` is the only graph workload; recursive CTEs in Postgres handle it to ~10⁶ edges |
| Elasticsearch / OpenSearch | SIEM already **exports** to Splunk/Elastic (`analytics/siem.py`) — running your own is duplicate cost |
| Kafka / NATS | Redis Streams + the existing outbox pattern cover current volume; Kafka is a 3-node ops commitment |
| Managed PG (Neon / Supabase / RDS) | $25–70/mo + cross-network latency on a hot money path, to replace a container that costs $0 marginal on an already-paid VPS. Revisit only at multi-region or >50 req/s sustained |
| pgvector → Pinecone/Qdrant | `vector_search.py` already documents "pgvector handles ~1M rows" — correct call, keep it |

---

## 5. Economics

Current marginal DB cost: **$0** (all self-hosted on one Hetzner VPS, 16 GB).
The proposal does not add spend — it **removes** a container.

| Change | RAM effect | Ops effect |
|--------|-----------:|------------|
| Drop ClickHouse | **+2 GB** freed | −1 container, −1 dialect, −1 init script |
| Cap Postgres (`limits.memory: 2g`, `shared_buffers=512MB`) | bounded | Removes the only unbounded service |
| Merge ~10 SQLite files | negligible | −10 WAL sets, −10 backup objects/snapshot |
| Timescale hypertables replace `logs.json` reads | — | Dashboard/BI/XAI latency goes flat instead of linear |

**Break-even for managed Postgres:** not before sustained load exceeds a single
box, or a second region is required. Until then, self-hosted PG on the existing
VPS is strictly cheaper *and* lower-latency. The correct spend, if any, is on
**backup destination** (already done — offsite S3, R1/R6 verified), not on a
managed primary.

---

## 6. Roadmap (each slice independently mergeable)

| # | Slice | Effort | Risk | Unblocks |
|---|-------|:------:|:----:|----------|
| **D-1** | **Schema authority — make Alembic actually run.** Apply `alembic upgrade head` under a Postgres advisory lock; reconcile init.sql / `create_schema()` / Alembic into one path; verify `monitors`, `probe_results`, `marketplace_embeddings` are created. Ratchet: no `CREATE TABLE` for Postgres outside `migrations/`. | 1–2 d | Low | **F1 — restores two dead features** |
| **D-1b** | ✅ **done** — `data/init.sql` folded into revision `0012`. Six tables lived only there (`waitlist`, `cert_applications` are live code paths). It also found a **second broken feature**: init.sql patched `portal_users` with `totp_secret`/`totp_enabled` via `ALTER TABLE IF EXISTS`, which is a **no-op on a fresh volume** — `portal_users` does not exist at Postgres-init time; the app's `create_schema()` creates it later, without those columns, and no migration added them. `portal_router.py` uses them in 8 places, so portal MFA failed with *column does not exist*. Guarded by `test_alembic_is_a_superset_of_init_sql`. | — | — | F1 |
| **D-2** | ✅ **done** — Postgres memory capped at 2 GB. It was the only service without a limit, and this image's `timescaledb-tune` sizes from the memory it *believes* it has: measured unbounded on the 16 GB host it picked `shared_buffers=3494 MB` / `effective_cache_size=10 GB`, while warden is separately allowed 8 GB on the same box. The tuner reads the cgroup, so the limit alone is the whole fix (explicit `-c` flags produced identical settings and were dropped). | — | — | F6 |
| **D-3** | 🟡 **seam shipped** — `warden_core.filter_events` hypertable + `filter_events_hourly` continuous aggregate (rev `0013`), `warden/analytics/events_store.py` (opt-in mirror off `FILTER_EVENTS_MIRROR`, readers return `None` ⇒ caller keeps its scan), and `financial/metrics_reader.py` migrated as the reference consumer. **GDPR: the mirror is inside the erasure path** — `logger.purge_before()`/`purge_old_entries()` purge it in the same call, and `GDPR_LOG_RETENTION_DAYS` stays the single retention authority (the migration installs no Timescale retention policy on purpose). **Remaining:** the other ~24 readers still scan NDJSON — mechanical, one caller at a time, each with the same `None`-fallback shape. | ~1 d done, ~2 d left | Low | F5, F8 |
| **D-4** | ✅ **done** — `warden/auth/user_store.py` is now the one account store behind both front doors. `portal_users` (Postgres) is authoritative when configured; the SQLite table stays as the fallback read and the sole store when `DATABASE_URL` is unset, because `auth/router.py` must keep working air-gapped and auth here is fail-closed. Both routers hash with the same `bcrypt`, so accounts move **without a password reset**: a SQLite-only account is promoted on its next *verified* login, and `import_sqlite_users()` does the rest in bulk. Uniqueness now spans both stores, so a site signup can no longer shadow a portal account. **Not unified:** the session mechanisms (`sw_session` JWT cookie vs. the portal's access/refresh tokens) — a separate concern, not needed to fix the data split. | — | — | F2, GDPR erasure correctness |
| **D-5** | ⛔ **blocked, and the premise was partly wrong — see §6b.** A readiness check found both Track F prerequisites unmet (`LEDGER_DUAL_WRITE` has never run; FT-6 Phase C not started), *and* that the atomicity gap D-5 was meant to buy is mostly **not cross-file**: clearing/listing/credits/escrow already share one `marketplace` file. The real gap was cross-*transaction* inside that file, and it has been fixed in SQLite — no migration required. | — | **High** | F4 (placement half) |
| **D-6** | 🟡 **the correctness half is done.** The duplicate `communities` schema was not cosmetic: `/communities` is served by **two mounted routers over two different SQLite files** (`router.py` → `warden_community_registry.db` for create/get/members/entities/break-glass; `communities_v2.py` → `warden_communities.db` for join/settings/data/peers/analytics). Their routes do not collide, so both are live on disjoint halves of one API — and v2 has **no create endpoint**, so nothing ever wrote its table and **every v2 endpoint 404'd on every community the API could create**. Fixed by making the registry store canonical and bridging `community_factory`'s seven accessors onto it (reads + writes), projecting `visibility`/`join_policy` out of the registry's existing `settings` JSON — no schema change, no `ALTER` on a live table. Legacy rows still resolve. **Remaining (volume, not correctness):** moving the SEP cluster (`warden_sep.db`, 31 tables / ~15 modules) and these two files to Postgres. | ~1 d done | Med | F3 |
| **D-7** | ❌ **dropped after measurement — do not re-propose.** See §6a. | — | — | — |
| **D-8** | **ClickHouse question to Track B** — fold the GSAM stream into a hypertable, or keep. Decision, then ≤2 d. | — | — | F7 |

Suggested order: **D-1 → D-2 → D-3 → D-4 → D-6 → D-7 → D-5 (with Track F) → D-8 (Track B).**
D-1 first because it is the only slice that restores functionality users are
already paying for. D-3 builds Postgres operational confidence on low-risk data
before any money table moves.

**Explicitly not in this roadmap:** converting `REAL` money columns in place.
That is Track F's FT-2, which chose opening-balance journal entries over
in-place rewrites — see F4.

### 6b. D-5 (money tables → Postgres) — readiness check: not ready, and narrower than stated

**Track F prerequisites, both unmet.** `LEDGER_DUAL_WRITE` defaults false, so the
double-entry journal is a shadow that has never run and no reconciliation
baseline exists. FT-6 Phase C (cutover reads) has not started and is explicitly
gated on a production bake plus reconciliation queries; `marketplace_purchases`
is documented as a fail-soft mirror that is *not yet trusted*. Moving the same
rows to Postgres now would be a second concurrent migration on one dataset, and
would destroy the ability to reconcile the first.

**Measured risk factors.** Coverage on the modules that would be rewritten:
`clearing` 79%, `credits` 68%, `escrow` 61% — against 100% on this repo's
security modules. Two Streamlit pages (`23_Marketplace_Admin.py`,
`24_Agentic_Trading.py`) open `MARKETPLACE_DB_PATH` directly, outside the module
seam. `marketplace_purchases` has 7 readers, `marketplace_escrow` 6.

**Correction to §F4.** The cross-file atomicity gap is narrower than this
document claimed. `clearing`, `listing`, `credits` and `escrow` all open the same
`marketplace` db_key — one file, so one transaction was always possible. The
separate files are `marketplace_x402` and `voice_x402`, and no flow writes both:
`x402_gate` deducts a balance, `voice/x402` is a different product, and neither
writes a marketplace order in the same call.

**The real gap, and it did not need Postgres.** `_do_purchase` committed three
separate statements — INSERT purchase, `create_escrow`'s own INSERT, then an
UPDATE writing the escrow_id back — serialised only by a `threading.RLock`,
which is in-process while `arq-worker` and `workers/x402_settlement.py` write the
same database from other containers. The worst window left an escrow row holding
funds against a purchase that still read `escrow_id=""`. Fixed by deploying the
contract outside the transaction (it is a network round-trip that can raise) and
writing both rows in one, which also removed the third statement entirely.
Escrow-failure policy is deliberately unchanged — a purchase whose escrow could
not be created is still recorded with `escrow_id=""`; making that roll back is a
money-semantics decision for Track F.

**Verdict.** D-5 stays blocked on Track F. Its headline benefit has been
delivered at a fraction of its risk.

### 6a. D-7 (merge the SQLite long tail) — dropped, with the measurement

The original plan folded ~10 single-table DBs into `warden_platform.db` and
`warden_staff.db`. Measured before implementing, it does not pay for itself:

| | Finding |
|---|---|
| Coupling to untangle | **None.** All 14 tail `db_key`s (`push`, `oauth_discovery`, `quota`, `handoff`, `notifications`, `webhooks`, `webhook_dispatch`, `marketplace_lifecycle`, `staff_bdr/growth/support/compliance/a2a/economics`) hold 1–3 tables and have **exactly one writing module** each. Merging buys file count and nothing else. |
| Concurrency | **Net negative.** SQLite is single-writer *per file*. Folding the five `staff_*` keys into one file puts `staff_economics` (writes on every agent action, via `_record_cost` on every return path) and `staff_a2a` (writes on every cross-agent call) — the subsystem's two highest-frequency writers — behind a single write lock, alongside three draft stores. This document's own principle in P3/§4 ("per-domain files preserve write concurrency") argues *against* the merge, not for it. |
| Risk | Every one of these files holds live production rows — push device tokens, OAuth grants, quota counters, refund intents, SAR drafts, the staff cost ledger, webhook endpoints and their secrets. Merging means a data migration on the VPS. |
| Benefit | ~10 fewer files in the nightly snapshot and ~10 fewer WAL/SHM triples. Nothing measures this as a constraint; `backup/service.py` handles the current 49 without strain. |

A live-data migration plus a write-concurrency regression, in exchange for a
smaller `ls`. Dropped.

Also checked while measuring, and **clean**: no `db_key` is used against two
different physical files (the cross-leak hazard `warden/db/ddl_registry.py`
warns about). `web3/key_rotation.py` looks like a violation in a naive grep — it
holds both `settings.key_rotation_db_path` and `settings.marketplace_db_path` —
but it opens each under its own matching key, which is correct.

---

## 7. Answer to "which databases should be connected"

**Connect / promote (all already present — none are a new dependency):**

1. **PostgreSQL 16** — promote from side-store to **system of record**.
2. **TimescaleDB** (already the running image) — hypertables + continuous
   aggregates for `filter_events`, `gsam_observations`, `uptime_probes`.
   Replaces both `logs.json` reads and ClickHouse.
3. **pgvector** (already migration 0011) — the only vector store needed.
4. **Redis 7** — unchanged; keep `noeviction`, keep AOF, keep fail-open.
5. **SQLite via `open_db()`** — unchanged; demoted to the module-local tier.
6. **MinIO + offsite S3** — unchanged; evidence and backups.

**Disconnect:** ClickHouse. **Keep opt-in only:** Turso (DR mirror).
**Do not add:** anything else.

The win in this architecture is **subtraction**, and every recommendation runs
on infrastructure the project already pays for.
