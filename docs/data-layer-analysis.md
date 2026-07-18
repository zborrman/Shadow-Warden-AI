# Data-Layer Analysis — Efficiency, Reliability, Cost (2026-07-18)

Scope: the C2 data-layer workstream (Track B / DE-6). Measured from source, not from docs.

## 1. Inventory (measured)

| Store | Usage | Footprint |
|-------|-------|-----------|
| SQLite (per-module) | **138 files call `sqlite3.connect` (209 sites)**; ~35 distinct DB files under `data_dir()` | Primary OLTP store |
| Postgres 16 (+ Timescale migration tree) | Uptime probes, optional pgvector/clearing paths, Alembic | Mostly idle |
| Redis | cache, ERS, quarantine flags, settings, SOVA memory, knock tokens | Hot path, fail-open |
| ClickHouse | GSAM observation stream only (NDJSON spool fallback) | Single consumer |
| Turso (libsql HTTP) | opt-in remote mirror for 6 DBs (`billing_audit, acp, marketplace, sep, staff, gsam`) | Off unless env set |
| MinIO + offsite S3 | evidence bundles, log ship, encrypted backups | Fail-open |
| `logs.json` NDJSON | event logger; read whole-file by dashboard, BI, XAI | O(n) reads |

Biggest shared files: `warden_marketplace.db` (~30 modules), `warden_sep.db` (~15 modules), `warden_communities.db`, `warden_commerce.db`, `warden_costs.db`. Long tail of single-table DBs: `warden_push.db`, `warden_oauth.db`, `warden_quota.db`, `warden_bdr.db`, `warden_growth.db`, `warden_support.db`, `warden_handoff.db`, `warden_lifecycle.db`, …

## 2. Scorecard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Efficiency | **6/10** | Connection-per-call everywhere; DDL re-executed on most connects; whole-file `logs.json` analytics reads |
| Reliability | **7/10** | WAL + busy_timeout exist but applied in only 13 of 138 files; excellent backup story (R1); DDL races possible on 62 legacy modules |
| Economy (ops) | **5/10** | 4 DB technologies + Turso + MinIO on one VPS; Postgres and ClickHouse each serve ~1 feature |
| Unit cost | **9/10** | Single Hetzner VPS, all self-hosted, no managed-DB fees; Turso free tier optional |

## 3. Findings

### F1 — Pragma helper is 90% unadopted (reliability, efficiency)
`warden/db/sqlite_pragmas.py::init_pragmas` (WAL, `synchronous=NORMAL`, `busy_timeout=5000`) is imported by **13 files**; the other ~125 connect sites run library defaults — `journal_mode=DELETE` (until some WAL-enabling module touches the same file first) and **`busy_timeout=0`**, i.e. instant `database is locked` under concurrent writers. `warden_marketplace.db` has ~30 writer modules; lock errors there are a when, not an if.

### F2 — DDL-once ratchet is ~25% done (efficiency, reliability)
**62 files still `executescript(DDL)` on every connection** (the Phase 6 registry covers ~30). Cost per request: parse + `CREATE TABLE IF NOT EXISTS` × N tables, plus a write-lock acquisition even for read paths. Two processes initializing the same file concurrently can race on index creation.

### F3 — Cross-module DB reads bypass any API (reliability)
`soc2_collector` opens 5 peer DB files; `business_intelligence/service.py` reads `sep`, `vendor`, `costs` files directly; `smb_suite` opens 3. Schema drift in the owning module silently breaks readers — there is no contract beyond the file path. (BI read-only rule limits blast radius but not drift.)

### F4 — Postgres and ClickHouse are each ~single-tenant (economy)
Postgres serves uptime probes (Timescale) and optional clearing/pgvector paths; ClickHouse serves only the GSAM stream, whose *read* surface deliberately uses the SQLite rollup. Both containers cost RAM/attention on a single VPS ~24/7 for marginal load.

### F5 — `logs.json` is the analytics bottleneck (efficiency)
Dashboard, BI, and XAI (`build_chain()` per record) each re-read the full NDJSON. Atomic-replace writes are safe but O(file) reads grow linearly forever until GDPR purge.

### F6 — Turso on hot paths would be a latency cliff (efficiency)
The adapter is per-statement HTTP; local SQLite is µs, Turso is ~tens of ms per query. Fine as DR mirror; wrong as primary for `marketplace`/`sep` hot tables.

## 4. Proposal (ordered by ROI)

### P1 — Single connection helper (1–2 days, highest ROI)
Add `warden/db/connect.py::open_db(db_key)` that does `sqlite3.connect` + `init_pragmas()` + `ensure_schema()` in one call; migrate connect sites mechanically (marketplace + sep clusters first). Add a ratchet test (`test_no_raw_sqlite_connect.py`, baseline 138 → 0) in the style of the existing key-hygiene ratchet. Kills F1 and F2 with one seam.

### P2 — Finish the DDL-registry migration (mechanical, rides P1)
Every module touched by P1 moves its `executescript` into `register()`. No schema changes, pure mechanics.

### P3 — Merge the long tail of single-table DBs (half day)
Fold `push/oauth/quota/bdr/growth/support/handoff/lifecycle` into per-domain files (`warden_staff.db`, `warden_platform.db`). Fewer fds, fewer WAL files, fewer backup objects. Keep `marketplace`/`sep`/`commerce` separate — per-domain files preserve write concurrency (SQLite is single-writer **per file**).

### P4 — Retire or commit Postgres (decision, then 1 day)
Two coherent end-states; pick one:
- **(a) Drop it**: move uptime probes to SQLite + the existing rollup pattern; save ~200–400 MB RAM + one Alembic tree. Cheapest.
- **(b) Commit it**: move money-adjacent multi-writer tables (clearing, escrow, credits, billing audit chain) to Postgres for real transactions/constraints — the direction `docs/fintech-grade-commerce-plan.md` implies. Right if commerce volume is real.
Running it as-is (option c, status quo) is the only wrong answer.

### P5 — Analytics reads off `logs.json` (1 day)
Keep NDJSON as the write-side journal (GDPR purge machinery already works). Add an hourly SQLite rollup (same pattern as `gsam/rollup.py`) that dashboard/BI/XAI query instead of full-file scans. ClickHouse stays GSAM-only; do **not** widen it.

### P6 — Read contracts for cross-module data (rides P5)
`soc2_collector`/BI/`smb_suite` switch from opening peer DB files to the owning module's read helpers (most already exist: `read_agent_stats`, semantic-layer models). Drift becomes an import error, not a silent wrong number.

### Non-goals
- No single mega-DB (kills write concurrency, one corruption takes all).
- No new DB technology; the win is subtraction.
- Turso stays opt-in DR; never default for hot tables.

## 5. Expected effect

| Change | Effect |
|--------|--------|
| P1+P2 | Removes per-request DDL + lock-error class; every connection gets WAL + 5s busy_timeout |
| P3 | ~10 fewer DB files; smaller backup set |
| P4a | −1 container, −1 migration tree, ~300 MB RAM back |
| P5 | Dashboard/BI latency flat instead of linear in log size |
| P6 | Cross-module schema drift becomes compile-time visible |

Total estimate: ~5–7 working days, no behavior changes visible to API consumers, all slices independently mergeable under the existing DE-6 umbrella.
