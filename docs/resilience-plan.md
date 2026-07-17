# Fault-Tolerance Audit & Remediation Plan (R-track)

**Date:** 2026-07-17 · **Scope:** full stack (docker-compose, warden pipeline, data layer, deploy path)

## What is already solid

- Healthchecks on all core services; `restart: unless-stopped` everywhere; `cloudflared` runs 2 replicas (Cloudflare HA pattern).
- Resource limits on every service; warden `stop_grace_period: 30s`; log rotation (10m × 3) on all containers.
- Deliberate fail-open/fail-closed split: security decisions fail-CLOSED (auth, signing keys, JIT lease, SAC URL screen), telemetry/cache fail-OPEN (Redis cache, GSAM→ClickHouse with size-capped NDJSON spool, S3 ship).
- Redis: AOF + RDB persistence. Prometheus: 15d retention. Deploy builds images *before* the swap (outage window minimized to the recreate).
- Nightly encrypted SQLite + Postgres backups (`warden/backup/service.py`, Fernet fail-CLOSED, 7-snapshot rotation) shipped to both same-host MinIO and an independent offsite S3 target (R1, done).
- External HTTP calls carry explicit timeouts almost everywhere (httpx's 5s default covers the rest).

## Gaps (ranked by risk)

| # | Gap | Impact | Status |
|---|-----|--------|--------|
| G1 | **No automated Postgres backup.** `pg_dump` existed only in docs. TimescaleDB data (uptime monitors, app data) was unrecoverable on volume loss. | Data loss | **DONE (R1)** |
| G2 | **All backups stayed on the same host.** SQLite snapshots shipped to MinIO *on the same VPS*; single Hetzner box was a total SPOF (disk, host, region). | Data loss | **DONE (R1)** |
| G3 | **Deploy = full-stack outage.** CI runs `docker compose down` → `up`: every merge to main drops prod for the container-recreate + model-warmup window (warden `start_period: 180s`). | Availability | **DONE for 18/19 services (R2)** — warden's own brief gap remains, see below |
| G4 | **Unhealthy containers are never restarted.** Docker healthchecks mark state but compose does not act on it — a hung (not crashed) warden stays hung until manual intervention. | Availability | **DONE (R3)** |
| G5 | **`PIPELINE_TIMEOUT_MS=0` (default).** The fail-open/closed timeout machinery in `main.py:2901` is built but disabled — a hung pipeline stage blocks uvicorn workers indefinitely. | Availability | **DONE (R3)** — verified live: `pipeline_timeout_ms:5000` |
| G6 | **Disk-full risk on 40 GB.** Loki has no retention config; ClickHouse TTL unverified; `node-exporter` (disk metrics) is behind the `monitoring` profile so likely not running in prod; no disk-usage alert in `warden_alerts.yml`. | Cascading outage | **DONE (R4)** |
| G7 | **Redis has no `maxmemory` and no compose memory limit.** Most keys are TTL'd, but unbounded growth can OOM the 16 GB host. | Cascading outage | **DONE (R5)** |
| G8 | **Single replicas:** 1 × warden (compose supports `--scale` but runs one), 1 × arq-worker. Acceptable on one VPS, but a warden crash = outage until restart completes (model load). | Availability | Open |
| G9 | **No restore drill / RTO-RPO definition.** Backups exist (SQLite) but restore has never been rehearsed end-to-end. | Recovery | Partially open (pg + SQLite restore code covered by unit tests; no live drill yet) |

## R1 — Postgres backup + offsite ship (DONE)

Implemented in `warden/backup/service.py`, shared by `scripts/db_snapshot.py` and the
`sova_nightly_backup` ARQ cron (03:30 UTC):

- `_pg_url()` derives a libpq-compatible URL from `DATABASE_URL` (strips the
  `+asyncpg` SQLAlchemy driver suffix); `PG_BACKUP_ENABLED=false` opts out.
- `_pg_dump_bytes()` runs `pg_dump --format=custom` (5 min timeout,
  `PG_BACKUP_TIMEOUT_S`), encrypted into `postgres.pgdump.enc` alongside the
  SQLite `*.db.enc` files in the same snapshot directory. A pg_dump failure is
  isolated — it never costs the SQLite snapshots in the same run
  (`record_failopen("backup_pg_dump", ...)`, counted not fatal).
- `_pg_restore_bytes()` runs `pg_restore --clean --if-exists` from a decrypted
  temp file; wired into `restore(snap, db_name="postgres")`.
- `ship_backup()` now ships to **two independent targets**: the existing
  same-host `S3_*` (MinIO) and a new `OFFSITE_S3_*` target (any S3-compatible
  endpoint on different hardware — Backblaze/Wasabi/Hetzner Storage Box
  gateway). Both are fail-open and independently counted
  (`backup_ship` / `backup_ship_offsite`).
- `warden/Dockerfile` installs `postgresql-client-16` from the PGDG apt repo
  (Debian bookworm ships client 15, which cannot dump a pg16 server).
- `docker-compose.yml`: `warden` and `arq-worker` both get `VAULT_MASTER_KEY`,
  `SNAPSHOT_DIR`, `SNAPSHOT_KEEP`, and `OFFSITE_S3_*`; `arq-worker` (where the
  cron actually runs) also gets the full `S3_*` set it previously lacked.
- 10 new tests in `warden/tests/test_backup_service.py`: URL normalization,
  encrypted-artifact round-trip, pg-failure isolation, restore dispatch,
  offsite fan-out, offsite failure is fail-open, unconfigured-offsite no-op.

**Operator setup (production `.env`):** set `OFFSITE_S3_ENDPOINT/ACCESS_KEY/
SECRET_KEY/BUCKET` to an off-VPS S3-compatible target. Without it, `ship_backup`
silently ships zero offsite copies (same fail-open contract as the existing
local-S3 path) — alertable via `record_failopen`, not a hard failure.

## R2 — Zero-downtime deploy (mostly DONE)

Implemented in `.github/workflows/ci.yml`'s deploy job:

- Replaced the blanket `docker compose down --remove-orphans` + full `up` with
  `docker compose up -d --no-build --remove-orphans --wait` scoped to exactly
  the 6 services actually rebuilt each deploy (`warden arq-worker analytics
  admin portal dashboard`). Compose only recreates a container whose
  image/config changed — every other service (proxy/Caddy, postgres, redis,
  minio, clickhouse, grafana, jaeger, loki, promtail, exporters,
  otel-collector, cloudflared) is never touched and never restarts. This is
  the fix for the Cloudflare HTTP 530s: **Caddy, the actual internet-facing
  edge, no longer goes down on every merge to main.**
- `minio-init` (one-shot bucket-init container, exits 0 after running) is
  deliberately excluded from the `--wait` service list — `--wait` treats any
  non-restarting exit as a failure even when the exit code is 0, so including
  it would make the step always report failure regardless of real health.
- The original full `down` + orphan-cleanup dance is kept, but only as a
  fallback triggered when the scoped `up` itself fails (e.g. a stale
  name-conflicting container from a prior failed deploy) — not run
  unconditionally on every deploy.
- Verified live on the production VPS before merging: ran the exact new
  command with no pending image changes and confirmed via `docker ps`
  uptimes that zero containers were recreated (a true no-op), and confirmed
  `--wait` correctly gates on health once a target service *is* rebuilt.

**Residual gap — warden's own brief window is NOT yet zero-downtime.** The
original resilience-plan draft assumed `docker compose up --scale warden=2`
plus Caddy's plain `reverse_proxy warden:8001` would round-robin across both
replicas during the swap. Verified against Caddy's docs this is **false**: a
bare hostname upstream is "dynamically static" — DNS is resolved once and
cached, not re-resolved per request or load-balanced across multiple A
records. True rolling replacement needs Caddy's `dynamic a` upstream module
(`reverse_proxy { dynamic a warden 8001 { refresh 5s } ... }`), which is
**not a core Caddy module** — it requires a custom `xcaddy` build, not the
stock `caddy:2-alpine` image currently in `docker-compose.yml`. That's a
real architecture change to the production edge proxy (new build pipeline,
new image to maintain, new failure mode if the plugin misbehaves) and needs
an explicit decision, not a silent addition — flagging as a follow-up rather
than building it unasked. Until then, warden itself still has a bounded
(~30-180s, cold-start dependent) gap during its own recreate, same as
before R2; everything else in front of and around it stays up.

## R3 — Auto-restart on unhealthy + pipeline timeout (DONE)

- `docker-compose.yml`: new `autoheal` service (`willfarrell/autoheal:latest`,
  0.1 CPU / 64M limit, read-only `docker.sock` mount, no exposed ports).
  Watches for Docker `health_status: unhealthy` events and restarts any
  container labeled `autoheal=true`. Labeled: `warden`, `proxy`, `postgres`,
  `redis` — the highest-value, lowest-risk targets (warden is stateless;
  proxy just reloads config; postgres/redis are crash-safe via WAL/AOF
  replay). Deliberately NOT blanket-applied to every service — a scoped,
  reviewable rollout rather than restarting things indiscriminately.
  `AUTOHEAL_START_PERIOD=60` gives the stack a minute after autoheal itself
  boots before it acts, layered on top of each container's own Docker
  `start_period` (already 180s for warden) so cold-start warmup is never
  mistaken for a hang.
  **Security note:** mounting `docker.sock` grants this container the
  ability to restart any container on the host. Scoped down to the
  well-known, single-purpose autoheal image with no other capabilities —
  flagging the tradeoff explicitly rather than treating a privileged mount as
  routine on a security product's own infrastructure.
- `grafana/provisioning/alerting/warden_alerts.yml`: new `warden-filter-bypass-spike`
  rule on `warden_filter_bypasses_total` (the pipeline-timeout bypass counter,
  distinct from the existing per-stage fail-open alert — this one means the
  *entire* pipeline timed out and the raw request passed with zero filtering).
  Fires on any increase over 5 minutes, `severity: critical`.
- **Operator step — done live on prod:** `PIPELINE_TIMEOUT_MS=5000` set in
  `/opt/shadow-warden/.env`, `warden` recreated. Verified via
  `GET /api/config`: `"pipeline_timeout_ms":5000, "fail_strategy":"open"`.

**Discovered mid-rollout and fixed separately:** R2's scoped deploy (only the
6 rebuilt services) doesn't see config-only changes on the other 13 services
— a brand-new service (`autoheal`) and label changes on `proxy`/`postgres`/
`redis` were invisible to it. Fixed with a second unscoped
`docker compose up -d --no-build --remove-orphans` pass after the scoped
one (commit `dbb5db68`) — verified idempotent (true no-op) when nothing
changed, and this is also what makes R4's Loki config mount below actually
land without a dedicated deploy-script change.

## R4 — Disk hygiene + alerts (DONE)

- `grafana/loki-config.yaml`: new file, identical to the `grafana/loki:2.9.4`
  image's baked-in default config (extracted directly from the image —
  schema/storage/paths must match whatever's already in the `loki-data`
  volume) plus `limits_config.retention_period: 168h` and an enabled
  `compactor`. Mounted over `/etc/loki/local-config.yaml` in
  `docker-compose.yml`. Without this Loki retained logs forever; current
  volume was 1.3GB and growing unboundedly.
- `docker/clickhouse/init.sql` already had a 30-day TTL on the GSAM
  observations table — no change needed, gap didn't exist.
- `node-exporter`: started live via `docker compose --profile monitoring up
  -d node-exporter` (not baked into `.env`/`COMPOSE_PROFILES` — that would
  also silently activate `cadvisor`, which needs `privileged: true`, a
  materially bigger security surface deserving its own explicit decision,
  out of scope here). Verified it survives a subsequent unscoped
  `--remove-orphans` pass without the profile flag — Compose treats an
  inactive-profile service as intentionally excluded, not orphaned, so it's
  safe across every future regular deploy without any `ci.yml` change.
  Prometheus was already scraping `node-exporter:9100` (job `"node"`) the
  whole time — the target just never resolved until now.
- `grafana/provisioning/alerting/warden_alerts.yml`: new
  `warden-host-disk-high` rule — `node_filesystem_avail_bytes{mountpoint="/"}`
  > 80% used for 10 minutes, `severity: warning`.

## R5 — Redis bounds (DONE)

- `docker-compose.yml`: `redis-server ... --maxmemory 1gb --maxmemory-policy
  noeviction` + `deploy.resources.limits.memory: 1280M` (1GB cap + AOF
  rewrite/fork headroom). `noeviction`, not an LRU policy: ERS scores,
  shadow-ban state, and approval tokens must never be silently evicted —
  past the cap, writes fail loudly instead (the cache layer already fails
  open on any Redis error, so a refused write degrades safely).
  Verified live usage before applying: 1.9MB used, 0 (unbounded) configured
  — ample headroom, no risk of immediately evicting/rejecting anything.
- `grafana/provisioning/alerting/warden_alerts.yml`: new
  `warden-redis-memory-high` rule on `redis_memory_used_bytes /
  redis_memory_max_bytes > 85%` for 5 minutes (redis-exporter was already
  scraped).

## Remaining remediation plan

### R6 — Restore drill + chaos verification (fixes G8, G9)
- Scripted restore rehearsal on a scratch compose project: restore latest pg + SQLite snapshots, boot warden, assert `/health/pipeline` green. Document measured RTO/RPO in `docs/sla.md`.
- Resilience test suite (staging): kill redis / clickhouse / minio / postgres one at a time; assert `/filter` still answers per its documented fail mode. Wire into the nightly autonomous loop as an optional step.

### Sequencing
R1 (done) → R2 (done) → R3 (done) → R4 (done) → R5 (done) → R6. Each phase: merge to main + deploy per CLAUDE.md deploy rule.
