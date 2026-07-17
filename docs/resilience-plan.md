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
| G3 | **Deploy = full-stack outage.** CI runs `docker compose down` → `up`: every merge to main drops prod for the container-recreate + model-warmup window (warden `start_period: 180s`). | Availability | Open |
| G4 | **Unhealthy containers are never restarted.** Docker healthchecks mark state but compose does not act on it — a hung (not crashed) warden stays hung until manual intervention. | Availability | Open |
| G5 | **`PIPELINE_TIMEOUT_MS=0` (default).** The fail-open/closed timeout machinery in `main.py:2901` is built but disabled — a hung pipeline stage blocks uvicorn workers indefinitely. | Availability | Open |
| G6 | **Disk-full risk on 40 GB.** Loki has no retention config; ClickHouse TTL unverified; `node-exporter` (disk metrics) is behind the `monitoring` profile so likely not running in prod; no disk-usage alert in `warden_alerts.yml`. | Cascading outage | Open |
| G7 | **Redis has no `maxmemory` and no compose memory limit.** Most keys are TTL'd, but unbounded growth can OOM the 16 GB host. | Cascading outage | Open |
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

## Remaining remediation plan

### R2 — Zero-downtime deploy (fixes G3)
- Replace `docker compose down && up` with `docker compose up -d --no-build --remove-orphans --wait` (recreates only changed services; `--wait` gates on health).
- Warden swap: `--scale warden=2` rolling recreate (old replica serves during new replica's 180s warmup; Caddy resolves both via Docker DNS), then scale back to 1. Keep `down` only as fallback for name-conflict recovery.

### R3 — Auto-restart on unhealthy + pipeline timeout (fixes G4, G5)
- Add `willfarrell/autoheal` service (label-scoped to warden, proxy, redis, postgres) or a systemd watchdog on the VPS.
- Set `PIPELINE_TIMEOUT_MS=5000` in prod `.env` (fail strategy stays explicit via `WARDEN_FAIL_STRATEGY`); alert on `FILTER_BYPASSES_TOTAL` spikes.

### R4 — Disk hygiene + alerts (fixes G6)
- Loki: mount a config with `limits_config.retention_period: 168h` + compactor.
- Verify `docker/clickhouse/init.sql` has a TTL on the observations table; add one (e.g. 30d) if missing.
- Run `node-exporter` in prod (`--profile monitoring`) and add a Grafana alert: disk > 80%.

### R5 — Redis bounds (fixes G7)
- `redis-server --maxmemory 1gb --maxmemory-policy noeviction` (noeviction: ERS/ban/approval keys must not be silently evicted; the cache already fails open on errors) + compose memory limit + Grafana alert via redis-exporter.

### R6 — Restore drill + chaos verification (fixes G8, G9)
- Scripted restore rehearsal on a scratch compose project: restore latest pg + SQLite snapshots, boot warden, assert `/health/pipeline` green. Document measured RTO/RPO in `docs/sla.md`.
- Resilience test suite (staging): kill redis / clickhouse / minio / postgres one at a time; assert `/filter` still answers per its documented fail mode. Wire into the nightly autonomous loop as an optional step.

### Sequencing
R1 (done) → R3 → R2 → R4 → R5 → R6. R3 is independent and highest remaining value; R2 touches only `ci.yml`. Each phase: merge to main + deploy per CLAUDE.md deploy rule.
