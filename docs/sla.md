# Shadow Warden AI — Service Level Agreement

**Version:** 1.0 · **Effective:** 2026-04-10  
**Audience:** Customers, SOC 2 auditors, compliance officers

---

## 1. Scope

This SLA applies to all paid tiers (Pro, Enterprise) of the Shadow Warden AI gateway service
(`/filter`, `/v1/chat/completions`, `/subscription/*`, portal authentication, and health
endpoints). Starter (free) tier access is best-effort with no uptime guarantee.

---

## 2. Uptime Commitment

| Tier | Monthly Uptime Target | Maximum Downtime / Month |
|------|-----------------------|--------------------------|
| Pro | 99.9% | 43.8 minutes |
| Enterprise | 99.95% | 21.9 minutes |

**Uptime** is defined as the percentage of minutes in a calendar month during which the
`GET /health` endpoint returns HTTP 200 with `{"status":"ok"}` from at least one availability
zone, as measured by the external monitoring system described in §6.

Scheduled maintenance windows (§7) and force-majeure events are excluded from downtime
calculations.

---

## 3. Performance SLOs

| Metric | Target | Measurement |
|--------|--------|-------------|
| `/filter` P50 latency | < 15 ms | Prometheus `warden_filter_duration_seconds` |
| `/filter` P99 latency | < 50 ms | Prometheus `warden_filter_duration_seconds` |
| `/filter` P99.9 latency | < 200 ms | Prometheus `warden_filter_duration_seconds` |
| `/v1/chat/completions` first-token | < 500 ms | Measured end-to-end including upstream LLM |
| 5xx error rate | < 0.1% / hour | Prometheus `warden_http_requests_total{status=~"5.."}` |
| Evolution Engine rule propagation | < 60 seconds | Time from block event to hot-reload |

---

## 4. Incident Response Times

| Severity | Definition | Initial Response | Status Update Cadence |
|----------|------------|-----------------|----------------------|
| P1 — Critical | Service unavailable or > 5% error rate | 15 minutes | Every 30 minutes |
| P2 — High | Degraded performance; P99 > 200 ms sustained | 1 hour | Every 2 hours |
| P3 — Medium | Non-blocking degradation, single component | 4 hours | Once resolved |
| P4 — Low | Cosmetic, dashboard, documentation | Next business day | On resolution |

Response times are measured from the time the incident is detected by automated monitoring
or reported by the customer via the support channel, whichever is earlier.

---

## 5. Support Tiers

| Feature | Starter | Pro | Enterprise |
|---------|---------|-----|------------|
| Support channel | GitHub Issues | Email + GitHub | Dedicated Slack + Email |
| Response SLA | Best effort | 24h business hours | 4h (P1/P2), 24h (P3/P4) |
| Uptime SLA | None | 99.9% | 99.95% |
| Incident notifications | Public status page | Email | PagerDuty / Slack webhook |
| Dedicated CSM | No | No | Yes |
| Annual security review | No | No | Yes |

---

## 6. External Uptime Monitoring

Shadow Warden AI uses **UptimeRobot** (https://uptimerobot.com) as the independent
third-party uptime monitor. Configuration is retained as SOC 2 A1 evidence.

### Monitor configuration (for auditors)

| Property | Value |
|----------|-------|
| Monitor type | HTTP(S) keyword |
| URL | `https://api.shadow-warden-ai.com/health` |
| Keyword (must be present) | `"status":"ok"` |
| Check interval | 1 minute |
| Alert contacts | On-call PagerDuty integration |
| Evidence retention | UptimeRobot logs → exported monthly to `warden-logs/uptime/YYYY-MM.json` |

### Monthly evidence export (automated)

The following command exports the previous month's uptime report and ships it to MinIO:

```bash
# Run monthly via cron or CI scheduled job
python scripts/export_uptime_evidence.py --month $(date -d "last month" +%Y-%m)
```

This produces `warden-logs/uptime/YYYY-MM.json` with:
- Total minutes monitored
- Downtime incidents with timestamps and durations
- Calculated uptime percentage
- Incident root-cause annotations (manual field)

### Alternative: self-hosted health check

If UptimeRobot is not available, the Grafana alert `warden-availability-slo` (defined in
`grafana/provisioning/alerting/warden_alerts.yml`) fires when the 1-hour success rate drops
below 99.9%. Grafana alert history exports serve as equivalent audit evidence.

---

## 7. Maintenance Windows

| Type | Schedule | Advance Notice |
|------|----------|---------------|
| Routine (patches, dependency upgrades) | Saturdays 02:00–04:00 UTC | 72 hours via status page |
| Emergency (critical security patch) | Any time | As early as possible, minimum 1 hour |
| Major version upgrade | Agreed with Enterprise customers | 2 weeks |

During maintenance:
- `/health` returns `{"status":"maintenance","eta_minutes":N}` with HTTP 503
- Downtime does not count against uptime SLA if notice was provided per the above schedule

---

## 8. SLA Credits

| Monthly Uptime Achieved | Service Credit (% of monthly fee) |
|-------------------------|-----------------------------------|
| 99.0% – 99.9% (Pro) / 99.5% – 99.95% (Enterprise) | 10% |
| 95.0% – 99.0% | 25% |
| < 95.0% | 50% |

Credits apply only to the affected calendar month and must be requested within 30 days of
the incident. Credits are applied against the next invoice; they are not refundable in cash.

---

## 9. Exclusions

The following are excluded from uptime calculations and SLA credits:

- Events caused by customer misuse, misconfiguration, or actions outside Shadow Warden's
  reasonable control
- Force majeure (natural disaster, civil unrest, regulatory action)
- Third-party upstream failures (NVIDIA NIM, Anthropic API, cloud provider outages) unless
  Shadow Warden's fail-open strategy did not activate correctly
- Scheduled maintenance communicated per §7
- Free (Starter) tier usage

---

## 10. Monitoring Evidence for SOC 2 Auditors

| Evidence item | Location | How to retrieve |
|--------------|----------|-----------------|
| External uptime logs | MinIO `warden-logs/uptime/` | `mc ls local/warden-logs/uptime/` |
| Grafana availability alert history | Grafana → Alerting → History | Export JSON |
| Health endpoint response samples | Prometheus `probe_success` (if Blackbox Exporter deployed) | PromQL query |
| Incident tickets | GitHub Issues labelled `incident` | GitHub API |
| Maintenance notifications | Git tag `maintenance/*` + release notes | `git tag -l 'maintenance/*'` |

---

## 11. Backup Restore RTO/RPO (measured, R6)

Measured via `scripts/restore_drill.py`, pulling the real latest snapshot from
the offsite S3 target (not a synthetic test file) into a throwaway scratch
Postgres + SQLite set — the actual disaster-recovery path, not a simulation.
Numbers below are from the first fully-clean end-to-end run (2026-07-26,
snapshot `20260726T033000Z`): **21 Postgres tables** (all of `warden_core`,
including the TimescaleDB uptime-monitor hypertable + its ~106 chunks) and
**7 SQLite DBs** (auth, community, healer_metrics, marketplace, sac_wallet,
secrets, x402) restored and integrity-checked.

| Stage | Measured time |
|---|---|
| Fetch latest snapshot from offsite S3 | ~0.6s |
| Start scratch Postgres 16 (TimescaleDB image) | ~6.3s |
| `pg_restore` the encrypted dump | ~9.8s |
| Restore + integrity-check SQLite snapshots | <0.1s |
| **Total measured RTO (data restore, verified)** | **~17s** |

**RPO:** bounded by the nightly `sova_nightly_backup` cron (03:30 UTC) —
worst case up to ~24h of Postgres/SQLite state loss if the VPS is lost
minutes before the next scheduled backup.

### Finding from the 2026-07-17 drill — code fix applied

The drill did **not** pass clean — 3 non-fatal `pg_restore` errors on every
run, reproducible:

1. `unrecognized configuration parameter "transaction_timeout"` — the pg_dump
   client is Postgres 17 (`warden/Dockerfile`, R1), but the actual server is
   Postgres 16. A v17 dump's `SET transaction_timeout = 0` preamble is
   rejected by a v16 server. Cosmetic in isolation (pg_restore continues past
   it), but a real version-skew bug.
2. `table "probe_results" is not a hypertable` / `ONLY option not supported
   on hypertable operations` — the uptime-monitor hypertable's foreign-key
   constraints fail to restore against a fresh TimescaleDB instance, even
   with `CREATE EXTENSION timescaledb` pre-run. TimescaleDB's chunk-based
   internal partitioning needs FK constraints reapplied in a specific order
   pg_restore's default dependency resolution doesn't get right.

**Why this mattered:** `warden/backup/service.py::_pg_restore_bytes()` — the
function the *documented, real* disaster-recovery path
(`scripts/db_snapshot.py --restore`) calls — checked `pg_restore`'s exit code
and raised on non-zero, exactly the code this drill exercised. A real restore
would have reported failure via that path even though 21 of 24 tables (all
non-hypertable data) restored completely intact. **Fixed** (see
`fix/pg-restore-timescaledb`): `_pg_restore_bytes()` now brackets the restore
with TimescaleDB's own `timescaledb_pre_restore()` / `timescaledb_post_restore()`
procedure (fixes the chunk/FK-ordering issue in #2) and judges success by
tables actually restored rather than the exit code alone (tolerates #1 as
benign noise). `scripts/restore_drill.py` mirrors the same logic so the drill
validates the real production code path.

### Finding from the 2026-07-26 re-run — a more severe, related gap

Re-running the drill (to validate the fix above) surfaced a **harder**
failure before ever reaching the two errors above: `timescaledb_post_restore()`
itself refused with `catalog version mismatch, expected "2.28.3" seen "2.26.2"`.

Root cause: `docker-compose.yml` pinned `postgres.image` to the **floating**
tag `timescale/timescaledb:latest-pg16`. Production's already-running
container is on TimescaleDB **2.26.2** (confirmed live:
`SELECT extversion FROM pg_extension WHERE extname='timescaledb'`), matching
the offsite backup — but `latest-pg16` had since moved forward to **2.28.3**.
A real disaster recovery — provisioning a fresh box and pulling `latest-pg16`
fresh — would restore into a newer extension version than the one that made
the backup, and TimescaleDB hard-refuses a cross-version restore rather than
risk silent catalog corruption. This is strictly worse than findings #1/#2
above: those were tolerated by the outcome-based fix; this one blocks the
TimescaleDB-aware restore path entirely, with 0 tables restored.

**Fixed:** `docker-compose.yml`'s `postgres.image` and
`scripts/restore_drill.py`'s `DRILL_PG_IMAGE` are both pinned to
`timescale/timescaledb:2.26.2-pg16` — confirmed via `docker inspect` to be a
distinct build from what's live (different Postgres 16.x minor/base-image
patch level) but the **same TimescaleDB extension version**, which is what
restore compatibility depends on. Postgres minor-version bumps within a major
version are binary-compatible by design, so redeploying this pin is a normal
container restart, not a data-format change — but it **is** an actual restart
of the production Postgres container on next deploy, not a no-op; deploy it
deliberately, not silently bundled with unrelated changes. Bump the pin in
both files together going forward, verified by a clean drill run before
merging any version bump — this is exactly the class of gap a floating tag
reintroduces.

Two drill-tooling robustness fixes landed alongside this investigation
(`scripts/restore_drill.py`), independent of the findings above:
- The scratch-Postgres startup check polled `pg_isready`, which can report
  ready against the postgres entrypoint's *temporary* init-phase server
  before it shuts down and execs the real one. Now polls the actual
  `CREATE EXTENSION` operation needed downstream instead of a fixed sleep.
- The pg_restore client (a separate `postgres:17` container, needed for the
  client/server version-skew reason above) reached the scratch server via
  `host.docker.internal` + its published port — a host NAT "hairpin" path
  that depends on host firewall/NAT state and was observed to time out after
  a host reboot. Now both containers share a dedicated Docker network and
  connect by container name over Docker's embedded DNS, with no host-NAT
  dependency. A further retry wraps `pg_restore` itself for TimescaleDB's own
  brief internal restart shortly after first `CREATE EXTENSION` activation.

### Finding from the 2026-07-26 clean run — final false-failure removed

With the version pin in place, the drill reached the very end of the restore —
every table, every hypertable chunk, and every FK constraint created, only the
one benign `transaction_timeout` SET ignored (`errors ignored on restore: 1`) —
and then **still reported FAIL with "0 tables restored."**

Root cause was entirely in the drill's own sanity check, not the restore: the
outcome query counted `information_schema.tables WHERE table_schema='public'`,
but the application's tables live in the **`warden_core`** schema, so a
perfectly-restored database counted 0 public tables and raised. The earlier
live hypothesis — that something in the FK-constraint-on-hypertable-chunk phase
was dropping the table count — was wrong; that phase succeeds completely.

**Fixed:** the check now counts `BASE TABLE`s across all non-system schemas
(excluding `pg_catalog`/`information_schema` and TimescaleDB's internal schemas,
so the number reflects real application tables rather than the hundreds of
hypertable chunks). The drill now passes clean end-to-end — see the measured
RTO table above.

**Status:** ✅ **Closed.** All three findings fixed; the offsite backup is
verified genuinely restorable end-to-end (RTO ~17s, 21 Postgres tables + 7
SQLite DBs). `warden/backup/service.py::_pg_restore_bytes()` (the real DR path)
and `scripts/restore_drill.py` share the same TimescaleDB-aware,
outcome-based logic, and `docker-compose.yml`/`DRILL_PG_IMAGE` are pinned in
lockstep to the extension version the backup was made with.

---

*Shadow Warden AI · sla.md · v1.3 · 2026-07-26*
