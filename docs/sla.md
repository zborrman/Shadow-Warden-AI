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

Measured 2026-07-17 via `scripts/restore_drill.py`, pulling the real latest
snapshot from the offsite S3 target (not a synthetic test file) into a
throwaway scratch Postgres — the actual disaster-recovery path, not a
simulation.

| Stage | Measured time |
|---|---|
| Fetch latest snapshot from offsite S3 | ~1.5–1.8s |
| Start scratch Postgres 16 (TimescaleDB image) | ~2–5s |
| `pg_restore` the encrypted dump | ~5–26s |
| **Total measured RTO (Postgres data only)** | **~10–30s** |

**RPO:** bounded by the nightly `sova_nightly_backup` cron (03:30 UTC) —
worst case up to ~24h of Postgres/SQLite state loss if the VPS is lost
minutes before the next scheduled backup.

### Finding from the drill (open, not yet fixed)

The drill did **not** pass clean — 3 non-fatal `pg_restore` errors on every
run, reproducible:

1. `unrecognized configuration parameter "transaction_timeout"` — the pg_dump
   client is Postgres 17 (`warden/Dockerfile`, R1), but the actual server is
   Postgres 16 (`timescale/timescaledb:latest-pg16`). A v17 dump's `SET
   transaction_timeout = 0` preamble is rejected by a v16 server. Cosmetic in
   isolation (pg_restore continues past it), but a real version-skew bug.
2. `table "probe_results" is not a hypertable` / `ONLY option not supported
   on hypertable operations` — the uptime-monitor hypertable's foreign-key
   constraints fail to restore against a fresh TimescaleDB instance, even
   with `CREATE EXTENSION timescaledb` pre-run. TimescaleDB's chunk-based
   internal partitioning needs FK constraints reapplied in a specific order
   pg_restore's default dependency resolution doesn't get right.

**Why this matters:** `warden/backup/service.py::_pg_restore_bytes()` — the
function the *documented, real* disaster-recovery path
(`scripts/db_snapshot.py --restore`) calls — checks `pg_restore`'s exit code
and raises on non-zero, exactly the code this drill exercised. A real
restore of this database today would report failure via that path even
though the drill showed 21 of 24 tables (all non-hypertable data) restore
completely intact. This is precisely what a restore drill is for: "we have
backups" was true; "the documented one-command restore definitely works"
was not, until measured. **Follow-up needed:** either make
`_pg_restore_bytes()` tolerate pg_restore's ignored-error exit code
(distinguishing it from a genuine hard failure) and script FK-constraint
reapplication for hypertables, or adopt TimescaleDB-aware backup tooling.
Tracked as a known gap, not silently patched under this pass.

---

*Shadow Warden AI · sla.md · v1.1 · 2026-07-17*
