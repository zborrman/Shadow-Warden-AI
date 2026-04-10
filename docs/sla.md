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

*Shadow Warden AI · sla.md · v1.0 · 2026-04-10*
