# Settings Integration Guide

Shadow Warden exposes live-tunable configuration through the API, wired to
the `enterprise-settings.html` and `settings.html` frontend pages.

---

## Configuration Endpoints

### Read config

```bash
GET /api/config
X-API-Key: your-key
X-Tenant-ID: default
```

### Update config

```bash
POST /api/config
X-API-Key: your-key
Content-Type: application/json

{
  "semantic_threshold": 0.75,
  "strict_mode": false,
  "rate_limit": 1000
}
```

!!! warning "Tier-1 changes"
    Changing `ANTHROPIC_API_KEY`, `VAULT_MASTER_KEY`, or `WARDEN_API_KEY`
    requires Slack approval via the HMAC-signed approval token flow.
    See [Phase 4 plan](../changelog/index.md) for the wiring timeline.

---

## Live-Tunable Settings

| Key | Type | Effect |
|-----|------|--------|
| `semantic_threshold` | float (0–1) | MiniLM similarity gate |
| `strict_mode` | bool | All borderline → BLOCK |
| `rate_limit` | int | Requests/minute per tenant |
| `intel_ops_enabled` | bool | Background ArXiv/OSV sync |
| `intel_bridge_interval_hrs` | int | ArXiv → Evolution sync cadence |

---

## Environment Variables Reference

All settings are loaded from environment variables at startup. The table
below lists every variable in priority order.

| Variable | Default | Impact |
|----------|---------|--------|
| `WARDEN_API_KEY` | — | Required. Fail-closed auth. |
| `ALLOW_UNAUTHENTICATED` | `false` | Set `true` in tests only |
| `SEMANTIC_THRESHOLD` | `0.72` | Jailbreak similarity gate |
| `STRICT_MODE` | `false` | Escalate borderline to BLOCK |
| `REDIS_URL` | `redis://localhost:6379/0` | Cache + ERS + session memory |
| `ANTHROPIC_API_KEY` | — | Evolution Engine + SOVA |
| `NVIDIA_API_KEY` | — | NIM Nemotron moderation |
| `SLACK_WEBHOOK_URL` | — | Alerts |
| `ADMIN_KEY` | — | Admin endpoint auth |
| `VAULT_MASTER_KEY` | — | Fernet at-rest encryption |
| `COMMUNITY_DB_PATH` | `/tmp/warden_community.db` | Community SQLite |
| `CVE_REPORT_PATH` | `data/cve_report.json` | CVE scan output |
| `SECURITY_POSTURE_PATH` | `data/security_posture.json` | Posture badge |
| `PATROL_URLS` | — | Extra visual patrol targets |
| `HEALER_BYPASS_THRESHOLD` | `0.15` | Auto-heal trigger (15%) |
