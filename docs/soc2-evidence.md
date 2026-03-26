# Shadow Warden AI — SOC 2 Type II Evidence Guide

**Version:** 1.0 · **Date:** 2026-03-26
**Audience:** SOC 2 auditors, compliance officers, security engineers

---

## Overview

This document maps Shadow Warden AI controls to the SOC 2 Trust Services Criteria (TSC). It identifies what automated evidence is generated, where it is stored, and how auditors can retrieve and verify it.

Shadow Warden AI's **Evidence Vault** and **Cryptographic Audit Trail** are specifically designed to support SOC 2 Type II audit engagements with minimal manual evidence collection overhead.

---

## Trust Services Criteria Coverage

### CC6 — Logical and Physical Access Controls

#### CC6.1 — Logical access security software, infrastructure, and architectures

| Control | Implementation | Evidence location |
|---------|---------------|-------------------|
| API authentication | Per-tenant API keys; SHA-256 hash lookup; constant-time compare | `warden/auth_guard.py`, configuration via `WARDEN_API_KEYS_PATH` |
| Dashboard authentication | bcrypt password hash + TOTP MFA option | `warden/analytics/auth.py` |
| SSO / SAML | SAML 2.0 SP (python3-saml), configurable via env vars | `warden/auth/saml_provider.py` |
| Docs protection | HTTP Basic auth on `/docs`, `/redoc`, `/openapi.json` | `main.py` → `_docs_auth()` |
| Audit trail | Every authentication event can be logged via `AUDIT_TRAIL_ENABLED=true` | `data/audit_trail.db` |

**Evidence to provide auditors:**
- API key rotation log (from git history or Vault)
- `data/audit_trail.db` → `SELECT * FROM audit_trail ORDER BY ts` (hash-chain verification)
- `GET /admin/audit/verify` response (confirms chain integrity)

#### CC6.7 — Restriction of access to information assets

| Control | Implementation | Evidence location |
|---------|---------------|-------------------|
| PII encryption at rest | Fernet AES-128-CBC per-process key; HMAC-SHA256 reverse map | `warden/masking/engine.py` |
| Secret redaction before LLM | SecretRedactor strips 15+ regex patterns before any ML stage | `warden/secret_redactor.py` |
| MinIO bucket isolation | Private access only; minio-init sets `mc anonymous set none` | `docker-compose.yml` → minio-init |
| GDPR content never logged | Only metadata logged; content field deliberately absent from schema | `warden/analytics/logger.py` → `build_entry()` |

---

### CC7 — System Operations

#### CC7.2 — Monitoring of system components and detection of security events

| Control | Implementation | Evidence location |
|---------|---------------|-------------------|
| Prometheus metrics | `warden_*` namespace — latency, block rate, poisoning, shadow ban | `/metrics` endpoint |
| Structured JSON logging | All logs emit JSON with `ts`, `level`, `logger`, `message` | stdout → log aggregator |
| Grafana SLO alerts | P99 latency, 5xx error rate, availability, shadow ban rate, corpus drift | `grafana/provisioning/alerting/warden_alerts.yml` |
| Real-time alerting | Slack + PagerDuty on HIGH/BLOCK risk events | `warden/alerting.py` |
| Telegram alerts | Poisoning attacks and Self-Healing events | `warden/telegram_alert.py` |
| SIEM integration | Splunk HEC + Elastic ECS output | `warden/analytics/siem.py` |

**Evidence to provide auditors:**
- Grafana dashboard screenshots over the audit period
- Exported Prometheus metrics (or Grafana data export)
- Alert history from PagerDuty / Slack
- Sample SIEM events from Splunk/Elastic

#### CC7.4 — Response to identified security incidents

| Control | Implementation | Evidence location |
|---------|---------------|-------------------|
| Evidence Vault bundles | Per-session SHA-256 signed JSON — timeline, tool events, compliance score | `warden-evidence/bundles/<session_id>.json` (MinIO) |
| Cryptographic audit trail | SQLite hash-chain; `entry_hash = SHA-256(prev_hash + payload)` | `data/audit_trail.db` |
| Evolution Engine | Automatically generates new detection rules from blocked attacks | `warden/brain/evolve.py`, `data/dynamic_rules.json` |
| Kill-switch | `DELETE /api/agent/session/<id>` immediately revokes agent session | `AgentMonitor.revoke_session()` |
| Self-Healing corpus | Canary examples monitored; automatic rollback on drift detection | `warden/brain/poison.py` |

**How to retrieve evidence for a specific incident:**

```bash
# 1. Get all audit trail entries for a time window
sqlite3 data/audit_trail.db \
  "SELECT * FROM audit_trail WHERE ts > '2026-01-01' ORDER BY ts;"

# 2. Verify the audit trail hash-chain is intact
curl -s http://localhost:8001/admin/audit/verify | jq .

# 3. Retrieve a specific Evidence Vault bundle from MinIO
mc get local/warden-evidence/bundles/<session_id>.json

# 4. Verify bundle integrity
python3 -c "
import json
from warden.compliance.bundler import EvidenceBundler
bundle = json.load(open('bundle.json'))
print('VALID:', EvidenceBundler.verify_bundle(bundle))
"

# 5. Export GDPR-safe log entries for a specific request
curl http://localhost:8001/gdpr/export?request_id=<id>
```

---

### CC8 — Change Management

#### CC8.1 — Authorization and approval for changes

| Control | Implementation | Evidence location |
|---------|---------------|-------------------|
| CI/CD pipeline | GitHub Actions: test matrix (3.11/3.12), lint, Docker smoke | `.github/workflows/ci.yml` |
| Coverage gate | ≥ 75% required (`--cov-fail-under=75`) | CI job logs |
| Mutation testing | mutmut on `secret_redactor.py` + `semantic_guard.py` | CI job logs |
| Evolution Engine corpus protection | New rules require poison detection pass before hot-reload | `warden/brain/evolve.py` → `_is_poison()` |
| Dynamic rules signed | `dynamic_rules.json` written atomically; content verified by CorpusHealthMonitor | `data/dynamic_rules.json` |

**Evidence to provide auditors:**
- GitHub Actions run history (CI pass/fail log for audit period)
- `git log --format="%H %ae %ai %s"` for all commits in the audit period
- Pull request history showing review approvals

---

### A1 — Availability

#### A1.2 — System availability monitoring and notification

| Control | Implementation | Status |
|---------|---------------|--------|
| Health endpoint | `GET /health` — checks Redis + model load | Live |
| Availability SLO alert | Grafana rule fires when success rate < 99.9% over 1h | `warden_alerts.yml` rule `warden-availability-slo` |
| Circuit breaker | Fail-open strategy (configurable `WARDEN_FAIL_STRATEGY`) | `warden/circuit_breaker.py` |
| Resource limits | Docker `deploy.resources.limits` (1.5 CPU, 1800MB) | `docker-compose.yml` |
| Redis AOF persistence | `--appendonly yes --appendfsync everysec` prevents state loss | `docker-compose.yml` → redis service |

**Current gap (for remediation before audit):**
- Formal SLA document with % uptime commitment needs to be drafted
- Uptime monitoring via external service (e.g., UptimeRobot, Better Uptime) should be enabled and evidence retained

---

### PI — Processing Integrity

#### PI1 — Processing is complete, valid, accurate, timely, and authorized

| Control | Implementation | Evidence location |
|---------|---------------|-------------------|
| Content hash cache | Identical requests return identical decisions (deterministic) | `warden/cache.py` |
| Pipeline timeout | `PIPELINE_TIMEOUT_MS` with configurable fail strategy | `main.py` → `_run_filter_pipeline()` |
| Per-stage timing | `processing_ms` in every FilterResponse | Response JSON |
| Batch processing | `POST /filter/batch` processes up to 50 items consistently | `main.py` → `/filter/batch` |
| Evidence bundle compliance score | `compliance_score = verified_events / total_events` | Evidence Vault bundle |

---

## Audit Package: What to Provide

For a SOC 2 Type II audit covering a 6-12 month period:

| Evidence item | How to collect | Format |
|--------------|---------------|--------|
| Filter decision logs | `cat data/logs.json` or MinIO download | NDJSON |
| Audit trail | `sqlite3 data/audit_trail.db .dump` | SQL |
| Audit trail verification | `GET /admin/audit/verify` | JSON |
| Evidence Vault bundles (sample) | MinIO `mc ls local/warden-evidence/bundles/` | JSON |
| Prometheus metrics export | Grafana → Export → CSV / JSON | CSV/JSON |
| Grafana alert history | Grafana → Alerting → History (export) | JSON |
| CI run history | GitHub Actions → workflow runs | HTML/JSON |
| Dependency manifest | `pip list --format=json` from running container | JSON |
| Docker image digests | `docker images --digests` | Text |

---

## Remediation Backlog (open items)

| Item | Priority | Target |
|------|---------|--------|
| Formal SLA document (99.9% uptime commitment) | High | v2.3 |
| External uptime monitoring with evidence retention | High | v2.3 |
| Causal Arbiter CPT calibration (MLE from prod data) | Medium | v2.3 |
| `mlock()` for PII vault key memory pages | Medium | v2.3 |
| SOC 2 Type II certification (external auditor engagement) | High | Q3 2026 |

---

*Shadow Warden AI · soc2-evidence.md · v1.0 · 2026-03-26*
