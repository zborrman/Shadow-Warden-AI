# Shadow Warden AI — SOC 2 Type II Evidence Guide

**Version:** 1.1 · **Date:** 2026-04-10
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

## Remediation Log

| Item | Status | Closed | Notes |
|------|--------|--------|-------|
| Formal SLA document (99.9% uptime commitment) | **Done** | 2026-04-10 | `docs/sla.md` v1.0 — Pro 99.9%, Enterprise 99.95%, credits table, maintenance windows |
| External uptime monitoring with evidence retention | **Done** | 2026-04-10 | UptimeRobot config + monthly MinIO export documented in `docs/sla.md §6` |
| Causal Arbiter CPT calibration (MLE from prod data) | **Done** | 2026-04-10 | `calibrate_from_logs()` in `warden/causal_arbiter.py` — MLE on obfusc/block rates at startup |
| `mlock()` for PII vault key memory pages | **Done** | 2026-04-10 | `_try_mlock()` in `warden/masking/engine.py` — Fernet + HMAC keys locked via `VirtualLock`/`mlock(2)` |
| SOC 2 Type II certification (external auditor engagement) | Open | — | Target Q3 2026 |

---

---

## Field audit — `soc2_collector.py` reads a log that does not exist (2026-08-09)

`warden/compliance/soc2_collector.py` reads 17 fields off journal entries and
**15 of them have never been written**. `timestamp` decides the outcome:
`_iter_log_window()` filters on it, so it yields nothing and every control in
every TSC section reports zero. #307 made the bundle declare that
(`evidence_status`); this is the audit of what it would take to make it true.

**The finding is not "the journal is missing fields".** It is that the collector
was written against a **structured security-event log** — one line per notable
event, carrying `event_type`, `stage`, `status`, `blocked`, `risk_score`,
`agent_id` — and pointed at `logs.json`, which is the **per-request decision
journal**: one line per request, metadata only. Different logs, different
shapes. `secrets_redacted` is the tell: it genuinely exists, as an application
log line at `main.py:2064` (`log.warning(json.dumps({"event":
"secrets_redacted", ...}))`), just not in the file the collector opens.

### Per field

| Field | Source today | Verdict |
|---|---|---|
| `timestamp` | `ts` in the journal | **rename** |
| `blocked` | `not allowed` | **derive** |
| `action` | `allowed` | **derive** |
| `secrets_redacted` | `secrets_found` (list) | **derive** |
| `redacted_count` | `len(secrets_found)` | **derive** |
| `risk_score` | `semantic_score`, recorded as of #308; or `risk_level` | **available now** |
| `agent_id` | `warden/agent/*` — not on the `/filter` path | different source |
| `event_type` | `agent_monitor.py` | different source |
| `stage` | nothing writes it as a log field | different source |
| `status` | unclear; no producer found | needs a definition first |
| `pqc_signed` | **nowhere in the codebase** | feature must emit it first |
| `pqc_verified` | **nowhere** | ” |
| `pqc_auth_failed` | **nowhere** | ” |
| `pqc_fail_reason` | **nowhere** | ” |
| `e2ee_activated` | **nowhere** | ” |

### What that means for the controls

Six fields are a rewrite of the collector against the journal it actually has —
mechanical, and it makes the Security, Availability, Processing-Integrity and
Privacy sections carry real numbers.

The five that exist **nowhere** are the uncomfortable half. They back
**CC6.7 Encryption in Transit** and the **C1 Confidentiality** section, and no
code anywhere emits them — so those controls have never had an evidence source,
in any run, since the collector was written. That is not a logging bug to fix;
it is a control whose evidence has to be produced before it can be collected.
Until then the honest state is the one #307 now reports: unavailable.

### Recommended order

1. Rewrite the collector against the real journal for the six derivable
   fields — roughly a day, and it retires `evidence_status: unavailable` for
   four of five TSC sections.
2. ✅ **Decided (2026-08-10).** Neither — the third option was the right one.
   The controls are **real**: hybrid Ed25519+ML-DSA-65 is implemented and
   build-asserted in the image, TLS is Caddy + Authenticated Origin Pulls +
   origin lockdown. Withdrawing the claims would understate the system.
   Emitting the telemetry is a feature, not a fix.

   What was wrong is the *presentation*: a `0` beside a control named "PQC key
   operations" reads as **checked, none occurred**, which claims more than the
   truth. Each such figure now carries an explicit evidence label —
   `not_instrumented` vs `counted` — that tracks the data rather than being
   hardcoded, plus a note naming the real evidence
   (`warden/crypto/pqc.py`, `pqc_selfcheck()` in `GET /health/pipeline`).
   `encryption_in_transit` is labelled `configuration_not_event_stream`: it is
   evidenced by configuration, and never had a per-request event to count.

   Emitting real `pqc_*` / `e2ee_*` telemetry remains open, and is now an
   enhancement rather than a correctness gap.
3. `agent_id` / `event_type` / `stage` need a second reader over the agent
   subsystem's own records, not more fields on `/filter`.

---

*Shadow Warden AI · soc2-evidence.md · v1.2 · 2026-08-09*
