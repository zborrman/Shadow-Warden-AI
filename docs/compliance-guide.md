# Shadow Warden AI — Compliance Guide

**Audience:** Compliance officers, CISOs, DPOs, auditors
**Tier required:** Pro+ (compliance posture); Enterprise (ISO 27001 full matrix)

---

## Overview

Shadow Warden's Real-time Compliance Dashboard (CP-30) continuously evaluates
your AI deployment against 4 major frameworks.

<!-- SCREENSHOT: portal/src/app/compliance/page.tsx — Compliance Dashboard -->
<!-- TODO: capture and save as docs/images/compliance-dashboard.png -->
<!-- Figure 5: Compliance Dashboard showing SVG score ring (overall: 84/B), per-framework bars (GDPR 91, SOC2 80, ISO27001 78, HIPAA 87), and top gaps with one-click remediation buttons --> Every control check runs on a
timer, publishes results to a Redis channel, and streams updates to connected
dashboards via WebSocket — so your posture score is always current, not a
point-in-time snapshot.

---

## 1. Supported frameworks

| Framework | Controls | Key focus |
|---|---|---|
| **GDPR** | 6 | Data minimisation, consent, Art. 17 purge, DPIA, retention, logging |
| **SOC 2 Type II** | 5 | Availability, confidentiality, processing integrity, security, privacy |
| **ISO 27001:2022** | 4 (posture); 93 (full matrix, Enterprise) | 4 themes: Organisational/People/Physical/Technological |
| **HIPAA** | 4 | PHI protection, audit controls, access management, transmission security |

Total: **19 live controls** evaluated continuously.

---

## 2. Real-time posture dashboard

### Portal (recommended)

Navigate to **Portal → Compliance** — the self-service page shows:
- Overall score (0–100) with letter grade (A/B/C/D/F)
- Score ring per framework
- Gap list sorted by severity
- One-click remediation for auto-fixable gaps

### SOC Dashboard

`https://dash.shadow-warden-ai.com/compliance` — SVG score ring, bar chart,
168-hour timeline, evidence download section.

### Streamlit analytics

`http://your-host:8501` → page **21 Compliance Dashboard** — 5 tabs:
Posture, Timeline, Standards, Evidence, Real-time.

### WebSocket live feed

```javascript
const ws = new WebSocket("wss://api.shadow-warden-ai.com/compliance/ws?tenant_id=acme");
ws.onmessage = (event) => {
  const { overall_score, grade, frameworks } = JSON.parse(event.data);
  console.log(`Score: ${overall_score} (${grade})`);
};
```

Push interval: 30 seconds. Cache TTL: 300 seconds (configurable via `COMPLIANCE_CACHE_TTL`).

---

## 3. API

### Get current posture

```bash
curl "https://api.shadow-warden-ai.com/compliance/posture?tenant_id=acme" \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "X-Tenant-Tier: pro"
```

```json
{
  "tenant_id": "acme",
  "overall_score": 84,
  "grade": "B",
  "frameworks": {
    "gdpr": 91, "soc2": 80, "iso27001": 78, "hipaa": 87
  },
  "gaps": [
    {
      "control_id": "SOC2-CC6.3",
      "framework": "soc2",
      "severity": "HIGH",
      "description": "No MFA enforced on admin portal",
      "remediation": "Enable FIDO2 or TOTP in Settings → Auth"
    }
  ],
  "computed_at": "2026-06-13T10:00:00Z"
}
```

### Get gaps only

```bash
curl "https://api.shadow-warden-ai.com/compliance/posture/gaps?tenant_id=acme" \
  -H "X-API-Key: $WARDEN_API_KEY" -H "X-Tenant-Tier: pro"
```

### Per-framework score

```bash
curl "https://api.shadow-warden-ai.com/compliance/posture/gdpr?tenant_id=acme" \
  -H "X-API-Key: $WARDEN_API_KEY" -H "X-Tenant-Tier: pro"
```

### Force recalculate

Use after remediating a gap to get an immediate updated score:

```bash
curl -s -X POST "https://api.shadow-warden-ai.com/compliance/posture/recalculate" \
  -H "X-API-Key: $WARDEN_API_KEY" -H "X-Tenant-Tier: pro" \
  -d '{"tenant_id": "acme"}'
```

### Score history (168-hour ring buffer)

```bash
curl "https://api.shadow-warden-ai.com/compliance/history?tenant_id=acme" \
  -H "X-API-Key: $WARDEN_API_KEY" -H "X-Tenant-Tier: pro"
```

---

## 4. Understanding gaps and remediation

Each gap has a severity: `LOW | MEDIUM | HIGH | CRITICAL`.

Common gaps and how to fix them:

| Gap | Severity | Fix |
|---|---|---|
| GDPR: content logged | CRITICAL | Ensure `LOGS_PATH` only stores metadata; check `event_logger.py` |
| GDPR: no DPIA | HIGH | Complete `docs/dpia.md`; link via Settings |
| SOC2: no MFA | HIGH | Enable FIDO2 in Portal → Settings → Auth |
| SOC2: no audit log export | MEDIUM | Configure SIEM: `POST /siem/configure` |
| ISO27001: no key rotation | MEDIUM | Enable `sova_rotation_check` (02:00 UTC cron) |
| HIPAA: PHI in non-compliant jurisdiction | HIGH | Configure Sovereign AI pods to US/EU/UK/CA/CH only |

### SOVA auto-remediation

SOVA tools #51 and #52 let the AI operator remediate gaps autonomously:

```bash
curl -s -X POST https://api.shadow-warden-ai.com/agent/sova \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{"query": "Remediate all MEDIUM compliance gaps for tenant acme"}'
```

---

## 5. ISO 27001:2022 full control matrix (Enterprise)

93 controls across 4 themes. Browse in the Streamlit page **18 ISO27001** or via API:

```bash
curl "https://api.shadow-warden-ai.com/compliance/iso27001?tenant_id=acme" \
  -H "X-API-Key: $WARDEN_API_KEY" -H "X-Tenant-Tier: enterprise"
```

Status values: `Implemented | Partial | Delegated`.

---

## 6. SOC 2 Type II evidence collection

Shadow Warden pre-generates evidence artefacts for auditors:

```bash
curl "https://api.shadow-warden-ai.com/compliance/soc2/evidence" \
  -H "X-API-Key: $WARDEN_API_KEY"
```

See [soc2-evidence.md](soc2-evidence.md) for the full auditor collection guide.

---

## 7. Document Intelligence for compliance scanning

Scan uploaded documents (contracts, DPAs, policies) through the security
and compliance pipeline:

```bash
# Convert and scan a PDF
curl -s -X POST https://api.shadow-warden-ai.com/document-intel/convert \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{
    "file_base64": "'$(base64 -w0 contract.pdf)'",
    "filename": "contract.pdf",
    "tenant_id": "acme"
  }' | jq '.secrets_found, .data_class'
```

`data_class` values: `CLASSIFIED | PHI | PII | FINANCIAL | GENERAL`

Documents classified as `PHI` or `CLASSIFIED` are automatically tagged with
Sovereign Pod Tags and routed to compliant jurisdictions only.

---

## 8. GDPR operations

### Purge a subject's data (Art. 17)

```bash
# Purge all events before a timestamp
curl -s -X POST https://api.shadow-warden-ai.com/gdpr/purge \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -d '{"before_ts": "2026-01-01T00:00:00Z", "tenant_id": "acme"}'
```

### Retention cron

`sova_gdpr_retention` runs daily at 02:00 UTC, purging events older than the
configured retention window (`GDPR_RETENTION_DAYS`, default 90).

### DPIA

Full GDPR Art. 35 Data Protection Impact Assessment: [dpia.md](dpia.md).

---

## 9. Alerting on compliance drift

Configure Slack or PagerDuty to receive alerts when posture drops below a threshold:

```bash
# In .env
COMPLIANCE_ALERT_THRESHOLD=75    # alert if score drops below 75
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

Grafana alert rules are pre-provisioned in
`grafana/provisioning/alerting/warden_alerts.yml` — includes a compliance score
alert that fires if the score stays below threshold for 2 consecutive check windows.
