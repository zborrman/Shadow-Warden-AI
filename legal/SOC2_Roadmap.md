# SOC 2 Type II Readiness Roadmap

**Organisation:** Shadow Warden AI Ltd.
**Target:** SOC 2 Type II — Trust Services Criteria: Security (CC), Availability (A1), Confidentiality (C)
**Target Audit Window:** 6 months (observation period)
**Target Audit Completion:** Q4 2026

---

## Executive Summary

SOC 2 Type II demonstrates to enterprise buyers that Shadow Warden AI's controls are not just documented (Type I) but have operated effectively over a sustained period. For MSP and financial-sector customers, a SOC 2 report is often a hard prerequisite for vendor approval.

This roadmap maps Shadow Warden AI's existing technical controls to the AICPA Trust Services Criteria (TSC), identifies gaps, and schedules remediation to achieve a clean Type II opinion.

---

## Current Control Posture (Architecture → TSC Mapping)

| Existing Control | TSC Reference | Status |
|-----------------|---------------|--------|
| TLS 1.3 on all endpoints | CC6.1 — Logical access controls | ✅ Implemented |
| Per-tenant API key auth (SHA-256 hash) | CC6.1 — Authentication | ✅ Implemented |
| Rate limiting (60 req/min/tenant, Redis-backed) | CC6.6 — Network controls | ✅ Implemented |
| Zero-content logging (metadata only) | C1.1 — Confidentiality commitments | ✅ Implemented |
| Redis content-hash cache with TTL | CC6.7 — Transmission controls | ✅ Implemented |
| GDPR purge API (`POST /gdpr/purge`) | C1.2 — Disposal of confidential data | ✅ Implemented |
| Atomic file writes (tempfile + os.replace) | A1.2 — System availability | ✅ Implemented |
| Docker healthchecks + resource limits | A1.1 — Capacity management | ✅ Implemented |
| Prometheus + Grafana P99 latency alerts | A1.2 — Performance monitoring | ✅ Implemented |
| GitHub Actions CI pipeline (lint + test + Docker smoke) | CC7.1 — Change management | ✅ Implemented |
| Pre-commit hooks (bandit, detect-secrets) | CC8.1 — Change management | ✅ Implemented |
| `.env.example` with documented secrets | CC6.2 — Credential management | ✅ Implemented |
| Corpus poisoning protection (growth cap, vetting) | CC7.2 — Threat detection | ✅ Implemented |
| Slack + PagerDuty alerting on HIGH/BLOCK | CC7.3 — Incident response | ✅ Implemented |

---

## Gap Analysis and Remediation Plan

### Phase 1 — Governance Foundation (Months 1–2)

| Gap | TSC | Action | Owner | Target |
|-----|-----|--------|-------|--------|
| No formal Information Security Policy | CC1.1 | Draft and approve ISP covering access, acceptable use, incident response | CEO/CTO | Month 1 |
| No documented Risk Assessment | CC3.1 | Complete annual risk register; score likelihood × impact | CTO | Month 1 |
| No vendor management programme | CC9.1 | Document sub-processor risk assessments (Hetzner, Stripe, Anthropic, Cloudflare) | Ops | Month 2 |
| No employee security training records | CC1.4 | Implement annual security awareness training; track completion | HR | Month 2 |
| No formal onboarding/offboarding checklist | CC6.2 | Document access provisioning and de-provisioning process | HR/IT | Month 2 |
| No Business Continuity Plan (BCP) | A1.3 | Draft BCP covering RTO/RPO targets, failover procedures, comms plan | CTO | Month 2 |

### Phase 2 — Technical Controls Hardening (Months 2–4)

| Gap | TSC | Action | Owner | Target |
|-----|-----|--------|-------|--------|
| No formal vulnerability management schedule | CC7.1 | Formalise quarterly pen test schedule; integrate Dependabot alerts into sprint | Eng | Month 2 |
| No immutable audit log for admin actions | CC6.3 | Implement append-only admin audit log (separate from application logs) | Eng | Month 3 |
| No multi-factor authentication enforcement on infrastructure | CC6.1 | Enforce MFA for GitHub, cloud provider, DNS, monitoring dashboards | Ops | Month 2 |
| No secrets rotation schedule | CC6.2 | Implement 90-day API key rotation policy; document in runbook | Ops | Month 3 |
| No documented backup and restore testing | A1.3 | Schedule and document quarterly backup restore tests | Ops | Month 3 |
| No network segmentation between services | CC6.6 | Implement Docker network segregation (warden ↔ postgres only; not exposed) | Eng | Month 3 |
| `/docs` endpoint exposure in production | CC6.1 | Enforce `DOCS_PASSWORD` env var in production deployment checklist | Ops | Month 2 ✅ |
| No intrusion detection / anomaly alerting | CC7.2 | Configure Grafana alert on 5xx spike > 1%; add login failure alerts | Eng | Month 4 |

### Phase 3 — Evidence Collection and Audit Preparation (Months 4–6)

| Activity | TSC | Action | Owner | Target |
|----------|-----|--------|-------|--------|
| Select SOC 2 auditor | All | RFP to 2–3 AICPA-licensed CPA firms specialising in SaaS | CEO | Month 3 |
| Define audit scope and boundaries | All | Document in-scope systems (warden, analytics, postgres, redis, grafana) | CTO | Month 3 |
| Begin evidence collection | All | Compile: change logs, access reviews, incident records, training records | Ops | Months 4–6 |
| Access review | CC6.2 | Quarterly user access review with documented approval | HR/IT | Month 4 |
| Penetration test | CC7.1 | External pen test by qualified third party; remediate Critical/High findings | Sec | Month 4 |
| Type I readiness assessment | All | Internal mock audit against TSC; close identified gaps | CTO | Month 5 |
| Auditor fieldwork begins | All | 6-month observation period; provide evidence on request | All | Month 3 |
| Draft SOC 2 Type II report | All | Auditor produces report; management responses to exceptions | CEO | Month 9 |
| Final SOC 2 Type II opinion | All | Clean or qualified opinion issued | Auditor | Month 9 |

---

## Trust Services Criteria Coverage Target

| TSC | Criteria Name | Coverage Plan |
|-----|--------------|---------------|
| **CC1** | Control Environment | ISP, training, org structure |
| **CC2** | Communication | Policy docs, change comms, customer notifications |
| **CC3** | Risk Assessment | Annual risk register, DPIA for high-risk customers |
| **CC4** | Monitoring | Prometheus/Grafana, automated test coverage |
| **CC5** | Control Activities | CI pipeline, code review policy, Makefile automation |
| **CC6** | Logical Access | API key auth, MFA, RBAC, docs auth, key rotation |
| **CC7** | System Operations | Alerting, incident response, vulnerability management |
| **CC8** | Change Management | GitHub PRs, pre-commit hooks, CI gate |
| **CC9** | Risk Mitigation | Vendor management, sub-processor DPAs, insurance |
| **A1** | Availability | Health checks, resource limits, BCP, backup tests |
| **C1** | Confidentiality | Zero-content logging, TLS, GDPR purge API |

---

## Key Deliverables Checklist

- [ ] Information Security Policy (signed by CEO)
- [ ] Risk Register (updated annually)
- [ ] Business Continuity Plan (tested annually)
- [ ] Employee Security Training Programme (records kept ≥3 years)
- [ ] Vendor Risk Assessments (Hetzner, Stripe, Anthropic, Cloudflare)
- [ ] Access Provisioning / De-provisioning Runbook
- [ ] Quarterly Access Review Records
- [ ] Secrets Rotation Policy and Log
- [ ] Immutable Admin Audit Log
- [ ] Quarterly Backup Restore Test Records
- [ ] External Penetration Test Report + Remediation Evidence
- [ ] SOC 2 Auditor Engagement Letter
- [ ] 6-Month Evidence Package
- [ ] Draft SOC 2 Type II Report Review
- [ ] Final SOC 2 Type II Opinion Letter

---

## Estimated Budget

| Item | Estimated Cost |
|------|----------------|
| SOC 2 auditor (Type II) | $15,000 – $30,000 |
| Penetration test | $5,000 – $10,000 |
| Compliance tooling (Drata / Vanta / manual) | $3,000 – $12,000/yr |
| Legal (policy review, DPA templates) | $2,000 – $5,000 |
| **Total** | **~$25,000 – $57,000** |

> Using a compliance automation platform (Drata or Vanta) reduces evidence-collection overhead significantly and is recommended if headcount is constrained.

---

*Document Owner: CTO*
*Next Review: June 2026*
