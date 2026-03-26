# Shadow Warden AI — Data Protection Impact Assessment (DPIA)

**Document type:** DPIA (GDPR Art. 35)
**Version:** 1.0 · **Date:** 2026-03-26
**Prepared by:** Data Protection Officer
**Review cycle:** Annual or upon significant system change

---

## 1. Overview and Necessity of DPIA

A DPIA is required under GDPR Article 35 when processing is "likely to result in a high risk to the rights and freedoms of natural persons." Shadow Warden AI performs systematic monitoring of AI request patterns, which qualifies as large-scale processing of user behaviour data under Art. 35(3)(b).

**Conclusion: DPIA is mandatory.** This document fulfills that requirement.

---

## 2. System Description

**System name:** Shadow Warden AI
**Version:** 2.2
**Purpose:** AI security gateway — filters jailbreak attempts, strips secrets/PII, and generates compliance evidence for AI-mediated interactions.

**Data controller:** The operator deploying Shadow Warden AI (customer)
**Data processor:** Shadow Warden AI software (on-prem — no data leaves the operator's infrastructure)
**Sub-processors:** None (self-hosted; MinIO runs on operator's infrastructure)

**Legal basis for processing:** Art. 6(1)(f) — Legitimate interests of the controller in protecting AI systems from abuse, ensuring regulatory compliance, and preventing data exfiltration.

---

## 3. Data Inventory

### 3.1 Data Processed

| Data element | Source | Retention | Lawful basis |
|-------------|--------|-----------|--------------|
| Request metadata (length, timing, flags) | Filter pipeline | 30 days (configurable) | Art. 6(1)(f) |
| Risk level and decision (ALLOW/BLOCK) | Filter pipeline | 30 days | Art. 6(1)(f) |
| Secret/PII types detected (not values) | SecretRedactor | 30 days | Art. 6(1)(f) |
| Pseudonymised entity key (SHA-256[:16]) | ERS module | TTL = sliding window (1h) in Redis | Art. 6(1)(f) |
| Agent session metadata (tool names, compliance score) | AgentMonitor | Per-session, expires on bundle export | Art. 6(1)(f) |
| Encrypted PII tokens (Fernet vault) | MaskingEngine | Ephemeral (process lifetime only) | Art. 6(1)(b)/(f) |
| Evidence bundles (pseudonymised metadata) | EvidenceBundler | Operator-defined; MinIO lifecycle policy | Art. 6(1)(c)/(f) |

### 3.2 Data NOT Processed (by design)

- **Raw prompt / response content** — never logged, never stored, never shipped to any service
- **Decrypted PII values** — vault key is ephemeral, never persisted to disk
- **IP addresses** — only SHA-256[:16] of (tenant+IP) is stored (irreversible pseudonymisation)
- **User identifiers** — not collected; entity key cannot be reversed to identify a natural person without the original (tenant+IP) pair

---

## 4. Risk Assessment

### 4.1 Identified Risks to Data Subjects

| Risk ID | Risk | Likelihood | Severity | Inherent Risk |
|---------|------|-----------|---------|---------------|
| R1 | Metadata aggregation → re-identification via timing correlation | Low | Medium | Low |
| R2 | Evidence bundle exposure to unauthorized party | Low | High | Medium |
| R3 | PII vault key exposed in process memory (core dump) | Very Low | High | Low |
| R4 | Shadow ban affects legitimate users with similar IP patterns | Low | Medium | Low |
| R5 | MinIO bucket publicly accessible due to misconfiguration | Low | High | Medium |
| R6 | GDPR erasure request not fulfilled within 30-day window | Low | High | Medium |

### 4.2 Risk Mitigations

| Risk ID | Mitigation | Residual Risk |
|---------|-----------|---------------|
| R1 | Entity key = SHA-256[:16] — irreversible without original input; no IP stored raw | Very Low |
| R2 | Bundles contain only pseudonymised metadata; SHA-256 signed; MinIO buckets private | Low |
| R3 | Fernet key is process-scoped; system-level memory protection recommended in hardened prod | Low |
| R4 | MIN_REQUESTS=5 before scoring activates; `reset()` API for false-positive clearance | Low |
| R5 | `mc anonymous set none` applied by minio-init sidecar on first start; document in ops runbook | Low |
| R6 | `/gdpr/purge` endpoint provides automated erasure; 30-day default retention with configurable TTL | Low |

---

## 5. Data Subject Rights Implementation

| Right (GDPR) | Article | Implementation | Endpoint |
|-------------|---------|---------------|---------|
| Right to access | Art. 15 | Returns all metadata for a request_id | `GET /gdpr/export?request_id=<id>` |
| Right to erasure | Art. 17 | Removes all log entries for a request_id or before a date | `DELETE /gdpr/purge` |
| Right to data portability | Art. 20 | NDJSON format is machine-readable and portable | `GET /gdpr/export` |
| Right to object | Art. 21 | Operator can disable processing per tenant via API key revocation | Auth module |
| Right to restriction | Art. 18 | Operator can delete entity ERS data via `DELETE /api/entity/{key}` | Admin API |

**GDPR Art. 17 erasure SLA:** 30 days maximum. Technical capability exists for immediate erasure via `/gdpr/purge`.

---

## 6. Data Transfers

**No data transfers to third countries occur by default.**

Shadow Warden AI is fully self-hosted. All data remains within the operator's infrastructure:
- Processing: on the operator's server
- Storage: MinIO on the operator's server or colocation
- Evolution Engine: calls Anthropic API with **attack pattern representations only** (not raw content) when `ANTHROPIC_API_KEY` is configured

**Anthropic API data transfer note:** When `ANTHROPIC_API_KEY` is set and the Evolution Engine is active, a representation of a blocked attack pattern is sent to Anthropic's API (US-based) for rule generation. This representation contains no user PII, no prompt content, and no personally identifiable information — only the type of threat detected and a synthesized example. Operators in the EU should evaluate whether an SCCs-covered DPA with Anthropic is required under their specific processing context.

---

## 7. Consultation and Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| DPO | [To be filled by operator] | [Date] | |
| CISO | [To be filled by operator] | [Date] | |
| Legal counsel | [To be filled by operator] | [Date] | |

**Prior consultation with supervisory authority required:** No — residual risks are Low after mitigations; no Art. 36 consultation threshold met.

---

## 8. Review Schedule

This DPIA must be reviewed:
- Annually on the anniversary of initial deployment
- Upon any significant change to the system (new processing modules, new data elements)
- Upon a security incident affecting personal data
- When a new country or jurisdiction deploys the system

---

*Shadow Warden AI · DPIA v1.0 · 2026-03-26*
*This document is prepared under GDPR Article 35. It should be maintained by the appointed DPO of the deploying organization.*
