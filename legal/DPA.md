# Data Processing Agreement (DPA)

**Between:** Shadow Warden AI Ltd. ("**Data Processor**", "**we**", "**us**")
**And:** [Customer Legal Name] ("**Data Controller**", "**you**")

**Effective Date:** [DATE]
**Agreement Reference:** [CONTRACT-ID]

---

## 1. Definitions

| Term | Meaning |
|------|---------|
| **Personal Data** | Any information relating to an identified or identifiable natural person, as defined by GDPR Article 4(1). |
| **Processing** | Any operation on Personal Data, as defined by GDPR Article 4(2). |
| **Sub-processor** | Any third party engaged by Shadow Warden AI to assist with Processing. |
| **EEA** | European Economic Area. |
| **Standard Contractual Clauses (SCCs)** | The European Commission's standard contractual clauses for transfers of personal data to third countries (Decision 2021/914/EU). |

---

## 2. Scope and Purpose

2.1 This DPA governs Processing of Personal Data carried out by Shadow Warden AI on behalf of the Controller in connection with the Shadow Warden AI security gateway service ("**Service**").

2.2 **Subject matter:** Filtering of AI prompts and documents for PII, secrets, and jailbreak attempts prior to transmission to third-party AI models.

2.3 **Nature of Processing:** Automated real-time analysis and redaction.

2.4 **Purpose:** Preventing accidental or malicious transmission of personal data to external AI services; protecting the Controller's data subjects and business assets.

2.5 **Duration:** For the term of the underlying Master Service Agreement, plus any statutory retention obligations.

2.6 **Categories of data subjects:** Employees, contractors, customers, or other individuals whose data may appear in AI prompts submitted by the Controller.

2.7 **Categories of Personal Data:** Any personal data appearing in prompt text, including but not limited to: names, email addresses, phone numbers, identification numbers, financial data, health data.

---

## 3. Shadow Warden AI's Obligations as Processor

Shadow Warden AI shall:

3.1 **Process only on documented instructions** from the Controller. If Shadow Warden AI believes an instruction infringes applicable law, it will promptly inform the Controller.

3.2 **Zero-content logging.** Shadow Warden AI does not log, store, or retain the *content* of any prompt or document submitted to the Service. Only metadata is recorded: content type, character length, detected risk level, processing latency, and tenant identifier. This is a hard architectural guarantee enforced at the code level.

3.3 **Confidentiality.** Ensure that all personnel authorised to process Personal Data are subject to enforceable confidentiality obligations.

3.4 **Security measures.** Implement and maintain the technical and organisational security measures described in Annex II (Security Measures).

3.5 **Sub-processors.** Not engage a new Sub-processor without prior specific or general written authorisation of the Controller. Current Sub-processors are listed in Annex III.

3.6 **Data subject rights.** Assist the Controller in responding to data subject rights requests (access, erasure, restriction, portability) insofar as they relate to data processed through the Service. Given the zero-content logging policy, Shadow Warden AI holds no content data to produce; metadata logs can be purged via the `POST /gdpr/purge` API endpoint.

3.7 **DPIA assistance.** Assist the Controller with Data Protection Impact Assessments (DPIAs) where required.

3.8 **Breach notification.** Notify the Controller of a Personal Data breach without undue delay and no later than **48 hours** after becoming aware of it, providing information required under GDPR Article 33(3) to the extent available.

3.9 **Deletion or return.** Upon termination, delete or return all Personal Data (if any) and certify deletion in writing within 30 days.

3.10 **Audit rights.** Make available all information necessary to demonstrate compliance with this DPA, and allow for and contribute to audits conducted by the Controller or a mandated auditor (with reasonable notice, subject to confidentiality obligations).

---

## 4. Controller's Obligations

4.1 The Controller warrants that it has a valid legal basis for submitting Personal Data to the Service.

4.2 The Controller is responsible for ensuring data subjects have been provided appropriate privacy notices.

4.3 The Controller shall provide Shadow Warden AI with clear and lawful Processing instructions.

---

## 5. International Transfers

5.1 Shadow Warden AI processes data within the EU/EEA by default. Where data is transferred outside the EEA, such transfers are governed by:
- EU Standard Contractual Clauses (Module 2: Controller to Processor), incorporated herein by reference; or
- Another transfer mechanism permitted under GDPR Chapter V.

5.2 The Controller may request a completed SCCs addendum by contacting privacy@shadowwarden.ai.

---

## 6. Approved Sub-processors

The Controller grants general authorisation for Shadow Warden AI to use the Sub-processors listed in **Annex III**. Shadow Warden AI will provide 30 days' prior written notice of any addition or replacement, giving the Controller the opportunity to object.

---

## 7. Liability

Each party's liability under this DPA is subject to the limitations set out in the Master Service Agreement. Nothing in this DPA limits either party's liability to data subjects or supervisory authorities.

---

## 8. Governing Law

This DPA is governed by the laws of [England & Wales / [Customer's jurisdiction — to be agreed]], without regard to conflict-of-law principles.

---

## Annex I — Processing Details

| Field | Detail |
|-------|--------|
| Subject matter | AI prompt security filtering |
| Duration | Per MSA term |
| Nature | Automated analysis, redaction, risk scoring |
| Purpose | Prevent PII/secrets leakage to external AI models |
| Data subjects | Controller's employees, contractors, end-users |
| Personal Data categories | Text data appearing in AI prompts (PII, as submitted) |
| Special category data | Not intentionally processed; if present, flagged and blocked |

---

## Annex II — Technical and Organisational Security Measures

| Control | Implementation |
|---------|---------------|
| **Encryption in transit** | TLS 1.3 for all API endpoints |
| **Encryption at rest** | AES-256 for all persistent storage |
| **Zero-content logging** | Enforced architecturally — content never written to disk |
| **Access control** | Per-tenant API keys with SHA-256 hash lookup; RBAC on infrastructure |
| **Authentication** | Multi-factor authentication required for all administrative access |
| **Network security** | WAF, rate limiting (60 req/min/tenant), DDoS protection |
| **Vulnerability management** | Automated dependency scanning (Dependabot); quarterly penetration testing |
| **Incident response** | Documented runbook; 24-hour on-call rotation; 48-hour breach notification SLA |
| **Audit logging** | All administrative actions logged with actor identity and timestamp |
| **Data minimisation** | Only metadata (not content) is retained; GDPR `purge` API available |
| **Business continuity** | Multi-region failover; RTO < 4h; RPO < 1h |

---

## Annex III — Approved Sub-processors

| Sub-processor | Location | Purpose | Safeguard |
|---------------|----------|---------|-----------|
| Hetzner Online GmbH | Germany (EU) | Cloud infrastructure (VPS hosting) | GDPR Art. 28 DPA |
| Cloudflare, Inc. | US (EU data centres) | CDN, WAF, DDoS protection | SCCs + EU-U.S. DPF |
| Stripe, Inc. | US | Billing and subscription management | SCCs + EU-U.S. DPF |
| Anthropic, PBC | US | Evolution Engine (rule generation only — **no customer content**) | SCCs; zero-content policy |

> **Note:** Anthropic receives only synthetic threat examples generated by the Evolution Engine — never actual customer prompts or documents.

---

*Shadow Warden AI Ltd.*
*privacy@shadowwarden.ai*
*Version 1.0 — March 2026*
