# Record of Processing Activities (RoPA)

**Organisation:** Shadow Warden AI Ltd.
**Data Protection Contact:** privacy@shadowwarden.ai
**GDPR Article 30 Reference:** Article 30(1) — Record maintained by Controller; Article 30(2) — Record maintained by Processor
**Last Updated:** March 2026
**Review Frequency:** Annually or upon material change

---

## Overview

Shadow Warden AI Ltd. operates as both:
- **Data Controller** — for personal data of its own employees, contractors, and prospective/existing customers (sales, billing, support).
- **Data Processor** — on behalf of customer organisations, for personal data that may appear in AI prompts submitted to the Shadow Warden AI security gateway.

---

## Processing Activity 1 — AI Prompt Security Filtering (Processor Role)

| Field | Detail |
|-------|--------|
| **Activity name** | Real-time AI prompt filtering for PII, secrets, and jailbreak detection |
| **Role** | Data Processor (acting on Controller's instructions) |
| **Controller** | Customer organisation (per individual DPA) |
| **Purpose** | Prevent accidental/malicious transmission of personal data to third-party AI models |
| **Legal basis (Controller's)** | Legitimate interests (GDPR Art. 6(1)(f)) — protecting business data and data subjects from AI data leakage |
| **Data subjects** | Controller's employees, contractors, end-users whose data may appear in submitted prompts |
| **Personal Data categories** | Any text data appearing in AI prompts: may include names, email addresses, phone numbers, ID numbers, financial data |
| **Special category data** | Not intentionally processed; if detected, flagged and blocked; not stored |
| **Recipients** | None — data is analysed locally and not forwarded to third parties (except where Controller explicitly routes approved content to their AI provider) |
| **Retention** | **Zero content retention** — prompt content is never written to disk or logs. Metadata (tenant ID, risk level, content length, timestamps) retained for [90 days] then purged. |
| **International transfers** | None for content. Metadata stored in EU (Hetzner, Germany). Where Sub-processors outside EEA are involved, SCCs apply (see DPA Annex III). |
| **Security measures** | See DPA Annex II — TLS 1.3, zero-content logging, rate limiting, access controls |
| **Automated decision-making** | Yes — automated risk scoring and block/allow decisions. Controllers retain the right to audit decisions via request logs. |
| **DPIA required?** | Recommended for Customers deploying in high-risk sectors (healthcare, finance). Shadow Warden AI provides DPIA assistance upon request. |

---

## Processing Activity 2 — Customer Account Management (Controller Role)

| Field | Detail |
|-------|--------|
| **Activity name** | Customer onboarding, account management, billing |
| **Role** | Data Controller |
| **Purpose** | Providing the Shadow Warden AI service; invoicing; support |
| **Legal basis** | Contract (Art. 6(1)(b)); Legal obligation (Art. 6(1)(c)) for tax/accounting records |
| **Data subjects** | Customer organisation contacts (procurement, IT, legal, billing) |
| **Personal Data categories** | Name, business email, phone, job title, billing address, payment method (tokenised — held by Stripe) |
| **Recipients** | Stripe Inc. (billing); Hetzner Online GmbH (hosting); internal staff on need-to-know basis |
| **Retention** | Account data: duration of contract + 3 years. Invoice records: 7 years (legal obligation). |
| **International transfers** | Stripe (US) — SCCs + EU-U.S. DPF |
| **Security measures** | Encrypted database; MFA for admin access; RBAC |
| **DPIA required?** | No — standard B2B processing, no high-risk indicators |

---

## Processing Activity 3 — Security Telemetry / Threat Intelligence (Controller Role)

| Field | Detail |
|-------|--------|
| **Activity name** | Aggregate threat intelligence and product analytics |
| **Role** | Data Controller |
| **Purpose** | Improving detection accuracy; generating aggregated threat reports for customers |
| **Legal basis** | Legitimate interests (Art. 6(1)(f)) — product improvement and security research |
| **Data subjects** | Indirectly — no direct data subjects (fully anonymised/aggregated statistics only) |
| **Personal Data categories** | None — all statistics are aggregated across tenants with no linkage to individuals |
| **Retention** | Indefinite (anonymised aggregate data poses no personal data risk) |
| **Recipients** | None external |
| **Security measures** | Aggregate-only pipeline; no reverse-engineering of individual records possible |
| **DPIA required?** | No — anonymised data is outside GDPR scope |

---

## Processing Activity 4 — Employee and HR Data (Controller Role)

| Field | Detail |
|-------|--------|
| **Activity name** | Employment, payroll, access management |
| **Role** | Data Controller |
| **Purpose** | Employment contract fulfilment; payroll; equipment and access provisioning |
| **Legal basis** | Contract (Art. 6(1)(b)); Legal obligation (Art. 6(1)(c)) |
| **Data subjects** | Employees, contractors |
| **Personal Data categories** | Name, address, national ID / tax number, bank details, equipment assignments, access logs |
| **Recipients** | Payroll provider; HMRC / local tax authority; pension provider |
| **Retention** | Duration of employment + 6 years (UK statutory minimum) |
| **International transfers** | None intended |
| **Security measures** | HR system with RBAC; encrypted storage; MFA |
| **DPIA required?** | No — standard HR processing |

---

## Data Subject Rights — Contact and Process

| Right | How to exercise | Response time |
|-------|-----------------|---------------|
| Access (Art. 15) | Email privacy@shadowwarden.ai | 30 days |
| Rectification (Art. 16) | Email privacy@shadowwarden.ai | 30 days |
| Erasure (Art. 17) | Email privacy@shadowwarden.ai; or `POST /gdpr/purge` API | 30 days |
| Restriction (Art. 18) | Email privacy@shadowwarden.ai | 30 days |
| Portability (Art. 20) | Email privacy@shadowwarden.ai | 30 days |
| Object (Art. 21) | Email privacy@shadowwarden.ai | 30 days |
| Withdraw consent | N/A — no consent-based processing currently active | — |

> **Note on Processor role:** Where Shadow Warden AI processes data as a Processor, data subjects must direct requests to the relevant Controller (the organisation that submitted the data to Shadow Warden AI). Shadow Warden AI will assist Controllers in responding to such requests as required by the applicable DPA.

---

## Supervisory Authority

Shadow Warden AI Ltd. is registered with / reports to:
- **[UK]** Information Commissioner's Office (ICO) — Registration No.: [ICO-REG-NUMBER]
- **[EU]** [Lead Supervisory Authority — to be determined based on main establishment]

---

*Maintained by: [DPO / Data Protection Contact]*
*Next review: March 2027*
