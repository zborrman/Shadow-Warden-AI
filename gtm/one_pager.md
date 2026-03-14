# Shadow Warden AI
## Zero-Trust AI Security Gateway for Managed Service Providers

---

> *Your clients' teams are using AI tools today. You have no visibility into what they're sending — and neither do they. Shadow Warden changes that.*

---

## The Problem MSPs Can't Ignore

| Risk | What's Happening | Your Exposure |
|------|-----------------|---------------|
| **Data Exfiltration** | Technicians paste SSNs, API keys, network configs into ChatGPT | GDPR fines up to 4% of global turnover, client contract breach |
| **Jailbreak Attacks** | Adversaries manipulate AI tools to bypass safety controls | Unauthorized data access, liability for AI-generated harm |
| **Compliance Gap** | Clients ask "How do you control AI data handling?" | Lost RFPs, failed audits, churned enterprise accounts |
| **AI Supply Chain** | LLM outputs contain XSS, SQL injection, shell commands | Downstream application compromise from AI-generated code |

**Average cost of an AI-related data breach: $4.45M** *(IBM, 2024)*

---

## What Shadow Warden Does

Shadow Warden is a mandatory security filter that sits in front of every AI request — before content reaches any LLM API. It operates in under **40 milliseconds** with zero impact on user experience.

```
Employee / App
      │
      ▼
┌─────────────────────────────────────┐
│         SHADOW WARDEN AI            │
│                                     │
│  1. Decode obfuscation (base64/ROT) │
│  2. Strip PII & credentials         │  ← SSN, IBAN, API keys, emails
│  3. Block jailbreaks (OWASP LLM01)  │  ← ML + rule engine, <40ms
│  4. Scan AI output (OWASP LLM02)   │  ← XSS, SQLi, shell commands
│  5. Log metadata (GDPR-safe)        │  ← No raw content ever stored
└─────────────────────────────────────┘
      │                    │
      ▼                    ▼
  AI Model API        Audit Log
  (clean input)    (per tenant, GDPR)
```

---

## OWASP LLM Top 10 Coverage

| Category | Shadow Warden Control |
|----------|----------------------|
| LLM01 — Prompt Injection | ML semantic detector + regex rules + obfuscation decoding |
| LLM02 — Insecure Output | Output scanner: XSS, HTML injection, Markdown injection |
| LLM06 — Sensitive Info Disclosure | 15 PII/secret patterns, GDPR-compliant redaction |
| LLM08 — Excessive Agency | Shell command, SQL injection, SSRF, path traversal detection |
| All 10 | Continuous self-improvement via Evolution Engine (Claude Opus) |

---

## Built for MSPs

**Multi-tenant by design.** One deployment. Every client in an isolated sandbox with independent policies, audit logs, and compliance exports. Add a new client in minutes via API.

**Your stack, your control.** Runs on-premises, in your private cloud, AWS, or Azure. No sensitive data ever leaves your environment. No vendor lock-in.

**Sells itself to your clients.** Give each client their own dashboard, GDPR Article 30 report, and real-time SIEM feed. This is your new managed AI security service.

---

## Key Features

### Security
- **Credential Redaction**: API keys, passwords, SSNs, IBANs, credit cards, phone numbers, crypto wallet addresses — 15+ patterns
- **Jailbreak Detection**: MiniLM ML model (all-MiniLM-L6-v2) + 300+ semantic rules, self-updating via Evolution Engine
- **Obfuscation Decoding**: Catches base64, hex, ROT13, and unicode homoglyph attacks before analysis
- **Output Sanitization**: Scans AI-generated content for OWASP LLM02/LLM08 injection vectors

### Compliance & Reporting
- **GDPR Article 30 RoPA**: Auto-generated Record of Processing Activities per tenant
- **Data Subject Export / Purge**: One-click GDPR data subject rights fulfillment
- **Immutable Audit Log**: Every request logged with timing, risk level, redaction actions — never raw content
- **SOC 2 Roadmap**: Audit trail architecture pre-aligned to Trust Services Criteria

### MSP Operations
- **Role-Based Dashboard**: Admin / Auditor / Viewer RBAC with SAML SSO (Okta, Entra ID)
- **Client Webhooks**: Push HIGH/BLOCK events to client SIEM in real time (HMAC-SHA256 signed)
- **Threat Intelligence Sync**: Federated attack pattern sharing across the Shadow Warden fleet — new jailbreaks blocked across all clients within hours of first detection
- **Explainable AI**: Every decision explained in plain English for non-technical stakeholders

### Developer Experience
- **SDKs**: Python, TypeScript, Go — drop-in replacement for direct API calls
- **OpenAI-compatible proxy**: Zero code change for GPT-4 / Copilot integrations
- **LangChain callback**: One-line integration for AI agent pipelines
- **Batch API**: Filter up to 50 requests per round-trip

---

## Deployment Options

| Option | Time to Deploy | Who Manages |
|--------|---------------|-------------|
| Docker Compose (self-hosted) | 5 minutes | You |
| Helm chart (Kubernetes) | 15 minutes | You |
| AWS ECS Fargate (Terraform) | 30 minutes | You (IaC provided) |
| Azure AKS (Terraform) | 30 minutes | You (IaC provided) |
| Shadow Warden Cloud (coming Q3 2026) | 0 minutes | Us |

---

## Pricing Model

| Tier | Who It's For | Includes |
|------|-------------|----------|
| **NFR License** | MSP internal use | Full features, unlimited internal tenants |
| **MSP Starter** | Up to 10 client tenants | Dashboard, webhooks, compliance reports |
| **MSP Pro** | Unlimited tenants | + Federated threat feed, priority support |
| **MSP Enterprise** | Custom | + Dedicated feed, SOC 2 report, SLA |

*Contact for pricing: vz@shadow-warden-ai.com*

---

## Why Israel

Shadow Warden AI was built by a team with roots in Israeli unit 8200 and commercial cybersecurity — the same DNA that produced Check Point, CyberArk, and Wiz.

AI security is not a feature. It is a discipline. We treat it as one.

---

## Get Started in 5 Minutes

```bash
# Clone and run
git clone https://github.com/zborrman/Shadow-Warden-AI
cd Shadow-Warden-AI && cp .env.example .env
docker-compose up -d warden

# Verify (your first intercept)
curl -X POST http://localhost:8001/filter \
  -H "Content-Type: application/json" \
  -d '{"content": "SSN: 078-05-1120, key: sk-ant-api03-demo", "tenant_id": "test"}'
```

**shadow-warden-ai.com** | vz@shadow-warden-ai.com | [Calendar link]

---

*Shadow Warden AI — Proprietary. All rights reserved. GDPR-compliant by design.*
*v1.3.0 | AWS Marketplace listing in progress | Azure Marketplace listing in progress*
