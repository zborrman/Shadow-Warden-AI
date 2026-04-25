# Strategy.md — Shadow Warden AI Go-to-Market & Business Strategy

**Version 4.7 · Last updated 2026-04**

---

## 1. Market Position

Shadow Warden AI is the **only GDPR-native AI security gateway** that combines:

- Real-time jailbreak/PII filtering (< 2ms P99)
- Self-improving threat detection via Claude Opus
- Post-Quantum cryptography (Ed25519+ML-DSA-65)
- Sovereign cloud routing (8 jurisdictions, MASQUE tunnels)
- Agentic SOC automation (MasterAgent + SOVA)

**Primary markets:** EU/US SMBs handling regulated data + Enterprise AI teams deploying LLM-backed products.

---

## 2. Pricing Strategy

| Tier | Price | Target |
|------|-------|--------|
| Starter | Free | Developers, evaluation |
| Individual | $19/mo | Freelancers, solo builders |
| Pro | $69/mo | SMBs, SaaS teams (≤50 employees) |
| Enterprise | $249/mo | Regulated industries, large orgs |

**Add-ons** (incremental revenue on Pro tier):
- Shadow AI Discovery: +$15/mo
- XAI Audit Reports: +$9/mo
- MasterAgent SOC: included in Pro base

**Strategic rationale:** Price anchored to IBM Cost of Data Breach 2024 average ($4.88M). Even a single breach prevention pays >16 years of Enterprise subscription.

---

## 3. Competitive Differentiation

| Capability | Shadow Warden | Lakera Guard | Prompt Security | Rebuff |
|-----------|--------------|--------------|----------------|--------|
| GDPR-native (content never logged) | ✅ | ⚠️ | ❌ | ❌ |
| Offline / air-gapped mode | ✅ | ❌ | ❌ | ❌ |
| Post-Quantum auth | ✅ | ❌ | ❌ | ❌ |
| Sovereign cloud routing | ✅ | ❌ | ❌ | ❌ |
| Self-improving (Evolution Engine) | ✅ | ⚠️ | ❌ | ⚠️ |
| Agentic SOC (MasterAgent) | ✅ | ❌ | ❌ | ❌ |
| Community document exchange (SEP) | ✅ | ❌ | ❌ | ❌ |
| FraudScore (real-time risk) | ✅ | ❌ | ❌ | ❌ |
| Open source core | ❌ (proprietary) | ✅ | ❌ | ✅ |

**Key moats:**
1. **GDPR architecture** — not bolt-on compliance; content never touches disk or logs by design.
2. **Topological + Causal AI** — Betti numbers + do-calculus arbitration not replicable without deep ML research.
3. **Evolution Engine** — Claude Opus rewrites detection rules from every attack attempt; gap closes faster than human analysts.
4. **Sovereign routing** — only product with MASQUE H3 tunnels + data residency attestation per jurisdiction.

---

## 4. Go-to-Market Channels

### 4.1 Developer-Led Growth (Starter → Pro)
- Free Starter tier with generous rate limits
- SDK: `pip install shadow-warden-client`
- LangChain callback (`WardenCallback`) — zero-friction integration
- OpenAI-compatible proxy endpoint — swap base URL, no code changes

### 4.2 Product-Led Growth (SMB)
- Landing page ROI calculator (IBM benchmarks)
- FraudScore page as lead magnet (real-time AI trust scoring)
- Dashboard SPA as free trial hook (live threat feed, no signup)

### 4.3 Enterprise Direct
- Compliance Report PDF as sales collateral (SOC 2 / GDPR Art. 30 ready)
- DPIA template (`docs/dpia.md`) handed to legal/DPO teams
- Sovereign Cloud demo (jurisdiction picker → MASQUE tunnel → attestation cert)
- MasterAgent live demo (autonomous SOC briefing on customer data)

### 4.4 Partnership
- EU AI Act consulting firms (we provide the technical layer they need)
- MSPs / MSSPs targeting SMBs in healthcare, finance, legal
- Reseller margin: 20% on annual Pro/Enterprise contracts

---

## 5. Revenue Model

### Recurring (MRR targets Q2 2026)
| Segment | Target MRR |
|---------|-----------|
| Pro (SMB) | $21,000 (300 seats) |
| Enterprise | $24,900 (100 seats) |
| Add-ons | $3,600 |
| **Total MRR** | **$49,500** |

### Non-Recurring
- Implementation / onboarding: $2,500 flat (Enterprise)
- Custom compliance report generation: $500/report
- Priority support SLA upgrade: $199/mo (Enterprise add-on)

---

## 6. Q2 2026 Growth Targets

| Metric | Target |
|--------|--------|
| MRR | $49,500 |
| Paying customers | 400 |
| Enterprise contracts | 100 |
| Churn (monthly) | < 3% |
| P99 filter latency | < 2ms |
| Coverage gate | ≥ 75% |
| Uptime SLA | 99.95% |

---

## 7. Regulatory Tailwinds

| Regulation | Impact |
|-----------|--------|
| EU AI Act (2025) | Mandatory risk classification for AI systems → compliance buyer |
| GDPR Art. 22 | Automated decisions require human review → CausalArbiter + XAI |
| NIS2 Directive | AI supply chain security → Shadow AI Governance |
| DORA (Financial) | AI resilience testing → Uptime Monitor + WardenHealer |
| US EO 14110 | Federal AI security standards → Sovereign Cloud routing |

---

## 8. Risk Factors

| Risk | Mitigation |
|------|-----------|
| OpenAI/Anthropic ship native filtering | Our GDPR-native arch + self-hosting option can't be replicated by API providers |
| liboqs breaking change (PQC) | Fail-open design; Ed25519 classical path always works |
| Playwright MCR base image changes | Pin `v1.49.0-noble`; CI smoke test catches breakage |
| Redis unavailability | `REDIS_URL=memory://` in-process fallback throughout |
| Coverage gate regression | Block-fail CI at 75%; adversarial tests are informational only |

---

*Strategy.md — Shadow Warden AI business strategy v4.7 · 2026-04*
