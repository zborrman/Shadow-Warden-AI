# Strategy.md — Shadow Warden AI Go-to-Market & Business Strategy

**Version 4.14 · Last updated 2026-05-07**

---

## 1. Market Position

Shadow Warden AI is the **only GDPR-native AI security gateway** that combines:

- Real-time jailbreak/PII filtering (< 2ms P99)
- Self-improving threat detection via Claude Opus
- Post-Quantum cryptography (Ed25519+ML-DSA-65)
- Sovereign cloud routing (8 jurisdictions, MASQUE tunnels)
- Agentic SOC automation (MasterAgent + SOVA)
- Business Community document exchange (SEP + Obsidian integration)
- Secrets Governance (multi-cloud vault lifecycle)
- SOC Next.js Dashboard (real-time threat feed, filter sandbox, OTel traces)
- Full OTel distributed tracing (per-layer spans, Jaeger, < 2ms overhead)
- Public API documentation (Redoc at docs.shadow-warden-ai.com — always-on, no auth)
- SLO burn-rate alerting (Google SRE multi-window: fast 14.4× + slow 6× budget consumption)
- Supply-chain security: Trivy container CVE scanning + pip-audit SCA in CI

**Primary markets:** EU/US SMBs and knowledge workers handling regulated data +
Enterprise AI teams deploying LLM-backed products.

---

## 2. Pricing Strategy

| Tier | Price | Requests | Target |
|------|-------|----------|--------|
| Starter | Free | 1k/mo | Developers, evaluation |
| Individual | $5/mo | 5k/mo | Freelancers, solo builders |
| Community Business | $19/mo | 10k/mo | Small teams, Obsidian power users |
| Pro | $69/mo | 50k/mo | SMBs, SaaS teams (≤50 employees) |
| Enterprise | $249/mo | Unlimited | Regulated industries, large orgs |

**Add-ons** (incremental revenue, sold separately from tier):

| Add-on | Price | Eligible tiers | Feature unlocked |
|--------|-------|----------------|-----------------|
| Shadow AI Discovery | +$15/mo | Pro+ | Shadow AI subnet probe + DNS telemetry |
| XAI Audit Reports | +$9/mo | Individual+ | /xai/* HTML + PDF reports |
| Secrets Vault | +$12/mo | Individual+ | Secrets Governance (all 14 endpoints) |

**Included in base tier** (not sold as add-ons):
- MasterAgent SOC — included in Pro ($69)
- Obsidian Integration — included in Community Business ($19)
- File Scanner + Email Guard — included in Community Business ($19)

**Strategic rationale:** Price anchored to IBM Cost of Data Breach 2024 average
($4.88M). Even a single breach prevention pays >16 years of Enterprise subscription.
Community Business at $19 targets the growing Obsidian + knowledge-management market
where GDPR compliance for AI-assisted note sharing is an unmet need.

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
| Obsidian vault integration | ✅ | ❌ | ❌ | ❌ |
| Multi-cloud secrets governance | ✅ | ❌ | ❌ | ❌ |
| FraudScore (real-time risk) | ✅ | ❌ | ❌ | ❌ |
| SOC Dashboard SPA (real-time feed) | ✅ | ❌ | ❌ | ❌ |
| OTel distributed tracing (Jaeger) | ✅ | ❌ | ❌ | ❌ |
| Public API docs (Redoc, always-on) | ✅ | ⚠️ | ⚠️ | ❌ |
| SLO burn-rate alerting (multi-window) | ✅ | ❌ | ❌ | ❌ |
| Container CVE scanning (Trivy CI) | ✅ | ⚠️ | ❌ | ❌ |
| Open source core | ❌ (proprietary) | ✅ | ❌ | ✅ |

**Key moats:**
1. **GDPR architecture** — not bolt-on compliance; content never touches disk or logs by design.
2. **Topological + Causal AI** — Betti numbers + do-calculus arbitration not replicable without deep ML research.
3. **Evolution Engine** — Claude Opus rewrites detection rules from every attack attempt; gap closes faster than human analysts.
4. **Sovereign routing** — only product with MASQUE H3 tunnels + data residency attestation per jurisdiction.
5. **Obsidian + SEP** — first AI security gateway with native Obsidian plugin that gates note sharing behind causal transfer safety.

---

## 4. Go-to-Market Channels

### 4.1 Developer-Led Growth (Starter → Individual → Pro)
- Free Starter tier with immediate API access
- SDK: `pip install shadow-warden-client`
- LangChain callback (`WardenCallback`) — zero-friction integration
- OpenAI-compatible proxy endpoint — swap base URL, no code changes
- GitHub-first: open issues for feature requests, closed-source core

### 4.2 Product-Led Growth (Community Business)
- Obsidian plugin published to Obsidian community plugins marketplace
- Landing page: shadow-warden-ai.com/obsidian — "Secure your vault"
- Free scan (no account required) → account required to share via SEP
- FraudScore page as lead magnet (real-time AI trust scoring demo)

### 4.3 SMB / Pro Channel
- ROI calculator (IBM benchmarks) on pricing page
- SOC Dashboard (`dash.shadow-warden-ai.com`) as free trial hook — live threat feed, filter sandbox, Jaeger traces, no signup required
- Email Guard and File Scanner demonstrate immediate value before conversion

### 4.4 Enterprise Direct
- Compliance Report PDF as sales collateral (SOC 2 / GDPR Art. 30 ready)
- DPIA template (`docs/dpia.md`) handed to legal/DPO teams
- Sovereign Cloud demo (jurisdiction picker → MASQUE tunnel → attestation cert)
- MasterAgent live demo (autonomous SOC briefing on customer data)
- Secrets Governance demo for DevSecOps teams (multi-vault compliance dashboard)

### 4.5 Partnership
- EU AI Act consulting firms (we provide the technical layer they need)
- MSPs / MSSPs targeting SMBs in healthcare, finance, legal
- Obsidian plugin ecosystem — co-marketing with Obsidian-adjacent tools
- Reseller margin: 20% on annual Pro/Enterprise contracts

---

## 5. Revenue Model

### Recurring (MRR targets Q3 2026)

| Segment | Target MRR |
|---------|-----------|
| Community Business ($19) | $3,800 (200 seats) |
| Pro ($69) | $21,000 (304 seats) |
| Enterprise ($249) | $24,900 (100 seats) |
| Add-ons (Shadow AI + XAI + Secrets) | $5,400 |
| **Total MRR** | **$55,100** |

### Non-Recurring
- Implementation / onboarding: $2,500 flat (Enterprise)
- Custom compliance report generation: $500/report
- Priority support SLA upgrade: $199/mo (Enterprise add-on)
- Obsidian plugin enterprise deployment: $1,500 one-time setup

---

## 6. Q3 2026 Growth Targets

| Metric | Target |
|--------|--------|
| MRR | $55,100 |
| Paying customers | 604 |
| Enterprise contracts | 100 |
| Community Business seats | 200 |
| Obsidian plugin installs | 2,000 |
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
| EU Data Act 2025 | Data portability and sharing obligations → SEP + Data Pods |

---

## 8. Risk Factors

| Risk | Mitigation |
|------|-----------|
| OpenAI/Anthropic ship native filtering | Our GDPR-native arch + self-hosting option can't be replicated by API providers |
| liboqs breaking change (PQC) | Fail-open design; Ed25519 classical path always works |
| Playwright MCR base image changes | Pin `v1.49.0-noble`; CI smoke test catches breakage |
| Redis unavailability | `REDIS_URL=memory://` in-process fallback throughout |
| Coverage gate regression | Block-fail CI at 75%; adversarial tests are informational only |
| Obsidian API breaking change | Plugin targets minAppVersion 1.4.0; locked to stable API surface |
| Multi-cloud vault connector auth changes | Abstract `VaultConnector` base class; each connector independently versioned |
| Container CVE discovered post-deploy | Trivy CI gate + SARIF uploaded to GitHub Security; `continue-on-error` avoids blocking hotfixes |
| SLO budget exhaustion unnoticed | Burn-rate alerts (fast 14.4× + slow 6×) fire before budget is fully consumed |
| OTel Collector breaking change | Pinned to `otel/opentelemetry-collector-contrib:0.103.1`; dashboard works without tracing |
| Next.js breaking change | Dashboard pinned to `next@14.2.29`; standalone output means no runtime dep on Next.js CDN |

---

*Strategy.md — Shadow Warden AI business strategy v4.13 · 2026-05-06*
