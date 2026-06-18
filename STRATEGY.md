# Strategy.md — Shadow Warden AI Go-to-Market & Business Strategy

**Version 6.6 · Last updated 2026-06-18**

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
- **Collective immunity network**: SEP community threat feed, reputation system (badges + points), public storytelling dashboard
- **ISAC/MISP integration**: MISPConnector → EvolutionEngine synthesis, SOVA tool #41
- **Auto-apply community recommendations**: one-click UECIID → corpus import with human-in-the-loop approval
- **Semantic Layer (Headless BI)**: centralized metric contracts (filter events, ERS scores, billing) — LLM translates natural language to deterministic SQL; OSI-compatible export
- **Settings Hub**: unified config surface across Agents (SOVA/MasterAgent), Notifications, Agentic Commerce, Semantic Layer — accessible from Streamlit, Portal, and SOC Dashboard
- **Agentic Commerce**: UCP/AP2/MCP procurement protocols; multi-agent auction (Claude/Gemini/GPT); FIDO2 passkey auth; Web3 Sepolia mandate contracts
- **AI Analytics Hub (v5.2)**: 9 semantic models covering security, risk, billing, incidents, vendors, commerce, sovereignty, compliance, and AI spend — single deterministic SQL interface for all dashboards + AI agents; Redis 10-min cache
- **Commerce Budget Guardian (v5.2)**: every AP2 payment pre-checked against actual MTD spend via Semantic Layer; per-transaction + monthly caps + approval gate + Slack alert; Semantic Layer as active business logic participant
- **Self-Service Model Catalog (v5.2)**: Pro+ tenants register custom semantic models via API or Streamlit; persisted to SQLite, hot-loaded without restart; OSI 1.0 export/import for external BI systems
- **GitHub Actions CI Security Gate (v5.3)**: pre-merge gate scans every commit message + diff through the 9-layer pipeline; composite action with PR comment + 90-day artifact; local pre-commit hook mode; Pro+ tier
- **Continuous Compliance Scoring (v5.3)**: real-time posture across SOC 2, GDPR, ISO 27001, HIPAA, NIS2 — auto-refresh every 30s, 168-snapshot ring buffer, SVG score gauge, SOC dashboard + Streamlit page; Pro+ tier
- **ISO 27001:2022 Annex A mapping (v5.3)**: all 93 Annex A controls mapped to platform capabilities across 4 themes with evidence pointers; per-theme coverage %, print-ready HTML report, SOC dashboard drilldown; Enterprise tier
- **Document Intelligence (v5.4)**: Microsoft MarkItDown converts PDF/DOCX/PPTX/XLSX/HTML/images/audio/ZIP to Markdown before the 9-layer pipeline runs; file-type-aware Redis cache (24h/7d/1h TTLs); 50 MB gate; SOVA tool #50; portal Document Scanner; `/document-intel` API; Prometheus counters; Community Business+ tier
- **Real-time Compliance Gap Dashboard (v5.5)**: `CompliancePostureService` aggregates 19 controls from Vendor Governance, Incident Register, Secrets Vault, Document Intelligence, STIX Audit, Training Records into live GDPR/SOC2/ISO27001/HIPAA scores with per-gap remediation guidance; Redis cache + Pub/Sub; WebSocket `/compliance/ws`; SOVA tools #51/#52; portal self-service page; Pro+ tier
- **Community Hub SOC Integration (v5.6)**: full Community Hub surface across all 3 client layers — SOC Next.js dashboard (list + 6-tab detail with live WebSocket metrics, `useCommunityWebSocket` hook, 30s auto-reconnect), Portal UX upgrade (`react-hot-toast` notifications on all actions, `dd/mm/yy` dates, descending chronological sort), Streamlit 7-tab Hub (`fmt_date()`, `st_toast()`, sorted member/community lists); Community Business+ tier
- **Voice-Commerce Agents (v6.0)**: end-to-end voice AI commerce stack — `warden/voice/` (StreamingASR, TTSEngine, VoiceNLU, DialogueManager, VoiceBiometric, VoiceGuardian), X402Protocol micropayment rail, 6 SOVA tools #62–67, WebSocket stream; Enterprise tier
- **Security Hardening Phase 2 (v6.1)**: HSM key rotation audit, AutoResponder agent isolation + STIX chain, prompt injection defense (10 regex + delimiter patterns), decentralized key lifecycle, Federated Trust Registry, SecureWipe, hybrid PQC asset signing, behavioral anomaly tests, voice-commerce Prometheus metrics + Grafana dashboard
- **Unified Design System DS-01 (v6.2)**: `packages/ui/` — 10 shared components + ThemeProvider with DS-01 tokens applied across portal, dashboard, Streamlit, and static site; ThemeToggle with localStorage persistence; no-root-package.json monorepo layout
- **Horizontal Scalability (v6.3)**: Helm chart (11 services, HPA warden 2–10, KEDA arq-worker), Terraform Hetzner, canary deploy script (10%→50%→100%, Prometheus gate, auto-rollback), region middleware (`X-Region` / `X-Region-Prefer` headers)
- **Advanced Detection (v6.4)**: multimodal jailbreak detection (Claude Vision image + VoiceGuardian audio, fail-open), agentic loop monitor (β₂ Betti topology), live MITRE ATLAS/OWASP LLM threat sync, adversarial benchmark suite (65 prompts, ≥95% BLOCK recall), deepfake audio pipeline (mel-spectrogram + VALL-E signatures)
- **Developer Experience (v6.5)**: Python + async SDK, OTel `WardenSpanProcessor`, VS Code inline gutter icons, `/playground` API explorer, webhook event system (HMAC-SHA256, 6 event types)
- **Enterprise SSO & White-Label (v6.6)**: SAML 2.0 SP-initiated (AuthnRequest, ACS, replay protection, JIT provisioning), white-label mode (per-tenant domain/logo/CSS), Custom Compliance Framework Builder, AI Usage Budgets, `/status` SLA page
- **Server performance (v6.6 maintenance)**: `event_logger.append()` offloaded to `BackgroundTask` (removes 5–20ms file I/O from hot path); Redis cache timeouts raised (connect 5s, read 3s); Docker `stop_grace_period: 30s` + healthcheck retries 15→5

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
| Semantic Layer AI Query | Included Pro+ | Pro+ | NL → SQL via Claude Haiku |
| Settings Hub | Included All | All | Unified agent/notification/commerce/semantic config |

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
| Community threat feed (SEP + reputation) | ✅ | ❌ | ❌ | ❌ |
| ISAC/MISP feed connector | ✅ | ❌ | ❌ | ❌ |
| Public storytelling dashboard | ✅ | ❌ | ❌ | ❌ |
| GitHub Actions CI security gate | ✅ | ❌ | ⚠️ | ❌ |
| ISO 27001:2022 control mapping (93 controls) | ✅ | ⚠️ | ❌ | ❌ |
| Real-time compliance scoring (5 standards) | ✅ | ❌ | ⚠️ | ❌ |
| Document Intelligence (PDF/DOCX/audio → scan) | ✅ | ❌ | ❌ | ❌ |
| Live compliance gap detection + remediation | ✅ | ❌ | ❌ | ❌ |
| Open source core | ❌ (proprietary) | ✅ | ❌ | ✅ |

**Key moats:**
1. **GDPR architecture** — not bolt-on compliance; content never touches disk or logs by design.
2. **Topological + Causal AI** — Betti numbers + do-calculus arbitration not replicable without deep ML research.
3. **Evolution Engine** — Claude Opus rewrites detection rules from every attack attempt; gap closes faster than human analysts.
4. **Sovereign routing** — only product with MASQUE H3 tunnels + data residency attestation per jurisdiction.
5. **Obsidian + SEP** — first AI security gateway with native Obsidian plugin that gates note sharing behind causal transfer safety.
6. **Collective immunity network** — reputation-gated community threat feed with gamification creates compounding network effects: more members → faster threat propagation → higher detection quality for every tenant.
7. **ISAC/MISP hub** — only product that bridges enterprise MISP feeds directly into the local ML corpus via EvolutionEngine; turns external intelligence into in-process rules in under a minute.

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
- **Public community dashboard** (`shadow-warden-ai.com/community`) — live threat stats, leaderboard, incident feed; demonstrates network effect to prospects without requiring signup
- **Reputation badges** — GUARDIAN/ELITE tiers serve as social proof; top contributors visible on public leaderboard (anonymised)

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
| MISP server unreachable | `MISPConnector.sync()` catches httpx errors and returns `MISPSyncResult` with errors list; no crash |
| Reputation DB corruption | SQLite `community_reputation` is append-only ledger; worst case: `DROP TABLE` and rebuild from `reputation_events` log |
| Community feed spam/abuse | UECIID publication requires PII gate (`/filter` check); display_name capped at 200 chars; rate-limited by ERS |
| Semantic Layer SQL injection | `_SAFE_IDENT` regex rejects unsafe identifiers; all values use `%s` parameterisation (psycopg2/asyncpg safe) |
| Settings Hub Redis unavailability | `_mem` in-process dict fallback in `settings/service.py`; all CRUD survives Redis outage |
| Agentic Commerce runaway spend | Per-transaction + monthly budget caps in `CommerceSettings`; approval gate above threshold; STIX audit chain |
| Web3 Sepolia contract failure | Blockchain calls wrapped in try/except; mandate validation falls back to AP2 HMAC path |
| CI gate false positives block merges | `fail_on` defaults to `BLOCK` only; `HIGH` opt-in; individual file cap 30 + 6 kB; binary/lockfile skip patterns prevent noisy findings |
| ISO 27001 audit delta between releases | `_ISO27001_CONTROLS_V2` is version-controlled; diffs are auditable; "Partial" status tracked honestly per control |
| Compliance posture drift undetected | 168-snapshot ring buffer + 30s auto-refresh; Grafana `corpus_drift` alert fires when detection quality drops below baseline |

---

*Strategy.md — Shadow Warden AI business strategy v6.6 · 2026-06-18*
