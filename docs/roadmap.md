# Roadmap & Release Cadence

**Version 4.19 · Last updated 2026-05-07**

This page is the authoritative public roadmap for Shadow Warden AI. It is updated every sprint and reflects the current state of shipped, in-progress, and planned features across all 12 product categories.

!!! tip "Full roadmap"
    The canonical source is [`ROADMAP.md`](https://github.com/zborrman/Shadow-Warden-AI/blob/main/ROADMAP.md) in the repository root. This page mirrors the high-level structure; the GitHub file has every individual item with version and tier information.

---

## How We Prioritize

Every item competes across three inputs:

1. **Community Feedback** — security teams vote on features via the Community Hub. Items with 3+ votes jump one priority tier automatically.
2. **Threat Signal** — SOVA analytics surfaces emerging attack patterns. When a new jailbreak class or CVE class exceeds detection threshold, the corresponding pipeline hardening moves to P0 regardless of backlog position.
3. **Enterprise Demand** — direct requests from Enterprise customers with signed contracts land in the next sprint (or quarterly planning cycle for architectural changes).

We publish an updated priority snapshot every quarter. Re-ordering happens openly — if something drops, the reason appears in the [changelog](changelog/index.md).

> **Release cadence:** patch versions (4.x.y) ship weekly · minor versions (4.x) ship when a delivery block completes · major versions (5.0) ship quarterly tied to infrastructure milestones.

---

## Category Summary

| # | Category | Shipped | Planned |
|---|----------|---------|---------|
| 1 | [Security Pipeline](#1-security-pipeline) | 21 | 3 |
| 2 | [Agentic SOC](#2-agentic-soc) | 19 | 6 |
| 3 | [Community & Collaboration](#3-community--collaboration) | 23 | 5 |
| 4 | [Integrations](#4-integrations) | 13 | 9 |
| 5 | [Compliance & Privacy](#5-compliance--privacy) | 20 | 6 |
| 6 | [Cryptography](#6-cryptography) | 12 | 3 |
| 7 | [Infrastructure & DevOps](#7-infrastructure--devops) | 19 | 3 |
| 8 | [Observability & Monitoring](#8-observability--monitoring) | 25 | 3 |
| 9 | [Frontend & Product Surfaces](#9-frontend--product-surfaces) | 11 | 6 |
| 10 | [Billing & Monetization](#10-billing--monetization) | 11 | 5 |
| 11 | [Testing & Quality](#11-testing--quality) | 15 | 4 |
| 12 | [AI Research & Evolution](#12-ai-research--evolution) | 8 | 4 |

---

## 1. Security Pipeline

The 9-layer filter that processes every AI request in under 2ms.

| Status | Feature | Since | Tier |
|--------|---------|-------|------|
| ✅ | TopologicalGatekeeper — β₀/β₁ Betti numbers, n-gram point cloud | v1.0 | All |
| ✅ | ObfuscationDecoder — base64/hex/ROT13/homoglyphs, depth-3 | v1.0 | All |
| ✅ | SecretRedactor — 15 patterns + Shannon entropy | v1.0 | All |
| ✅ | SemanticGuard — rule engine, compound risk (3× MEDIUM → HIGH) | v1.0 | All |
| ✅ | HyperbolicBrain — MiniLM + Poincaré ball (70/30 cosine/hyperbolic) | v1.0 | All |
| ✅ | CausalArbiter — Bayesian DAG, Pearl do-calculus | v1.0 | All |
| ✅ | ERS — Redis sliding window, shadow ban ≥ 0.75 | v1.0 | All |
| ✅ | EvolutionEngine — Claude Opus auto-rule generation, hot-reload | v1.0 | All |
| ✅ | PhishGuard + SE-Arbiter — URL phishing + social engineering | v2.0 | All |
| ✅ | Shadow Ban Engine — gaslight / delay / standard (30+ pool, `secrets.choice()`) | v2.2 | All |
| ✅ | CPT drift gate — rejects calibration shifts >25% | v4.7 | All |
| ✅ | Evolution ReDoS gate — nested-quantifier heuristic + 0.3s timeout | v4.7 | All |
| ✅ | Intel Bridge — ArXiv → `synthesize_from_intel()` hot-reload | v4.13 | Pro+ |
| ✅ | Adaptive OTel sampling — 10% ALLOW / 100% HIGH+BLOCK | v4.14 | All |
| 📋 | Multi-modal content guard — image prompt injection | — | Pro+ |
| 📋 | Audio/video transcription guard — Whisper pre-scan | — | Enterprise |
| 📋 | ONNX fine-tuned model export — <1ms inference | — | All |

---

## 2. Agentic SOC

Autonomous AI operators — SOVA, MasterAgent, WardenHealer.

| Status | Feature | Since | Tier |
|--------|---------|-------|------|
| ✅ | SOVA Agent — Claude Opus 4.6, ≤10 iter, Redis memory (6h/20 turns) | v3.0 | Pro+ |
| ✅ | SOVA tools #1–27 — health, stats, CVE triage, ArXiv, billing | v3.0 | Pro+ |
| ✅ | SOVA tool #28 — `visual_assert_page` (BrowserSandbox + Claude Vision) | v3.3 | Pro+ |
| ✅ | SOVA tool #29–31 — shadow AI, explain decision, visual diff | v4.2–4.11 | Pro+ |
| ✅ | SOVA tools #38–42 — community feed, MISP, reputation | v4.15–4.16 | Community+ |
| ✅ | SOVA tools #43–45 — Obsidian scan, feed, share | v4.17 | Community+ |
| ✅ | MasterAgent — 4 sub-agents, HMAC tokens, human-in-the-loop | v4.0 | Pro |
| ✅ | WardenHealer — circuit breaker, bypass spike, canary, OLS trend, Haiku LLM | v3.3–4.11 | Pro+ |
| ✅ | `sova_obsidian_watchdog` — vault integrity check every 4h | v4.17 | Community+ |
| 📋 | SOVA tool #46 — `generate_threat_report` (PDF/HTML via XAI) | — | Pro+ |
| 📋 | SOVA tool #47 — `block_ip_range` (ERS hard block) | — | Enterprise |
| 📋 | MasterAgent sub-agent #5 — DataPrivacyAgent (GDPR Art.17) | — | Enterprise |
| 📋 | SOVA memory expansion — pgvector over past conversations | — | Pro+ |
| 📋 | Voice-activated SOC operator — WebRTC → Whisper → SOVA → TTS | — | Enterprise |

---

## 3. Community & Collaboration

Federated knowledge-sharing between Security Operations teams via SEP.

| Status | Feature | Since | Tier |
|--------|---------|-------|------|
| ✅ | UECIID codec — `SEP-{11 base-62}`, lexicographic = chronological | v4.6 | Community+ |
| ✅ | Inter-community peering — MIRROR_ONLY/REWRAP_ALLOWED/FULL_SYNC | v4.6 | Community+ |
| ✅ | Knock-and-Verify invitations — one-time Redis token, 72h TTL | v4.6 | Community+ |
| ✅ | Causal Transfer Guard — exfiltration P≥0.70 block in <20ms | v4.7 | Community+ |
| ✅ | STIX 2.1 Audit Chain — SHA-256 prev_hash, OASIS-compatible | v4.7 | Community+ |
| ✅ | Sovereign Data Pods — per-jurisdiction MinIO routing | v4.7 | Enterprise |
| ✅ | Community Charter — versioned governance, DRAFT→ACTIVE lifecycle | v4.8 | Community+ |
| ✅ | Behavioral Anomaly Detection — Z-score, 30-day rolling baseline | v4.8 | Community+ |
| ✅ | OAuth Agent Discovery — 14-provider catalog, scope-based risk | v4.8 | Community+ |
| ✅ | Reputation system — points ledger, NEWCOMER → ELITE badge ladder | v4.16 | Community+ |
| ✅ | `GET /public/leaderboard` — anonymised top-10 | v4.16 | Public |
| ✅ | Auto-apply community recommendations with human-in-the-loop | v4.16 | Pro+ |
| 📋 | `TRUSTED_ENTRY +3` reputation cron — 30-day auto-award | — | Community+ |
| 📋 | Community threat score federation — broadcast verified verdicts to peers | — | Enterprise |
| 📋 | Community AI model sharing — signed UECIID rule bundles | — | Enterprise |

---

## 4. Integrations

| Status | Feature | Since | Tier |
|--------|---------|-------|------|
| ✅ | LangChain callback — `WardenCallback` duck-typed | v2.0 | All |
| ✅ | Obsidian plugin v4.10 — ribbon, 5 commands, auto-scan | v4.10 | Community+ |
| ✅ | Obsidian plugin v4.18 — sidebar, frontmatter tagging, local pre-validation | v4.18 | Community+ |
| ✅ | Obsidian plugin v4.19 — Dataview dashboard, offline queue, XAI viz, scheduler | v4.19 | Community+ |
| ✅ | Slack slash command — HMAC-SHA256 verified, Block Kit, `/warden scan/status/approve` | v4.17 | Pro+ |
| ✅ | MISP connector — IoC → EvolutionEngine synthesis | v4.16 | Pro+ |
| ✅ | Shadow AI syslog sink — dnsmasq/BIND9/Zeek DNS UDP listener | v4.7 | Enterprise |
| ✅ | Browser extension — popup, verdict badge, UECIID display | v4.11 | Community+ |
| 📋 | VS Code extension — inline risk annotation | — | Individual+ |
| 📋 | GitHub Actions pre-commit hook — scan diff + commit message | — | Pro+ |
| 📋 | Jira integration — auto-create tickets on HIGH/BLOCK | — | Pro+ |
| 📋 | Microsoft Teams slash command | — | Pro+ |
| 📋 | Notion integration — scan pages, write risk properties | — | Community+ |
| 📋 | STIX/TAXII 2.1 feed consumer | — | Enterprise |
| 📋 | Zapier / Make connector | — | Individual+ |
| 📋 | MISP syslog bridge — route MISP ZMQ into syslog sink | — | Pro+ |

---

## 5. Compliance & Privacy

| Status | Feature | Since | Tier |
|--------|---------|-------|------|
| ✅ | GDPR Art. 35 DPIA | v2.0 | All |
| ✅ | GDPR purge API + auto-retention ARQ cron | v4.13 | All |
| ✅ | SOC 2 Type II evidence guide | v3.0 | Pro+ |
| ✅ | Secrets governance — 4 vault connectors, lifecycle, 14 endpoints | v4.9 | Community+ |
| ✅ | Sovereign AI Cloud — 8 jurisdictions, MASQUE tunnels, attestation | v4.4 | Enterprise |
| ✅ | STIX audit chain — tamper-evident, SIEM-importable JSONL | v4.7 | Community+ |
| ✅ | Transfer rules matrix — CLASSIFIED never; PHI 5-jurisdiction only | v4.4 | Enterprise |
| 📋 | ISO 27001 Annex A control mapping | — | Enterprise |
| 📋 | HIPAA technical safeguards attestation | — | Enterprise |
| 📋 | NIS2 Directive compliance report | — | Enterprise |
| 📋 | Continuous compliance scoring dashboard | — | Pro+ |

---

## 6–12. Other Categories

For the complete item-level breakdown of Cryptography, Infrastructure, Observability, Frontend, Billing, Testing, and AI Research — see the full [`ROADMAP.md`](https://github.com/zborrman/Shadow-Warden-AI/blob/main/ROADMAP.md).

---

## Release Timeline

| Version | Date | Theme |
|---------|------|-------|
| v1.0 | 2025 | Core 9-layer filter pipeline |
| v2.0 | 2025 | Multi-tenant auth, shadow ban, SIEM |
| v3.0 | 2025-Q4 | SOVA Agent, MasterAgent, WardenHealer |
| v4.0–4.5 | 2026-04 | Enterprise Pillars (PQC, Shadow AI, XAI, Sovereign, MasterAgent) |
| v4.6–4.7 | 2026-04 | SEP protocol, Security hardening P0/P1, STIX |
| v4.8–4.9 | 2026-04 | Community Intelligence, Secrets Governance |
| v4.10–4.13 | 2026-05 | Obsidian integration, SOVA v2, OTel tracing |
| v4.14–4.16 | 2026-05 | CI hardening, Public community, MISP, Reputation |
| v4.17–4.19 | 2026-05-07 | SOVA+Obsidian+Slack unification, plugin sidebar, Dataview dashboard |
| **v5.0** | **Q3 2026** | Multi-region active-active, ONNX online learning, HIPAA |

---

## Provide Feedback

- **Community Hub** — share ideas directly from the Obsidian plugin or tenant portal
- **GitHub Issues** — tag `roadmap` for feature requests
- **Enterprise** — contact your account team to escalate a backlog item to P0

We review the backlog every Friday and publish the updated sprint board every Monday.
