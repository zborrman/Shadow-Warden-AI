# Shadow Warden AI — Changelog

Version history from v1.0 to current. Entries are grouped by minor version.
Feature IDs reference [ROADMAP.md](../ROADMAP.md).

---

## v6.3 — Reputation, DAO Governance & Cross-chain Escrow (2026-06-13)

- **MKT-05** — Advanced Reputation & Trust Graph: `trust_graph.py` + `sybil_guard.py`,
  per-agent PageRank-style composite score (trade history + community tenure + dispute rate),
  `GET /marketplace/agents/{id}/trust` endpoint, Sybil detection (wash trading + rapid listing flood).
- **MKT-06** — Community DAO Governance: `governance/proposals` CRUD, 72h voting window, quorum
  check (default 51%), `POST /marketplace/governance/proposals/{id}/vote`, on-chain finalisation stub.
- **MKT-07** — Cross-chain Escrow: Sepolia + Polygon Amoy + Arbitrum Sepolia support in
  `warden/web3/chains.py`; `_check_rpc_with_retry()` with 2/4/8 s exponential back-off;
  `EscrowDeploymentError` → HTTP 502 via API; `warden_escrow_rpc_check_total` Prometheus counter.
- **INFRA-01** — Preflight checks for MASQUE tunnel creation: `warden/sovereign/preflight.py`
  (MinIO + Redis + Warden API health, concurrent httpx + sync redis-py, 5 s timeout);
  `skip_preflight: bool` bypass field; `warden_tunnel_preflight_total{region,status}` counter.
- 10 new tests: `test_tunnel_preflight.py` (6 tests) + `test_escrow_rpc_check.py` (4 tests).
- **Docs**: `troubleshooting.md` created; `deployment-guide.md` preflight section; `ROADMAP.md`
  INFRA-01 entry; `api-reference.md` sovereign tunnels + document-intel cache endpoints.

## v6.2 — Agentic Commerce Hub (2026-06-10)

- **MKT-04** — Unified Community Hub Portal page (`portal/src/app/community-hub/hub/[id]/page.tsx`):
  left sidebar navigation, 6 sections (Overview, Tunnels & Peering, Marketplace, Compliance,
  Governance, Settings), TanStack Query data fetching, `wFetch<T>()` for sovereign/tunnels.
- Portal sidebar: **My Hub** entry (`/community-hub/hub`) links to active community's hub page.
- Create-community flow redirects to new hub route after creation.
- Marketplace section: 5 sub-tabs (Agents, Assets, Trading, Escrow, Purchased).
- Governance section: DAO proposal list + vote For/Against + Create proposal modal.

---

## v5.6 — Production Readiness & Public SDK (2026-06-12)

- **SDK-01** — Public Node.js/TypeScript SDK (`@shadow-warden/sdk`): 5 resource classes
  (Community, Marketplace, Compliance, Semantic, Documents), zero runtime deps, Vitest tests,
  LangChain + CrewAI + AutoGPT integration examples.
- **ONB-01** — AI-Assisted Onboarding Wizard: 5-step guided setup (Community → Members →
  Marketplace → Compliance → Integrations), Redis-backed sessions (24h TTL), SOVA tools #53–55,
  Streamlit page 25.
- **MO-01** — Mobile SOC App: React Native (iOS + Android), FCM/APNs push alerts, 9-stage XAI
  detail, one-tap deep-link, SQLite device registry (50/tenant).
- OpenAPI 3.0.3 spec at repo root (`openapi.json`), covers all 37 public endpoints.
- Marketplace analytics: 3 new endpoints (`/analytics/summary`, `/volume`, `/agents`),
  Streamlit page 23, SOC Dashboard marketplace page.
- `openapi-typescript-codegen` integration: `npm run generate` auto-generates typed client
  from `openapi.json`.

## v5.5 — Real-time Compliance Dashboard (2026-05-20)

- **CP-30** — Real-time Compliance Dashboard: 19 controls across GDPR(6)/SOC2(5)/ISO27001(4)/
  HIPAA(4), Redis pub/sub, WebSocket `/compliance/ws` (30s push), 5-tab Streamlit page 21.
- **SOVA #51** — `get_compliance_report` tool (live posture + gap list).
- **SOVA #52** — `remediate_gap` tool (acknowledge, invalidate cache, return updated score).
- Portal `/compliance/` self-service page with gap remediation UI.
- New Grafana compliance alerts: posture score below threshold.

## v5.4 — Document Intelligence (2026-05-10)

- **FE-50** — Document Intelligence: `MarkItDown` converter, SHA-256 Redis cache (PDF 24h /
  audio 7d / images 1h), 50 MB gate, 30s timeout. 6 endpoints at `/document-intel/*`.
- `FilterRequest` now accepts `file_base64` + `file_filename` — filter hook converts file to
  Markdown before 9-layer pipeline (fail-open).
- **SOVA #50** — `scan_document` tool.
- Community document converter at `/doc-converter`.
- `POST /obsidian/scan-attachment`, `POST /prompt-library/from-file`.
- Portal `/doc-scanner/` page.

## v5.3 — GitHub Actions CI Gate + ISO 27001 (2026-04-28)

- **IN-15** — GitHub Actions CI gate: `warden-scan.yml`, per-file diff scanning, step summary
  table, PR comment, 90-day audit artifact, composite action, pre-commit mode.
- **CP-22** — ISO 27001:2022 full 93-control matrix (Organizational/People/Physical/
  Technological), SOC Dashboard drilldown page.
- **CP-25** — Continuous compliance scoring: `GET /compliance/posture` + `GET
  /compliance/history`, 168-entry ring buffer, tier gate (Pro+).
- Streamlit page 17 (Compliance Scoring), page 18 (ISO 27001).

## v5.2 — AI Analytics Hub + Budget Guardian (2026-04-15)

- **FE-47** — AI Analytics Hub: 9 built-in Semantic Layer models, Redis query cache
  (TTL 600s), landing page at `/analytics`.
- **FE-48** — Commerce Budget Guardian: `check_budget()` reads settings → queries `ai_spend`
  model → allow/require_approval/block.
- **FE-49** — Self-Service Catalog: `register_tenant_model()`, SQLite persistence, hot-reload
  into SemanticEngine on startup.
- `WhatsNew.astro` component on marketing site.
- SOVA tools: `semantic_query`, `list_semantic_models`, `check_commerce_budget`,
  `get_spend_summary`.

## v5.1 — Semantic Layer + Settings Hub (2026-03-30)

- **FE-42** — Semantic Layer (Headless BI): `SemanticEngine` deterministic SQL generator,
  3 built-in models, access-rule enforcement. FastAPI router at `/semantic-layer/*` (Pro+).
  Streamlit page 15, SOC Dashboard `/semantic-layer`.
- **FE-43** — Settings Hub: unified config for Agents/Notifications/Commerce/Semantic.
  Redis + in-memory fallback. Streamlit page 16, SOC Dashboard `/settings`.
- `catalog.py` — `bootstrap_tenant_models()` restores persisted models on startup.

## v5.0 — Agentic Commerce + Community M2M Marketplace (2026-03-10)

- **CM-40** — Agentic Commerce: UCP/AP2/MCP procurement protocols, multi-agent auction
  (`MultiAgentOrchestrator`), FIDO2 passkeys, Sepolia Web3 mandate contract.
- M2M Marketplace Phase 1: agent DID registration (`did:shadow:{32 base62}`), asset
  tokenizer (rule/model/signals), listings, escrow lifecycle.
- Sybil Guard + Trust Graph for agent reputation.
- DAO Governance Proposals with voting.
- MasterAgent sub-agent #5: `DataPrivacyAgent` (GDPR ROPA/DPIA).
- `sova_visual_patrol` smart priority weights (_PatrolWeights): Redis-backed per-URL
  decay/boost, fallback to in-process dict.

---

## v4.30 — Business Intelligence Module (2026-03-01)

- **CM-39** — Business Intelligence: 8-category analytics (usage, threats, vendors, costs,
  compliance, benchmarks, predictions, reports). SQLite cache, 15-min TTL. FastAPI router
  at `/business-intelligence/*`. Streamlit page 12, OLS extrapolation.

## v4.29 — SMB Governance Suite (2026-02-20)

- **IN-25** — SMB AI Governance Suite: single-wizard provisioning of all 7 modules
  (vendor governance, cost allocation, budget, incidents, supplier risk, prompt library,
  training records). `provision_suite()` orchestrator. UECIID + STIX audit on provision.

## v4.28 — Employee AI Training Records (2026-02-12)

- **CM-38** — Employee AI Training Records: HMAC-SHA256 signed completions, expiry tracking,
  behavioral hook integration (`ai_training_completed` event), compliance report.

## v4.27 — Shared Prompt Library (2026-02-05)

- **CM-37** — Shared Prompt Library: UECIID provenance, injection screening via `/filter`
  before save, versioning, peered sharing.

## v4.26 — Supplier AI Risk Assessment (2026-01-28)

- **CM-36** — Supplier AI Risk Assessment: 5-criteria composite scoring (data access,
  capability, compliance, peering history, disclosure recency). Pulls from `sep_transfers`
  and `vendor_dpa_records`. No external API calls.

## v4.25 — AI Incident Register (2026-01-20)

- **CM-35** — AI Incident Register: STIX-linked incident journal. `log_incident()` appends to
  STIX audit chain. `auto_log_from_filter_event()` fires on BLOCK decisions from `main.py`.
  JIRA/Slack integration on HIGH/CRITICAL severity.

## v4.24 — Cost Allocation + Budget Dashboard (2026-01-15)

- **BL-23** — AI Cost Allocation: per-department/vendor SQLite spend tracking,
  `import_from_logs()` to ingest from logs.json.
- **BL-24** — AI Budget Dashboard: real-time spend vs cap, approval workflow
  (pending/approved/rejected), Next.js SOC page.

## v4.23 — AI Vendor Governance Register (2026-01-08)

- **BL-22** — AI Vendor Governance Register: DPA tracking (GDPR Art 28/CCPA/ISO27001/CUSTOM),
  expiry alerts, risk tier (LOW/MEDIUM/HIGH/CRITICAL). Streamlit page 6 (Secrets & Governance).

---

## v4.22 — SOVA Memory + Community Federation (2025-12-15)

- **AG-24** — SOVA memory expansion: pgvector over past conversations.
- **CM-26** — Community threat score federation: broadcast verified verdicts to peers.
- **CM-27** — Community AI model sharing: signed UECIID bundles.
- **IN-14** — VS Code extension: inline risk annotation on selected text.
- **SP-22** — Multi-modal content guard: image prompt injection detection.

## v4.21 — SOVA Tool Suite Expansion (2025-12-01)

- **AG-21** — SOVA tool #46: `generate_threat_report` (PDF/HTML export via XAI renderer).
- **AG-22** — SOVA tool #47: `block_ip_range` (ERS hard block, tenant-scoped, Enterprise).
- **AG-23** — MasterAgent DataPrivacyAgent sub-agent (GDPR ROPA/DPIA, retention).
- **IN-16** — Jira integration: auto-create tickets on HIGH/BLOCK.
- **IN-17** — Microsoft Teams slash command.
- **IN-18** — Notion integration: scan pages, write risk tags.
- **IN-19** — STIX/TAXII feed consumer.
- **IN-20** — Zapier / Make connector.
- **IN-21** — OTel SDK library (`WardenSpanProcessor`).
- **IN-22** — MISP syslog bridge (ZMQ + HTTP poll fallback).

## v4.19 — Obsidian Plugin v4.19 (2025-11-20)

- Dataview dashboard, offline publish queue, XAI pipeline visualisation,
  scan scheduler with configurable interval.
- `manifest.json` version bumped to 4.19.0.

## v4.18 — Obsidian Sidebar + Pre-validation (2025-11-10)

- `WardenSidebarView` (ItemView): scan result, reputation, feed, queue badge.
- `tagFrontmatter()`: writes `warden_data_class`, `warden_risk`, `warden_flags`.
- `prevalidate()`: 8 client-side PII regex patterns.
- `GET /obsidian/reputation` endpoint.

## v4.17 — SOVA + Obsidian + Slack Unification (2025-11-01)

- Slack slash command handler with HMAC-SHA256 verification.
- SOVA tools #43–45: `scan_obsidian_note`, `get_obsidian_feed`, `share_obsidian_note`.
- `sova_obsidian_watchdog` ARQ cron every 4h.
- `alert_obsidian_event()` Slack webhook on HIGH/BLOCK.

## v4.16 — MISP + Community Reputation (2025-10-20)

- **IN-09** — MISP connector: 14 IoC types → EvolutionEngine synthesis.
- **CM-18/19** — Reputation system + badge ladder (NEWCOMER → ELITE).
- **CM-20** — Anonymised leaderboard `GET /public/leaderboard`.

## v4.15 — Community Discovery (2025-10-10)

- **CM-16** — SOVA community lookup endpoint.
- **CM-17** — `GET /public/community` GDPR-safe aggregate stats.
- **AG-07** — SOVA tools #38–40: community feed, publish, recommendations.

## v4.14 — OTel Adaptive Sampling (2025-10-01)

- **SP-21** — Adaptive sampling: 10% ALLOW / 100% HIGH+BLOCK, tail-sampling Collector.
- **SP-14** — Intel Bridge: ArXiv papers → `synthesize_from_intel()` → hot-reload (activated).

---

## v4.13 — OTel + GDPR Cron (2025-09-15)

- **SP-15** — OTel span instrumentation across all 9 pipeline stages.
- **CP-02/03** — GDPR Art. 17 purge API + daily ARQ cron at 02:00 UTC.
- `py-spy` profiling script added to `scripts/`.

## v4.11 — SOVA Intelligence (2025-09-01)

- **AG-06** — `visual_diff` tool: Claude Vision baseline vs candidate comparison.
- **AG-16/17** — WardenHealer OLS trend prediction + Claude Haiku incident classification.
- **AG-18** — `sova_visual_patrol` with Redis-backed per-URL weights.
- **IN-13** — Browser extension popup.

## v4.10 — Obsidian Business Community Integration (2025-08-20)

- Obsidian note scanner, API (`/obsidian/*`), TypeScript plugin, 25 tests.

## v4.9 — Secrets Governance (2025-08-10)

- Vault connectors, inventory, policy engine, lifecycle manager, 14 API endpoints.

## v4.8 — Community Governance + Intelligence (2025-08-01)

- Community Charter, Behavioral Anomaly Detection, Intelligence Report, OAuth Discovery.
- CPT drift gate fix (Windows ReDoS workaround in regex safety validator).

## v4.7 — Security Hardening + SEP Strategic Features (2025-07-20)

- Fail-closed auth, VAULT_MASTER_KEY validation, shadow ban `secrets.choice()`.
- CPT drift gate, Evolution ReDoS gate.
- Causal Transfer Guard, Sovereign Data Pods, STIX 2.1 Audit Chain.
- PQC Transfer Proof (ML-DSA-65 hybrid).
- Caddy v2.8 replacing nginx. Optional scapy ARP probe for Shadow AI.
- MasterAgent batch API (50% token discount).

---

## v4.6 — Syndicate Exchange Protocol (SEP) (2025-07-01)

- UECIID codec, peering, Knock-and-Verify invitations. 18 REST endpoints.

## v4.5 — Pricing + Tier Gates (2025-06-20)

- Pro $49→$69, Enterprise $199→$249. Add-ons: shadow_ai_discovery ($15), xai_audit ($9).

## v4.4 — Sovereign AI Cloud (2025-06-10)

- 8 jurisdictions, MASQUE tunnels, per-tenant routing policy, sovereignty attestation.

## v4.3 — Explainable AI 2.0 (2025-06-01)

- 9-stage causal chain, HTML/PDF report renderer, XAI dashboard.

## v4.2 — Shadow AI Discovery (2025-05-20)

- 18-provider fingerprint DB, async subnet probe, DNS telemetry classifier.

## v4.1 — Post-Quantum Cryptography (2025-05-10)

- HybridSigner (Ed25519+ML-DSA-65), HybridKEM (X25519+ML-KEM-768), liboqs fail-open.

## v4.0 — Agentic SOC (2025-05-01)

- MasterAgent: 4 sub-agents, HMAC task tokens, human-in-the-loop approval gate.
- SOVA tools #29 (Shadow AI scan), #30 (explain decision).

---

## v3.x — WardenHealer + Browser Sandbox (2025-Q1)

- v3.5: Uptime Monitor, SMB Compliance Report.
- v3.3: SOVA `visual_assert_page`, WardenHealer, `ScreencastRecorder`.
- v3.0: SOVA Agent (Claude Opus 4.6), MaskingEngine, AgentMonitor, SIEM integration.

## v2.x — OpenAI Proxy + Shadow Ban (2025-Q1)

- v2.5: DataPoisoningGuard.
- v2.2: Shadow Ban Engine (gaslight/delay/standard differentiation).
- v2.0: PhishGuard + SE-Arbiter, OpenAI-compatible `/v1/chat/completions` proxy,
  LangChain callback, Batch filter endpoint.

## v1.0 — Initial Release (2024-Q4)

- **9-layer Security Pipeline**: TopologicalGatekeeper, ObfuscationDecoder,
  SecretRedactor, SemanticGuard (rule engine), HyperbolicBrain (MiniLM),
  CausalArbiter (Bayesian DAG), ERS (Redis sliding window), EvolutionEngine.
- GDPR hard rule: content never logged.
- Multi-tenant API keys, per-tenant config.
- Streamlit analytics dashboard.
- Docker Compose orchestration (11 services).
- `docs/dpia.md`, `docs/soc2-evidence.md`.
