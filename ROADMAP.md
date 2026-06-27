# Shadow Warden AI — Full Product Roadmap

**Version 7.0 · Last updated 2026-06-27**

Complete feature roadmap organized by product category. Each category tracks what is shipped, what is planned, and the target tier.

Legend: ✅ Shipped · 🔄 In Progress · 📋 Planned · ❌ Cancelled

---

## How We Prioritize

Every item on this roadmap competes across three inputs:

1. **Community Feedback** — security teams using the platform vote on features via the Community Hub. Items with 3+ community votes jump one priority tier automatically.
2. **Threat Signal** — SOVA analytics surfaces emerging attack patterns. When a new jailbreak class or CVE class exceeds a detection threshold, the corresponding pipeline hardening moves to P0 regardless of backlog position.
3. **Enterprise Demand** — direct requests from Enterprise customers with signed contracts. These land in the next sprint if they don't require architectural changes; otherwise they enter the quarterly planning cycle.

We publish an updated priority snapshot every quarter. The `📋 Planned` items below reflect the current ranking; re-ordering happens openly — if something drops, the reason appears in the changelog.

> **Release cadence:** patch versions (4.x.y) ship weekly; minor versions (4.x) ship when a delivery block is complete; major versions (5.0) ship on a quarterly cycle tied to infrastructure milestones.

---

## v7.0 Release — 2026-06-27

| ID | Feature | Status |
|----|---------|--------|
| V7-01 | Agentic Marketplace unified page — Community + Marketplace + Agentic merged at `/agentic`; topology canvas, community search, live feed | ✅ |
| V7-02 | `/community` and `/marketplace` 301 redirects to `/agentic` | ✅ |
| V7-03 | CI mypy gate: relative import fix in `m2m_store/inventory.py`; Pydantic v2 `type: ignore` in `communities/router.py` | ✅ |
| V7-04 | Full test suite: 4305 tests, 81.21% coverage (gate 79%), 0 mypy errors | ✅ |

---

## 1. Security Pipeline — Core Detection Engine

The 9-layer filter that processes every AI request in < 2ms.

| ID | Feature | Version | Tier | Status |
|----|---------|---------|------|--------|
| SP-01 | TopologicalGatekeeper — n-gram point cloud → β₀/β₁ Betti numbers | v1.0 | All | ✅ |
| SP-02 | ObfuscationDecoder — base64/hex/ROT13/Caesar/homoglyphs, depth-3 recursive | v1.0 | All | ✅ |
| SP-03 | SecretRedactor — 15 regex patterns + Shannon entropy for unknown secrets | v1.0 | All | ✅ |
| SP-04 | SemanticGuard (rule engine) — compound risk escalation (3× MEDIUM → HIGH) | v1.0 | All | ✅ |
| SP-05 | HyperbolicBrain — MiniLM + Poincaré ball (70% cosine + 30% hyperbolic) | v1.0 | All | ✅ |
| SP-06 | CausalArbiter — Bayesian DAG, 5 nodes, Pearl do-calculus, backdoor correction | v1.0 | All | ✅ |
| SP-07 | ERS — Redis sliding window reputation, shadow ban at score ≥ 0.75 | v1.0 | All | ✅ |
| SP-08 | EvolutionEngine — Claude Opus auto-rule generation, hot-reload, no restart | v1.0 | All | ✅ |
| SP-09 | PhishGuard + SE-Arbiter — URL phishing + social engineering detection | v2.0 | All | ✅ |
| SP-10 | Shadow Ban Engine — gaslight (`secrets.choice()`, 30+ pool) / delay / standard | v2.2 | All | ✅ |
| SP-11 | DataPoisoningGuard — MiniLM singleton, adversarial suffix stripping | v2.5 | All | ✅ |
| SP-12 | CPT drift gate — rejects calibration shifts >25% from prior | v4.7 | All | ✅ |
| SP-13 | Evolution ReDoS gate — nested-quantifier heuristic + 0.3s degenerate-string timeout | v4.7 | All | ✅ |
| SP-14 | Intel Bridge — ArXiv papers → `synthesize_from_intel()` → hot-reload | v4.13 | Pro+ | ✅ |
| SP-15 | OTel span instrumentation — per-layer spans across all 9 pipeline stages | v4.13 | All | ✅ |
| SP-16 | Batch filter endpoint (`POST /filter/batch`) | v3.0 | All | ✅ |
| SP-17 | OpenAI-compatible proxy (`/v1/chat/completions`) — 400-char fast-scan buffer | v2.0 | All | ✅ |
| SP-18 | GDPR hard rule — content never logged, only metadata (type/length/timing) | v1.0 | All | ✅ |
| SP-19 | Fail-closed auth — startup error if both API key vars unset | v4.7 | All | ✅ |
| SP-20 | Worm Guard — lateral movement detection (agent chain patterns) | v3.5 | Pro+ | ✅ |
| SP-21 | Adaptive OTel sampling — 10% ALLOW / 100% HIGH+BLOCK, tail-sampling Collector | v4.14 | All | ✅ |
| SP-22 | Multi-modal content guard — image prompt injection detection | v4.22 | Pro+ | ✅ |
| SP-23 | Audio/video transcription guard — Whisper pre-scan before LLM | v5.0 | Enterprise | 📋 |
| SP-24 | Fine-tuned ONNX model export — <1ms inference, eliminates MiniLM cold start | v4.21 | All | ✅ |
| SP-25 | Document Intelligence filter hook — `file_base64` + `file_filename` on `FilterRequest`; MarkItDown converts file to Markdown before 9-layer pipeline (fail-open) | v5.4 | All | ✅ |
| SEC-02 | HSM Key Storage Hardening — `rotate_master_key()`, `audit_access()` STIX log, `lock_key()` / `unlock_key()` per-agent (PKCS#11 + SW fallback) | v6.1 | Pro+ | ✅ |
| SEC-03 | Autonomous Threat Response — `AutoResponder.isolate_agent()` + `restore_agent()`, STIX audit, Kafka event, Slack notify; wired into Maestro high-threat path | v6.1 | Pro+ | ✅ |
| SEC-04 | Prompt Injection Defense — 10-regex + delimiter-attack scanner; integrated into `negotiation.py` (`send_offer()`) and `voice/guardian.py` | v6.1 | All | ✅ |
| SEC-05 | Decentralized Key Rotation — `KeyRotationManager.schedule_rotation()` / `complete_rotation()` / `check_overdue()`; `POST /marketplace/agents/{id}/rotate-key` | v6.1 | Pro+ | ✅ |
| SEC-06 | Federated Trust Registry — `FederatedTrustRegistry.share_flag()` / `check_global_deny()` / `expire_flags()`; cross-community deny list; `federated_trust_enabled` gate | v6.1 | Comm.Biz+ | ✅ |
| SEC-07 | Runtime Memory Protection — `secure_wipe()` (ctypes zeroing), `@secure_memory` decorator, `mlock_current()`, `disable_core_dumps()` | v6.1 | All | ✅ |
| SEC-08 | Quantum-Safe Asset Signatures — `sign_asset_hybrid()` / `verify_asset_hybrid()` Ed25519 + ML-DSA-65; `POST /marketplace/assets/{ueciid}/upgrade-signature` | v6.1 | Enterprise | ✅ |
| SEC-09 | Behavioral Anomaly Detector — Z-score per dimension over 30-day baseline; integrated into `MaestroService.run_full_audit()` MaestroReport | v6.1 | Pro+ | ✅ |
| SEC-10 | Data Lifecycle Manager — per-entity TTL registry, ARQ cron `check_expired` daily / `purge_expired` weekly, `POST /admin/data-lifecycle/purge` | v6.1 | Pro+ | ✅ |

---

## 2. Agentic SOC — SOVA, MasterAgent, WardenHealer

Autonomous AI operators that monitor, respond, and self-heal.

| ID | Feature | Version | Tier | Status |
|----|---------|---------|------|--------|
| AG-01 | SOVA Agent — Claude Opus 4.6 agentic loop, ≤10 iterations, Redis memory (6h / 20 turns) | v3.0 | Pro+ | ✅ |
| AG-02 | SOVA tools #1–27 — health, stats, config, CVE triage, key rotation, ArXiv, billing | v3.0 | Pro+ | ✅ |
| AG-03 | SOVA tool #28 — `visual_assert_page` (BrowserSandbox + Claude Vision, in-process) | v3.3 | Pro+ | ✅ |
| AG-04 | SOVA tool #29 — `scan_shadow_ai` (ShadowAIDetector subnet probe, live) | v4.2 | Enterprise | ✅ |
| AG-05 | SOVA tool #30 — `explain_decision` (9-stage causal chain retrieval) | v4.3 | Pro+ | ✅ |
| AG-06 | SOVA tool #31 — `visual_diff` (baseline vs candidate Claude Vision comparison) | v4.11 | Pro+ | ✅ |
| AG-07 | SOVA tools #38–40 — `search_community_feed`, `publish_to_community`, `get_community_recommendations` | v4.15 | Community+ | ✅ |
| AG-08 | SOVA tool #41 — `sync_misp_feed` (MISP REST → EvolutionEngine synthesis) | v4.16 | Pro+ | ✅ |
| AG-09 | SOVA tool #42 — `get_reputation` (community badge + points lookup) | v4.16 | Community+ | ✅ |
| AG-10 | SOVA tools #43–45 — `scan_obsidian_note`, `get_obsidian_feed`, `share_obsidian_note` | v4.17 | Community+ | ✅ |
| AG-11 | MasterAgent — supervisor loop, 4 sub-agents, HMAC tokens, human-in-the-loop | v4.0 | Pro (included) | ✅ |
| AG-12 | MasterAgent sub-agents — SOVAOperator, ThreatHunter, ForensicsAgent, ComplianceAgent | v4.0 | Pro (included) | ✅ |
| AG-13 | MasterAgent batch API — `client.beta.messages.batches` (50% token discount) | v4.7 | Pro+ | ✅ |
| AG-14 | Human-in-the-Loop approval gate — Slack webhook → Redis (1h TTL) → `POST /agent/approve/{token}` | v4.0 | Pro+ | ✅ |
| AG-15 | WardenHealer — circuit breaker, bypass spike, corpus DEGRADED, canary probe | v3.3 | Pro+ | ✅ |
| AG-16 | WardenHealer OLS trend prediction — linear extrapolation, WARN at predicted bypass >15% | v4.11 | Pro+ | ✅ |
| AG-17 | WardenHealer LLM incident classification — Claude Haiku + SQLite recipe cache | v4.11 | Pro+ | ✅ |
| AG-18 | `sova_visual_patrol` — nightly 03:00 UTC, ScreencastRecorder + Redis weight decay | v3.3 | Pro+ | ✅ |
| AG-19 | `sova_obsidian_watchdog` — every 4h, vault integrity check + Slack alert | v4.17 | Community+ | ✅ |
| AG-20 | Prompt caching — SOVA agentic loop with Anthropic cache_control | v3.0 | Pro+ | ✅ |
| AG-21 | SOVA tool #46 — `generate_threat_report` (full PDF/HTML export via XAI renderer) | v4.21 | Pro+ | ✅ |
| AG-22 | SOVA tool #47 — `block_ip_range` (ERS hard block, tenant-scoped) | v4.21 | Enterprise | ✅ |
| AG-23 | MasterAgent sub-agent #5 — DataPrivacyAgent (GDPR ROPA/DPIA, retention, PII governance) | v4.21 | Enterprise | ✅ |
| AG-24 | SOVA memory expansion — vector search (pgvector) over past conversations | v4.22 | Pro+ | ✅ |
| AG-25 | Voice-activated SOC operator — WebRTC audio → Whisper → SOVA → TTS response | v5.0 | Enterprise | 📋 |
| AG-26 | SOVA tool #50 — `scan_document` (base64 file → MarkItDown → full FilterResponse via /filter hook) | v5.4 | Pro+ | ✅ |
| AG-27 | SOVA tool #51 — `get_compliance_report` (live GDPR/SOC2/ISO27001/HIPAA posture + gap list) | v5.5 | Pro+ | ✅ |
| AG-28 | SOVA tool #52 — `remediate_gap` (acknowledge fix, invalidate posture cache, return updated score) | v5.5 | Pro+ | ✅ |
| MO-01 | Mobile SOC App — React Native (iOS + Android), FCM/APNs push alerts for HIGH/BLOCK; alert feed, 9-stage XAI detail, one-tap deep-link; SQLite device registry (50/tenant); `warden/push/` backend; `mobile_push_enabled` Pro+ gate | v5.6 | Pro+ | ✅ |

---

## 3. Community & Collaboration — SEP, Peering, Intelligence

Federated knowledge-sharing between Security Operations teams.

| ID | Feature | Version | Tier | Status |
|----|---------|---------|------|--------|
| CM-01 | UECIID codec — `SEP-{11 base-62}` from 64-bit Snowflake; lexicographic = chronological | v4.6 | Community+ | ✅ |
| CM-02 | UECIID index — SQLite `sep_ueciid_index`, prefix + display name search | v4.6 | Community+ | ✅ |
| CM-03 | Causal Transfer Proof — HMAC-SHA256 signed, tamper-evident, verify endpoint | v4.6 | Community+ | ✅ |
| CM-04 | Sovereign Pod Tags — jurisdiction + data_class per entity; blocks non-compliant transfers | v4.6 | Community+ | ✅ |
| CM-05 | Inter-community peering — HMAC handshake, MIRROR_ONLY/REWRAP_ALLOWED/FULL_SYNC | v4.6 | Community+ | ✅ |
| CM-06 | `transfer_entity()` — TransferRecord + new UECIID in target + CTP proof | v4.6 | Community+ | ✅ |
| CM-07 | Knock-and-Verify invitations — one-time Redis tokens (72h TTL) | v4.6 | Community+ | ✅ |
| CM-08 | Causal Transfer Guard — exfiltration P≥0.70 block in <20ms | v4.7 | Community+ | ✅ |
| CM-09 | PQC Transfer Proof — ML-DSA-65 hybrid signature on CTP (Enterprise keypairs) | v4.7 | Enterprise | ✅ |
| CM-10 | STIX 2.1 Audit Chain — SHA-256 prev_hash, OASIS-compatible JSONL | v4.7 | Community+ | ✅ |
| CM-11 | Sovereign Data Pods — per-jurisdiction MinIO routing, Fernet-encrypted keys | v4.7 | Enterprise | ✅ |
| CM-12 | Community Charter — versioned governance, DRAFT→ACTIVE lifecycle, tamper-evident SHA-256 | v4.8 | Community+ | ✅ |
| CM-13 | Behavioral Anomaly Detection — Z-score over 30-day rolling window, 5 event patterns | v4.8 | Community+ | ✅ |
| CM-14 | Community Intelligence Report — 3-source weighted risk score, SAFE→CRITICAL labels | v4.8 | Community+ | ✅ |
| CM-15 | OAuth Agent Discovery — 14-provider catalog, scope-based risk, ALLOW/MONITOR/BLOCK | v4.8 | Community+ | ✅ |
| CM-16 | SOVA community lookup endpoint (`POST /agent/sova/community/lookup`) | v4.15 | Community+ | ✅ |
| CM-17 | `GET /public/community` — GDPR-safe aggregated stats (members, trend, flags, incidents) | v4.15 | Public | ✅ |
| CM-18 | Reputation system — SQLite points ledger, PUBLISH+5/SEARCH+1/REC_ADOPTED+10/TRUSTED+3 | v4.16 | Community+ | ✅ |
| CM-19 | Badge ladder — NEWCOMER → CONTRIBUTOR → TOP_SHARER → GUARDIAN → ELITE | v4.16 | Community+ | ✅ |
| CM-20 | `GET /public/leaderboard` — anonymised top-10 (no tenant_id) | v4.16 | Public | ✅ |
| CM-21 | Auto-apply recommendations with human-in-the-loop (`POST /agent/sova/community/apply/{ueciid}`) | v4.16 | Pro+ | ✅ |
| CM-22 | Public incident card (`GET /public/incident/{ueciid}`) — XAI chain, GDPR-safe | v4.16 | Public | ✅ |
| CM-23 | SEP REST API — 24 endpoints: UECIID, pod-tags, peerings, knock, pods, audit-chain | v4.7 | Community+ | ✅ |
| CM-24 | `TRUSTED_ENTRY +3` reputation cron — 30-day no-report entries auto-awarded | v4.21 | Community+ | ✅ |
| CM-25 | `SEARCH_HIT +1` reputation — awarded on `search_community_feed` result match | v4.21 | Community+ | ✅ |
| CM-26 | Community threat score federation — broadcast verified verdicts to federated peers | v4.22 | Enterprise | ✅ |
| CM-27 | Community AI model sharing — share fine-tuned detection rules as signed UECIID bundles | v4.22 | Enterprise | ✅ |
| CM-28 | Community SLA contracts — codify data residency + retention commitments in charter | v5.0 | Enterprise | 📋 |
| CM-35 | AI Incident Register — STIX-linked incident journal | v4.25 | Individual+ | 📋 |
| CM-36 | Supplier AI Risk Assessment — 5-criteria peering-based scoring | v4.26 | Community+ | 📋 |
| CM-37 | Shared Prompt Library — UECIID provenance + community sharing | v4.27 | Community+ | 📋 |
| CM-38 | Employee AI Training Records — HMAC attestation + behavioral hooks | v4.28 | Community+ | 📋 |

---

## 4. Integrations — Obsidian, Slack, MISP, LangChain

Connectors that bring Shadow Warden into existing developer and analyst workflows.

| ID | Feature | Version | Tier | Status |
|----|---------|---------|------|--------|
| IN-01 | LangChain callback — `WardenCallback` duck-typed (before/after hooks) | v2.0 | All | ✅ |
| IN-02 | Obsidian note scanner — YAML frontmatter parse, data classification, SecretRedactor | v4.10 | Community+ | ✅ |
| IN-03 | Obsidian plugin v4.10 — ribbon, 5 commands, auto-scan on modify, WardenSettingTab | v4.10 | Community+ | ✅ |
| IN-04 | Obsidian plugin v4.18 — `WardenSidebarView` (ItemView), frontmatter auto-tagging, local PII pre-validation | v4.18 | Community+ | ✅ |
| IN-05 | Obsidian plugin v4.19 — Dataview dashboard, offline queue, XAI pipeline viz, scan scheduler | v4.19 | Community+ | ✅ |
| IN-06 | Obsidian API — 6 endpoints: `/obsidian/scan`, `/share`, `/feed`, `/ai-filter`, `/reputation`, `/stats` | v4.17 | Community+ | ✅ |
| IN-07 | Slack slash command handler — `POST /slack/command`, HMAC-SHA256 verification, Block Kit | v4.17 | Pro+ | ✅ |
| IN-08 | Slack Obsidian alerts — `alert_obsidian_event()` fires on HIGH/BLOCK scan + UECIID share | v4.17 | Community+ | ✅ |
| IN-09 | MISP connector — `MISPConnector.sync()`, 14 IoC types → EvolutionEngine synthesis | v4.16 | Pro+ | ✅ |
| IN-10 | MISP admin endpoint (`POST /agent/misp/sync`) | v4.16 | Pro+ | ✅ |
| IN-11 | SOVA `sova_obsidian_watchdog` — vault integrity check every 4h | v4.17 | Community+ | ✅ |
| IN-12 | Shadow AI syslog sink — UDP listener for dnsmasq/BIND9/Zeek DNS events | v4.7 | Enterprise | ✅ |
| IN-13 | Browser extension — popup with scan button, verdict badge, UECIID display | v4.11 | Community+ | ✅ |
| IN-14 | VS Code extension — inline risk annotation on selected text | v4.22 | Individual+ | ✅ |
| IN-15 | GitHub Actions integration — CI gate scans commit message + per-file diff (30 files, 93 controls), PR comment, 90-day audit artifact, composite action, pre-commit hook mode | v5.3 | Pro+ | ✅ |
| IN-16 | Jira integration — auto-create security tickets on HIGH/BLOCK verdicts | v4.21 | Pro+ | ✅ |
| IN-17 | Microsoft Teams slash command — Adaptive Card via webhook, `/warden` for Teams | v4.21 | Pro+ | ✅ |
| IN-18 | Notion integration — scan Notion pages via API, write risk tags as properties | v4.21 | Community+ | ✅ |
| IN-19 | STIX/TAXII feed consumer — ingest external threat intel from any TAXII 2.1 server | v4.22 | Enterprise | ✅ |
| IN-20 | Zapier / Make connector — webhook trigger + filter action blocks | v4.21 | Individual+ | ✅ |
| IN-21 | OpenTelemetry SDK library — `WardenSpanProcessor` for any OTel-enabled app | v4.21 | Pro+ | ✅ |
| IN-22 | MISP syslog bridge — ZMQ SUB socket + HTTP poll fallback, topic `misp_json` | v4.21 | Pro+ | ✅ |
| IN-25 | SMB AI Governance Suite — single-wizard provisioning of all 7 modules | v4.29 | Community+ | ✅ |
| CM-39 | Business Intelligence Module — 8-category analytics: usage, threats, vendors, costs, compliance, benchmarks, predictions, reports | v4.30 | Community+ | ✅ |
| SDK-01 | Public Node.js / TypeScript SDK — `@shadow-warden/sdk`, 5 resource classes (Community, Marketplace, Compliance, Semantic, Documents), zero runtime deps, Vitest tests | v5.6 | All | ✅ |
| ONB-01 | AI-Assisted Onboarding Wizard — 5-step guided setup (Community → Members → Marketplace → Compliance → Integrations), Redis-backed sessions, SOVA tools #53–55, Streamlit page 25 | v5.6 | All | ✅ |

---

## 5. Compliance & Privacy — GDPR, Secrets, Sovereign AI

Everything needed for regulated industries (GDPR, SOC 2, HIPAA, ISO 27001).

| ID | Feature | Version | Tier | Status |
|----|---------|---------|------|--------|
| CP-01 | GDPR Art. 35 DPIA (`docs/dpia.md`) — full impact assessment | v2.0 | All | ✅ |
| CP-02 | GDPR Art. 17 purge API — `purge_before(ts)` + `read_by_request_id()` | v4.13 | All | ✅ |
| CP-03 | GDPR auto-retention ARQ cron — daily 02:00 UTC | v4.13 | All | ✅ |
| CP-04 | SOC 2 Type II evidence guide (`docs/soc2-evidence.md`) — control mapping | v3.0 | Pro+ | ✅ |
| CP-05 | SMB Compliance Report — PDF/JSON with OWASP LLM Top 10 coverage | v3.5 | Community+ | ✅ |
| CP-06 | Secrets vault connectors — AWS SM / Azure KV / HashiCorp / GCP SM / env (metadata-only) | v4.9 | Community+ | ✅ |
| CP-07 | Secrets inventory — SQLite-backed, risk scoring 0–100, auto-retire | v4.9 | Community+ | ✅ |
| CP-08 | Secrets policy engine — 7 violation rules, compliance score 0–100 | v4.9 | Community+ | ✅ |
| CP-09 | Secrets lifecycle manager — expiry alerts, auto-retire, rotation scheduling | v4.9 | Community+ | ✅ |
| CP-10 | Secrets REST API — 14 endpoints at `/secrets/*` | v4.9 | Community+ | ✅ |
| CP-11 | Secrets Governance Streamlit dashboard — 6-tab UI | v4.9 | Community+ | ✅ |
| CP-12 | Sovereign AI Cloud — 8 jurisdictions (EU/US/UK/CA/SG/AU/JP/CH) | v4.4 | Enterprise | ✅ |
| CP-13 | MASQUE tunnels — MASQUE_H3/H2/CONNECT_TCP with TOFU TLS pinning | v4.4 | Enterprise | ✅ |
| CP-14 | Per-tenant routing policy — BLOCK/DIRECT fallback, data-class overrides | v4.4 | Enterprise | ✅ |
| CP-15 | Sovereignty attestation — HMAC-SHA256 signed, 7-year Redis TTL | v4.4 | Enterprise | ✅ |
| CP-16 | STIX 2.1 audit chain — SHA-256 prev_hash, OASIS-compatible, SIEM import | v4.7 | Community+ | ✅ |
| CP-17 | Transfer rules matrix — CLASSIFIED never; PHI US/EU/UK/CA/CH only | v4.4 | Enterprise | ✅ |
| CP-18 | MaskingEngine — Fernet-encrypted PII vault, HMAC-SHA256 reverse map | v3.0 | All | ✅ |
| CP-19 | AgentMonitor — INJECTION_CHAIN detection, cryptographic attestation | v3.0 | Pro+ | ✅ |
| CP-20 | OTel GDPR span rules — raw content, PII, secrets prohibited on spans (Rule.md §21) | v4.13 | All | ✅ |
| CP-21 | Uptime Monitor — HTTP/SSL/DNS/TCP probes, TimescaleDB hypertable | v3.5 | Community+ | ✅ |
| CP-22 | ISO 27001:2022 Annex A control mapping — 93 controls across 4 themes (Org/People/Physical/Tech), per-theme coverage %, HTML report, Streamlit page, SOC dashboard drilldown | v5.3 | Enterprise | ✅ |
| CP-23 | HIPAA technical safeguards attestation (encryption, audit, access control) | v4.21 | Enterprise | ✅ |
| CP-24 | NIS2 Directive compliance report | v4.21 | Enterprise | ✅ |
| CP-25 | Continuous compliance scoring dashboard — 30s auto-refresh, 168-snapshot ring buffer, 5-standard SVG gauge, timeline chart, Streamlit + SOC dashboard pages | v5.3 | Pro+ | ✅ |
| CP-26 | Data retention policy enforcement — tenant-configurable per data_class TTL | v4.21 | Community+ | ✅ |
| CP-30 | Real-time Compliance Gap Dashboard — `CompliancePostureService` aggregates 19 controls (GDPR/SOC2/ISO27001/HIPAA) from Vendor Gov + Incidents + Secrets + Doc Intel + STIX + Training; per-gap remediation guidance; Redis cache (5min); Pub/Sub invalidation; WebSocket `/compliance/ws`; 4 new endpoints; portal self-service page; Streamlit 5-tab gap manager; SOVA tools #51 + #52 | v5.5 | Pro+ | ✅ |

---

## 6. Cryptography — PQC, Attestation, Key Management

Quantum-resistant and classical cryptographic foundations.

| ID | Feature | Version | Tier | Status |
|----|---------|---------|------|--------|
| CR-01 | HybridSigner — Ed25519 (64B) + ML-DSA-65 (3309B), FIPS 204, liboqs fail-open | v4.1 | Enterprise | ✅ |
| CR-02 | HybridKEM — X25519 + ML-KEM-768, HKDF-SHA256(XOR) shared secret, FIPS 203 | v4.1 | Enterprise | ✅ |
| CR-03 | CryptoBackend hot-swap — v1 (classical) / v2-hybrid (PQC), kid suffix "-hybrid" | v4.1 | Enterprise | ✅ |
| CR-04 | `upgrade_to_hybrid()` — zero-downtime keypair upgrade for existing communities | v4.1 | Enterprise | ✅ |
| CR-05 | Community keypair — classical Ed25519 default; `generate_community_keypair(pqc=True)` | v3.0 | Community+ | ✅ |
| CR-06 | Sovereignty attestation HMAC — `SOVEREIGN_ATTEST_KEY` → fallback `VAULT_MASTER_KEY` | v4.4 | Enterprise | ✅ |
| CR-07 | VAULT_MASTER_KEY validation — Fernet key validated at boot (fail with clear error) | v4.7 | All | ✅ |
| CR-08 | Per-tenant API keys — JSON multi-key + SHA-256 hash lookup, constant-time compare | v2.0 | All | ✅ |
| CR-09 | Causal Transfer Proof HMAC — canonical string, `verify_transfer_proof()` | v4.6 | Community+ | ✅ |
| CR-10 | PQC Transfer Proof — ML-DSA-65 signature on CTP, both HMAC and PQC must pass | v4.7 | Enterprise | ✅ |
| CR-11 | MasterAgent HMAC task tokens — `(sub_agent:task_hash:ts:sig)` per delegated task | v4.0 | Pro+ | ✅ |
| CR-12 | Knock token — Redis `sep:knock:{hmac_hash}` (72h TTL), one-time use | v4.6 | Community+ | ✅ |
| CR-13 | ML-KEM-1024 upgrade path (FIPS 203 Level 5, `CRYPTO_KEM_ALGO` env var) | v4.21 | Enterprise | ✅ |
| CR-14 | HSM integration — PKCS#11 bridge for sovereign key material | v4.22 | Enterprise | ✅ |
| CR-15 | Certificate-pinned MASQUE tunnels — `ca_cert_pem` TLS full-chain verification | v4.21 | Enterprise | ✅ |

---

## 7. Infrastructure & DevOps

Everything from Docker orchestration to CI/CD to Kubernetes.

| ID | Feature | Version | Tier | Status |
|----|---------|---------|------|--------|
| IF-01 | 11-service Docker Compose — proxy, warden, app, analytics, dashboard, postgres, redis, prometheus, grafana, minio, minio-init | v2.0 | All | ✅ |
| IF-02 | Caddy v2 reverse proxy — hostname-based routing, HSTS, QUIC/HTTP3, `caddy-data` volume | v4.7 | All | ✅ |
| IF-03 | Helm chart — shadow-warden namespace, OTel + otelCollector values | v3.0 | Enterprise | ✅ |
| IF-04 | OTel Collector pipeline — gRPC exporter + Jaeger backend | v4.13 | All | ✅ |
| IF-05 | Adaptive OTel sampling — 10% ALLOW / 100% HIGH+BLOCK, Collector tail-sampling | v4.14 | All | ✅ |
| IF-06 | ARQ worker — 10 cron jobs, Redis-backed, `WorkerSettings` | v3.0 | All | ✅ |
| IF-07 | Named Docker volume `warden-models` — persists ONNX model across rebuilds | v4.13 | All | ✅ |
| IF-08 | Playwright MCR base image — `mcr.microsoft.com/playwright/python:v1.49.0-noble`, non-root UID 10001 | v3.3 | Pro+ | ✅ |
| IF-09 | MinIO Evidence Vault — `warden-evidence/bundles/` + `warden-logs/` + `screencasts/` | v2.0 | Pro+ | ✅ |
| IF-10 | CI matrix — Python 3.11/3.12, ruff, mypy, Docker smoke Phase 1+2, ML model cache | v2.0 | — | ✅ |
| IF-11 | CI: Trivy CVE scan — CRITICAL/HIGH, SARIF → GitHub Security tab | v4.14 | — | ✅ |
| IF-12 | CI: k6 smoke test — 1 VU, 30s, `api.shadow-warden-ai.com` post-deploy | v4.14 | — | ✅ |
| IF-13 | CI: pip-audit SCA — Python dependency CVE scan, 30-day artifact | v4.14 | — | ✅ |
| IF-14 | CI: JUnit test reports — `dorny/test-reporter@v1` publishes per-test pass/fail | v4.14 | — | ✅ |
| IF-15 | CI: Slack deploy notify — ✅/🚨 attachment with commit SHA + actor + run URL | v4.14 | — | ✅ |
| IF-16 | CI: `--no-cache` pre-build for admin + arq-worker (layer corruption guard) | v4.13 | — | ✅ |
| IF-17 | GitHub Actions autodeploy — SSH deploy to Hetzner VPS | v4.11 | — | ✅ |
| IF-18 | py-spy profiling + k6 load harness (`scripts/profile_under_load.sh`) | v4.13 | — | ✅ |
| IF-19 | Kubernetes horizontal pod autoscaler for warden + dashboard services | v4.22 | Enterprise | ✅ |
| IF-20 | Multi-region active-active deployment (EU + US) — X-Region middleware, `docs/multi-region.md`, sovereign tunnel integration | v6.2 | Enterprise | ✅ |
| IF-21 | cosign + SBOM CI signing on Docker images | v4.13 | — | ✅ |
| IF-22 | Mutation testing — mutmut on `secret_redactor.py` + `semantic_guard.py` | v2.0 | — | ✅ |
| IF-23 | CI: Docker Scout CVE scan gated behind `DOCKER_SCOUT_ENABLED` Actions repo variable — eliminates "not entitled" auth noise on free-tier runners; set to `true` to re-enable | v6.9 | — | ✅ |
| INFRA-01 | Preflight checks for MASQUE tunnels + RPC node validation before escrow deployment | v5.6 | Enterprise | ✅ |
| PERF-01 | Async event logging — `event_logger.append()` via `BackgroundTask`; removes file I/O + lock from hot `/filter` path (5–20ms gain) | v6.6 | All | ✅ |
| PERF-02 | Redis socket timeout tuning — connect 5s / read 3s in `cache.py`; reduces false cache-miss cascades under load | v6.6 | All | ✅ |
| PERF-03 | Docker `stop_grace_period: 30s` + healthcheck retries 15→5 on warden service | v6.6 | All | ✅ |
| PERF-04 | Remove root `package.json` workspace — portal + dashboard are standalone npm projects; eliminates npm v10 workspace-detection breakage in CI | v6.6 | — | ✅ |

---

## 8. Observability & Monitoring

Dashboards, metrics, tracing, and alerting across all layers.

| ID | Feature | Version | Tier | Status |
|----|---------|---------|------|--------|
| OB-01 | Prometheus metrics — 20+ counters/histograms (filter, shadow ban, ERS, cost saved) | v2.0 | All | ✅ |
| OB-02 | Grafana SLO alerts — P99 latency, 5xx rate, availability, shadow ban rate, corpus drift | v2.0 | All | ✅ |
| OB-03 | Grafana multi-window burn-rate alerts — fast (1h+5min, 14.4×) + slow (6h+30min, 6×) | v4.14 | All | ✅ |
| OB-04 | SIEM integration — Splunk HEC + Elastic ECS export | v2.5 | Pro+ | ✅ |
| OB-05 | NDJSON analytics logger — atomic writes, GDPR-safe (metadata only) | v1.0 | All | ✅ |
| OB-06 | Streamlit analytics dashboard (`:8501`) — 6-page analytics + settings | v2.0 | All | ✅ |
| OB-07 | Uptime Monitor — HTTP/SSL/DNS/TCP probes, TimescaleDB continuous aggregate | v3.5 | Community+ | ✅ |
| OB-08 | OTel distributed tracing — Jaeger 1.58, per-layer spans in all 9 stages | v4.13 | All | ✅ |
| OB-09 | XAI causal chain — 9-stage DAG, primary cause, counterfactuals, HTML+PDF report | v4.3 | Pro+ | ✅ |
| OB-10 | XAI REST API — `/xai/explain`, `/batch`, `/report/{id}`, `/pdf`, `/dashboard` | v4.3 | Pro+ | ✅ |
| OB-11 | XAI add-on gate — +$9/mo (Individual+) for PDF reports | v4.5 | Individual+ | ✅ |
| OB-12 | Financial Impact Calculator — IBM 2024 benchmarks, industry multipliers, ASCII report | v3.0 | All | ✅ |
| OB-13 | Dollar impact REST API — `/financial/impact`, `/cost-saved`, `/roi`, `/generate-proposal` | v3.0 | All | ✅ |
| OB-14 | Shadow AI discovery REST API — `/shadow-ai/scan`, findings, report, policy | v4.2 | Enterprise | ✅ |
| OB-15 | Shadow AI syslog DNS classifier — dnsmasq/BIND9/Zeek UDP listener | v4.7 | Enterprise | ✅ |
| OB-16 | Community Intel REST API — charter, anomalies, OAuth, intelligence report | v4.8 | Community+ | ✅ |
| OB-17 | Public community dashboard — Astro, SVG chart, 60s auto-refresh | v4.15 | Public | ✅ |
| OB-18 | Public incident page — anonymised XAI chain, GDPR notice, CTA | v4.16 | Public | ✅ |
| OB-19 | SOC Next.js dashboard (`:3002`) — 8 pages, TanStack Query, Recharts | v4.13 | All | ✅ |
| OB-20 | SOC dashboard auth gate — Next.js edge middleware, httpOnly cookie, 8h TTL | v4.14 | All | ✅ |
| OB-21 | Community Defense Widget — live SEP feed + SOVA search (Overview page) | v4.16 | Community+ | ✅ |
| OB-22 | Community Recommendations block — Event Detail page, blocked events only | v4.16 | Community+ | ✅ |
| OB-23 | Anomaly timeline Streamlit dashboard (Page 4 — Community Behavioral tab) | v4.8 | Community+ | ✅ |
| OB-24 | Threat intelligence Streamlit (Page 2 — Threat Radar + Intel Bridge + Causal Arbiter) | v4.13 | Pro+ | ✅ |
| OB-25 | AI-generated weekly ROI email — ARQ cron, Friday 08:00 UTC, Pro+ tenants | v3.0 | Pro+ | ✅ |
| OB-26 | Real-time anomaly WebSocket stream — push XAI events to dashboard without polling | v4.22 | Pro+ | ✅ |
| OB-27 | Grafana unified dashboard for all 11 services | v4.21 | All | ✅ |
| OB-28 | Mobile SOC app — React Native, push alerts for HIGH/BLOCK verdicts | v5.0 | Pro+ | 📋 |

---

## 9. Frontend & Product Surfaces

All customer-facing web surfaces: landing, portal, dashboards, extensions.

| ID | Feature | Version | Tier | Status |
|----|---------|---------|------|--------|
| FE-01 | Landing pages — 33 HTML pages with accessibility widget | v1.0 | Public | ✅ |
| FE-02 | Astro site (`shadow-warden-ai.com`) — marketing, community, incident pages | v3.0 | Public | ✅ |
| FE-03 | Tenant portal (`app.shadow-warden-ai.com`) — Next.js 14, API hub, communities | v3.0 | All | ✅ |
| FE-04 | SOC Next.js dashboard (`dash.shadow-warden-ai.com`) — 8-page SPA | v4.13 | All | ✅ |
| FE-05 | Redoc API docs (`docs.shadow-warden-ai.com`) — always-public OpenAPI schema | v4.14 | Public | ✅ |
| FE-06 | Accessibility widget — WCAG 2.1 AA, Section 508, EN 301 549, ADA | v4.11 | All | ✅ |
| FE-07 | Browser extension — popup, scan button, verdict badge, UECIID | v4.11 | Community+ | ✅ |
| FE-08 | Obsidian plugin — sidebar, 5 commands, XAI viz, Dataview dashboard | v4.19 | Community+ | ✅ |
| FE-09 | Streamlit analytics dashboard — 6 pages, 6-tab Secrets Governance | v4.9 | All | ✅ |
| FE-10 | Community public dashboard — animated KPIs, SVG bar chart, 60s refresh | v4.15 | Public | ✅ |
| FE-11 | Settings HTML panel — SOVA + MasterAgent configuration tabs | v4.11 | Pro+ | ✅ |
| FE-12 | SOC dashboard DNS A record (`dash.shadow-warden-ai.com → 91.98.234.160`) | v4.20 | — | ✅ |
| FE-13 | Analytics API live endpoints in SOC dashboard (replace mock/placeholder data) | v4.21 | All | ✅ |
| FE-14 | Mobile-responsive SOC dashboard | v4.21 | All | ✅ |
| FE-15 | Onboarding flow — guided 5-step setup wizard for new tenants | v4.22 | All | ✅ |
| FE-16 | Dark/light theme toggle in portal and SOC dashboard | v4.21 | All | ✅ |
| FE-17 | `shadow-warden-ai.com/pricing` — interactive tier comparison + add-on calculator | v4.20 | Public | ✅ |
| FE-18 | Community & Tunnel 7-page Astro SPA — view / members / tunnel / integrations / activity / settings / new | v4.20 | Community+ | ✅ |
| FE-19 | Community member roles — Owner / Admin / Member, `normalizeMember()` backward-compat, role badges | v4.20 | Community+ | ✅ |
| FE-20 | Community join request system — pending approval flow, Approve / Decline on members page | v4.20 | Community+ | ✅ |
| FE-21 | E2EE key simulation — AES-256-GCM tunnel labels, SW-PUB keypair on creation, fingerprint, .asc export | v4.20 | Community+ | ✅ |
| FE-22 | Community & member search — live name/ID filter on `/community`, role/ID filter on `/community/members` | v4.20 | Community+ | ✅ |
| FE-23 | GDPR Art. 20 community export — JSON download in Settings, private key excluded | v4.20 | Community+ | ✅ |
| FE-24 | Community audit log — Activity tab, activityLog[], 15+ event icons, owner-only Clear Log | v4.20 | Community+ | ✅ |
| FE-25 | Disappearing messages — 24h auto-delete toggle in tunnel, persisted per-community | v4.20 | Community+ | ✅ |
| FE-26 | Castle logo PNG — Shadow-Warden-AI castle on all 40 pages, og:image + favicon | v4.20 | Public | ✅ |
| FE-27 | Agentic Commerce (UCP/AP2/MCP) — multi-agent procurement, FIDO2 passkeys, Web3 mandates | v5.0 | Community+ | ✅ |
| FE-42 | Semantic Layer (Headless BI) — metric contracts, deterministic SQL, AI query via Claude Haiku | v5.1 | Pro+ | ✅ |
| FE-43 | Settings Hub — unified Agents/Notifications/Commerce/Semantic config; Streamlit + Portal + SOC | v5.1 | All | ✅ |
| FE-44 | Site v5.1 refresh — 15-layer badge, WhatsNew section, /roadmap page with JS filters | v5.1 | Public | ✅ |
| FE-47 | AI Analytics Hub — 9 semantic models, Redis cache, SOVA tools, /analytics landing page | v5.2 | Pro+ | ✅ |
| FE-48 | Commerce Budget Guardian — Semantic Layer-backed AP2 pre-flight check | v5.2 | Community+ | ✅ |
| FE-49 | Self-Service Catalog — tenant model registration, SQLite persistence, hot-reload | v5.2 | Pro+ | ✅ |
| SEM-02 | Full Marketplace Semantic Layer — 10 domain models (listings/trades/escrow/negotiations/reputation/governance/agents/assets/flags/cross-chain), flat analytics tables, tenant-isolated SQL | v6.8 | All | ✅ |
| FE-50 | Document Intelligence (MarkItDown) — PDF/DOCX/PPTX/XLSX/audio/image → Markdown + 9-layer scan, Redis cache, `file_base64` filter hook, `/document-intel` API (5 endpoints), Streamlit scanner page | v5.4 | Community+ | ✅ |
| FE-51 | Marketplace Intelligence Charts — two live Chart.js panels on `marketplace.astro`: First-Proposal Bias doughnut (single vs multiple candidates) + Model Tier doughnut (Haiku/Sonnet/Opus distribution + cost-savings pill); `AbortController` 3s timeout, fail-open demo data, `destroy()` before recreate, `Promise.all` parallel fetch, 60s auto-refresh | v6.9 | All | ✅ |
| CM-51 | Community Hub — 11-category federated collaboration platform: community CRUD (32-char SHA-256 ID), Ed25519 member keypairs, shared data pods (UECIID provenance), Document Intelligence scan, MASQUE peering, network federation (meta-communities), BI analytics, per-community compliance (5-control), HTML report export, AI evolution rule sharing with human-in-the-loop approval; unified `/communities` router (38 endpoints), Streamlit 6-tab page `22_Community_Hub.py`, 27 tests | v5.6 | Community Business+ | ✅ |
| CM-52 | Community Hub Actions — delete community (owner only, inline confirmation), remove individual member (toggle guard), file upload from computer (`st.file_uploader` + context notes, multipart), community description/name editing (`PATCH /communities/{id}`), 7-tab Streamlit Hub, danger-zone UI; `context` column on `community_files` table (auto-migration) | v5.6 | Community Business+ | ✅ |
| CM-53 | SOC Dashboard Community Hub — list page (4 StatCards + community grid sorted desc by `created_at`); 6-tab detail (Overview/Members/Data/Compliance/Evolution/Analytics); `useCommunityWebSocket` hook with live-metrics banner + green/red `WsStatus` indicator + 30s auto-reconnect; members sorted desc by `joined_at`; dates in `dd/mm/yy` | v5.6 | Community Business+ | ✅ |
| CM-54 | Portal Community Hub UX — `react-hot-toast` notifications on all community actions (create/delete community, invite/remove member, upload, edit description); `fmtDateShort()` dd/mm/yy across list + members tab; descending sort by `created_at`/`joined_at`; `<Toaster>` in layout | v5.6 | Community Business+ | ✅ |
| MKT-05 | Advanced Reputation & Trust Graph — `TrustGraph` (networkx PageRank damping=0.85, pure-Python fallback); `SybilGuard` (circular trade detection, volume z-score, Redis flag TTL 72h); 5-component reputation formula (completed_rate×0.50 + volume×0.15 + dispute×0.10 + trust_rank×0.15 + sybil×0.10); `GET /marketplace/agents/{id}/trust`; Sybil 403 gate on listing creation; Streamlit Trust Graph + Sybil Flags tabs; 30 tests | v6.0 | Community+ | ✅ |
| MKT-06 | Public SDK (`@shadow-warden/sdk` v1.0.0) — renamed from `shadow-warden-client`; `client.marketplace` namespace (`agents.list/register/getTrust`, `listings.list/create/purchase`, `stats()`); `client.agent()` SOVA query; `client.health()`; exponential-backoff retry on 429/5xx (`RetryConfig`); 43 tests (27 existing + 16 marketplace); TypeScript CJS+ESM+dts | v6.0 | All | ✅ |
| MKT-07 | Community DAO Governance — `GovernanceService` (SQLite `dao_proposals`+`dao_votes`); 3 proposal types (`dispute_resolution`, `parameter_change`, `agent_block`); weighted voting (TrustRank×100, min 1); quorum 15%; 72h TTL; `DAO_GOVERNANCE_ENABLED` flag; escrow auto-creates DAO proposal on `raise_dispute`; `resolve_dispute` blocked when active proposal exists; 5 REST endpoints at `/marketplace/proposals`; Streamlit Governance tab (proposals table + vote progress + Create/Vote/Execute forms); 12 tests | v6.0 | Community Business+ | ✅ |
| MKT-08 | Cross-chain Escrow — multi-chain support for Sepolia, Polygon Amoy, Arbitrum Sepolia; `warden/web3/chains.py` (`CHAINS` dict, `VALID_CHAINS`, `get_chain()`, `chain_label()`); `warden/web3/smart_contract.py` (`deploy_escrow()` returns `address:chain` suffix, `strip_chain_suffix()`, `call_escrow()`); `chain` field on `Listing` + `Escrow` dataclasses; backward-compat `_migrate_chain_column()`; `chain` param on `publish_listing()`, `create_escrow()`, `ListingCreateRequest`, `EscrowCreateRequest`; Streamlit Escrow Monitor tab with chain filter + distribution chart; `SEPOLIA_RPC_URL` / `POLYGON_AMOY_RPC_URL` / `ARBITRUM_SEPOLIA_RPC_URL` env vars; 12 tests | v6.0 | Community+ | ✅ |
| MKT-09 | MAESTRO Threat Detection — multi-layer M2M security: `GoalMisalignmentDetector` (z-score analysis vs community goals, >2σ flag); `CollusionDetector` (negotiation pair tracking, flag ≥60% suspicious pairs with <2 rounds + <5% price delta); `ModelPoisoningDetector` (3σ outlier detection on rule features from community baseline); `MaestroService` aggregator with `run_full_audit()` + `get_maestro_penalty()`; `ReputationEngine` v3 formula adds `maestro_factor×0.10`; `AssetImporter` poisoning gate sets `pending_review` status + Slack alert; `GET /marketplace/agents/{id}/maestro-report` + `GET /marketplace/maestro/flags`; 3 Prometheus counters; Streamlit MAESTRO Threats tab in 23_Marketplace_Admin.py; SOC Dashboard trust page MAESTRO alerts section; 20+ pytest tests | v6.5 | Enterprise | ✅ |
| MKT-10 | Kafka/Flink Event Streaming — `KafkaEventBus` (aiokafka producer/consumer, Redis pub/sub fallback, fail-open); `FlinkAgentRunner` stateful stream processor (marketplace.escrow + marketplace.listings topics, per-community Redis state, `_watchdog_loop()` auto-dispute for timed-out funded escrows every 5 min); `get_event_bus()` + `get_runner()` singletons; `GET /streams/health`, `POST /streams/topics/{topic}/replay`, `GET /streams/communities/{id}/state`; `STREAMS_EVENTS_TOTAL` Prometheus counter; `streams_enabled` feature gate (Pro+); `event_streaming_pack` add-on $19/mo; 11 pytest tests | v6.6 | Pro+ | ✅ |
| MKT-11 | Agent Tokenomics / WAT ERC-20 — `AgentToken` dual-rail (Web3.py on-chain Polygon Amoy + Redis simulation via `WAT_SIMULATE=true`); `mint()`, `transfer()`, `balance_of()` with `_WAT_UNIT=10**18` decimals; `OutcomePricingService` (SQLite `outcome_listings`, KPI-gated settlement `final_price = base_price × min(achieved/target, 1.0)`, WAT auto-transfer); 5 REST endpoints at `/tokenomics/*`; `WAT_TRANSFERS_TOTAL` Prometheus counter; `tokenomics_enabled` feature gate (Enterprise); `agent_tokenomics_pack` add-on $39/mo; 10 pytest tests | v6.6 | Enterprise | ✅ |
| MKT-12 | USDC Multi-Rail Payments — `USDCService` (`PaymentIntent` dataclass, create intent + Redis TTL, `verify_payment()` Coinbase Commerce or on-chain USDC, simulation auto-confirm first call via `USDC_SIMULATE=true`); `_create_coinbase_charge()` (Coinbase Commerce API key); per-chain singleton `get_usdc_service(chain)`; 2 REST endpoints at `/payments/usdc/*`; `USDC_INTENTS_TOTAL` Prometheus counter; `usdc_payments_enabled` feature gate (Enterprise); `usdc_payments_pack` add-on $29/mo; 8 pytest tests | v6.6 | Enterprise | ✅ |
| MKT-13 | ANS Certificate Authority — `CertificateAuthority` (X.509 with `cryptography` library, JSON synthetic fallback); `issue_agent_certificate()` (subject CN `agent-{id}.{community}.shadow-warden.ai`, Ed25519 CA key, SQLite `ans_certificates`); `revoke_certificate()` (DB flag + Redis CRL set `ans:crl:{community_id}`); `verify_certificate()` (chain + revocation + expiry checks); `get_agent_certificate()`; `get_ca()` singleton; 4 REST endpoints at `/marketplace/agents/{id}/certificate` + `/certificates/verify`; `ANS_CERTS_ISSUED_TOTAL` + `ANS_CERTS_REVOKED_TOTAL` Prometheus counters; `ans_certificates_enabled` gate (Enterprise); `ans_certificate_pack` add-on $25/mo; 10 pytest tests | v6.6 | Enterprise | ✅ |
| MKT-14 | ARC Edge Agent Packs — `EdgeAgentPack` ABC with `@register` decorator, global `_REGISTRY`; 3 concrete packs: `CropHealthMonitor` (NDVI/red-edge/soil-moisture → health_score + stress_level + chlorophyll_index); `YieldOptimizer` (soil/temp/humidity/crop_type → evapotranspiration + irrigation_schedule + yield_risk via Penman–Monteith); `DiseaseDetector` (Claude Vision or NDVI heuristic → severity + detected_issues + area_affected_pct); `list_packs()`, `get_pack()`, `validate_sensors()`; `GET /agents/packs`, `POST /agents/packs/{name}/deploy`, `POST /agents/packs/{name}/analyze`; `EDGE_PACK_ANALYZE_TOTAL` Prometheus counter; `edge_packs_enabled` gate (Pro+); `edge_agent_packs` add-on $15/mo; 17 pytest tests | v6.6 | Pro+ | ✅ |
| BGA-01 | Brand Agent (seller-side gateway) — `BrandAgentFilter` 4-gate sequential filter: (1) federation deny-list (SHA-256 DID hash via `check_threat_hash()`); (2) TrustRank gate (`BRAND_AGENT_MIN_TRUST=0.0` default disables until reputation data exists); (3) Redis sliding-window rate limit (`BRAND_AGENT_MAX_RPM=60` req/min per DID, sorted-set pattern, skipped for `REDIS_URL=memory://`); (4) capability gate (`marketplace_buy` required). `FilterVerdict` dataclass. All gates fail-open. `warden/marketplace/brand_agent.py` | v6.8 | Pro+ | ✅ |
| TDB-01 | Three-Layer Context DB — Layer 1: Redis+SQLite session; Layer 2: `AgentHandoffMemory` (~50-token JSON summaries, ~61% token savings, Redis primary + SQLite fallback, `compact_prompt()`, configurable TTL); Layer 3: pgvector MiniLM-384 semantic search + SQLite LIKE fallback when `MARKETPLACE_VECTOR_SEARCH=false`. SOVA tools #70–74: `write_handoff_memory`, `read_handoff_memory`, `semantic_listing_search`, `get_protocol_schema`, `send_order_proposal`. `warden/marketplace/memory.py` + `vector_search.py` | v6.8 | Pro+ | ✅ |
| MKT-15 | M2M 4-Stage Lifecycle Protocol — Stage 1: DID registration + `GET /marketplace/protocol` (`X-Protocol-Version: 1.1`, `Cache-Control: max-age=300`) + `GET /marketplace/protocol/schema/{action}` (7 JSON Schemas for agent payload validation). Stage 2: semantic search via Layer 3 pgvector. Stage 3: Brand Agent 4-gate filter on all seller-facing actions (`send_proposal`, `send_message`, `send_offer`, `negotiate`, `buy`). Stage 4: `POST /marketplace/clear` — `ClearingEngine` auto-rejects non-winner negotiations (`cleared_by_market`), dual-writes SQLite (sync) + PostgreSQL (async via asyncpg, fail-open). 14 action types in unified `POST /marketplace/action` dispatcher. `warden/marketplace/clearing.py`. 71 marketplace tests | v6.8 | Pro+ | ✅ |
| MKT-16 | First-Proposal Bias Guard + Confused Deputy Protection — `BuyerAgent.search_and_buy()` enforces `MARKETPLACE_MIN_OFFERS_BEFORE_BUY=3` minimum alternatives; ranks by `price × (1 − rep_score)` utility function (not arrival order); prevents latency-race market collapse. `POST /marketplace/analytics/query` scopes all SQL to `caller_agent_id` DID via `_confused_deputy_check()`; rejects queries referencing foreign agent DIDs | v6.8 | Community+ | ✅ |
| MKT-17 | Dynamic Model Router — `warden/marketplace/model_router.py`; 4-factor complexity scoring: `action_type` base weight (0.10–0.80) + payload length (+0–0.20) + round_count (+0–0.15) + MAESTRO risk (+0.00/+0.10/+0.25); routes to Haiku (<0.35) / Sonnet (0.35–0.65) / Opus (≥0.65); wired into `dispatch_action()` before every handler; OTel span attrs `mkt.model_tier/score/model_id/action_type`; `ROUTER_FORCE_MODEL` / `ROUTER_HAIKU_THRESHOLD` / `ROUTER_SONNET_THRESHOLD` env overrides; `routed_model`/`route_tier`/`route_score` in dispatch response | v6.9 | All | ✅ |
| MKT-18 | Model Tier Analytics — `model_tier_distribution()` in `warden/marketplace/analytics.py`; reads `marketplace_clearing_log` action_type counts, maps via static `_ACTION_TIER` dict (avoids import cycle), estimates cost savings vs all-Opus baseline (Haiku $0.00025/Sonnet $0.003/Opus $0.015 per 1k tokens); sparse-data fallback (60/30/10% proportional estimate when <10 records); `GET /marketplace/analytics/model-tiers?period_days=N` endpoint | v6.9 | All | ✅ |

---

## 10. Billing & Monetization

Revenue model: tiers + add-ons + usage-based overages via Lemon Squeezy.

| ID | Feature | Version | Tier | Status |
|----|---------|---------|------|--------|
| BL-01 | Tier catalog — Starter $0 / Individual $5 / Community Business $19 / Pro $69 / Enterprise $249 | v4.5 | — | ✅ |
| BL-02 | Feature gate system — `require_feature()` FastAPI dep, per-tier caps | v4.5 | — | ✅ |
| BL-03 | Add-on: Secrets Vault Governance — +$12/mo (Individual+) | v4.9 | Individual+ | ✅ |
| BL-04 | Add-on: XAI Audit Reports — +$9/mo (Individual+) | v4.5 | Individual+ | ✅ |
| BL-05 | Add-on: Shadow AI Discovery — +$15/mo (Pro+) | v4.5 | Pro+ | ✅ |
| BL-06 | MasterAgent — included in Pro tier (not an add-on) | v4.5 | Pro+ | ✅ |
| BL-07 | PQC + Sovereign AI Cloud — Enterprise only, not purchasable as add-on | v4.5 | Enterprise | ✅ |
| BL-08 | `require_addon_or_feature()` — HTTP 403 (tier too low) / 402 (add-on not purchased) | v4.5 | — | ✅ |
| BL-09 | Billing admin endpoints — `grant`/`revoke` require `X-Admin-Key` | v4.5 | — | ✅ |
| BL-10 | Dunning ARQ cron — every 12h (06:00 + 18:00 UTC) | v3.0 | — | ✅ |
| BL-11 | Lemon Squeezy webhook handler — checkout → grant_addon() | v4.5 | — | ✅ |
| BL-12 | Add-on: On-Prem Deployment Pack — +$29/mo (Pro+), unlocks `on_prem_deployment` | v4.20 | Pro+ | ✅ |
| BL-13 | Add-on: Community Seats (+5 members) — +$9/mo (Community Business+), stackable | v4.20 | CB+ | ✅ |
| BL-14 | Bundle: Power User Bundle — Secrets Vault + XAI + Shadow AI at $29 (save $7) | v4.20 | Pro+ | ✅ |
| BL-15 | Annual billing — 15% off: $51/$194/$703/$2541/yr for Individual/CB/Pro/Enterprise | v4.20 | All | ✅ |
| BL-16 | 14-day Pro trial — 10k req cap, no MasterAgent, one-time per tenant | v4.20 | Individual+ | ✅ |
| BL-17 | `PricingCalculator` React component — tier + add-on + bundle + annual/monthly toggle | v4.20 | — | ✅ |
| BL-18 | `UsageProgress` React component — quota bar, 80% upgrade CTA, 60s refresh | v4.20 | — | ✅ |
| BL-19 | Request overage billing — ARQ monthly cron, Pro $0.50/1k, Enterprise $0.10/1k | v4.21 | Pro+ | ✅ |
| BL-20 | Add-on: Obsidian Business Pack — bundled plugin features +$8/mo | v4.21 | Individual+ | ✅ |
| BL-21 | Marketplace listing — AWS / Azure / Google Cloud Marketplace | v5.0 | Enterprise | 📋 |
| BL-22 | AI Vendor Governance Register — DPA tracking + expiry alerts | v4.23 | Individual+ | ✅ |
| BL-23 | AI Cost Allocation — per-department/vendor spend tracking | v4.24 | Community+ | ✅ |
| BL-24 | AI Budget Dashboard — real-time spend + approval workflow | v4.24 | Community+ | ✅ |

---

## 11. Testing & Quality

Test suites, coverage gates, mutation testing, adversarial scenarios.

| ID | Feature | Version | Status |
|----|---------|---------|--------|
| TQ-01 | pytest suite — `warden/tests/`, markers: adversarial/slow/integration | v1.0 | ✅ |
| TQ-02 | Coverage gate — ≥75% (`--cov-fail-under=75`), currently ~75.3% | v2.0 | ✅ |
| TQ-03 | Mutation testing — mutmut on `secret_redactor.py` + `semantic_guard.py`, <20 survivors | v2.0 | ✅ |
| TQ-04 | Adversarial test suite — informational, `|| true`, does not block CI | v2.0 | ✅ |
| TQ-05 | SWFE FakeContext — unified fake activation via `mock.patch`, X-Simulation-ID isolation | v3.5 | ✅ |
| TQ-06 | SWFE fake layer — FakeAnthropicClient, FakeNvidiaClient, FakeS3Storage, FakeEvolutionEngine | v3.5 | ✅ |
| TQ-07 | SWFE Scenario DSL — ScenarioRunner, ScenarioStep, `build_core_scenarios()`, YAML loader | v3.5 | ✅ |
| TQ-08 | ScenarioStep.smart_retry — auto-retry with XAI causal-chain hint on failure | v4.11 | ✅ |
| TQ-09 | test_obsidian_integration.py — 25 tests, 6 classes | v4.10 | ✅ |
| TQ-10 | test_secrets_governance.py — 48 tests | v4.9 | ✅ |
| TQ-11 | test_community_v48.py — 50 tests, UUID isolation pattern | v4.8 | ✅ |
| TQ-12 | test_security_fixes.py — 17 tests for P0/P1 security fixes | v4.7 | ✅ |
| TQ-13 | test_coverage_boost.py — 55 targeted tests pushing coverage to 75.3% | v4.11 | ✅ |
| TQ-14 | k6 load test — baseline/ramp/spike/soak scenarios against `api.shadow-warden-ai.com` | v4.13 | ✅ |
| TQ-15 | k6 smoke test — 1 VU, 30s, post-deploy gate | v4.14 | ✅ |
| TQ-16 | Coverage gate raise to 80% | v4.21 | ✅ |
| TQ-17 | Property-based testing (Hypothesis) on SecretRedactor + TopologicalGatekeeper | v4.21 | ✅ |
| TQ-18 | Integration test suite against live Docker Compose stack | v4.22 | ✅ |
| TQ-19 | Chaos engineering — random service kill + traffic replay, verify fail-open | v4.22 | ✅ |

---

## 12. AI Research & Evolution

Continuous self-improvement and threat intelligence synthesis.

| ID | Feature | Version | Status |
|----|---------|---------|--------|
| AR-01 | EvolutionEngine — Claude Opus auto-rule gen, hot-reload, no restart required | v1.0 | ✅ |
| AR-02 | `synthesize_from_intel()` — ArXiv paper → attack examples → rule injection | v3.0 | ✅ |
| AR-03 | Evolution regex gate — rejects AI-generated regex that fails compile / times out / nested quantifiers | v4.7 | ✅ |
| AR-04 | Intel Bridge — background ArXiv → EvolutionEngine sync every 6h | v4.13 | ✅ |
| AR-05 | MISP IoC synthesis — 14 attribute types → attack descriptions → rules | v4.16 | ✅ |
| AR-06 | Threat Radar — OSV API CVE scan + ArXiv paper hunt → `data/intel_report.json` | v3.0 | ✅ |
| AR-07 | `data/evolution_dataset.jsonl` — persisted training examples for audit | v1.0 | ✅ |
| AR-08 | Community auto-apply — UECIID → attack example → human-in-the-loop approval | v4.16 | ✅ |
| AR-09 | Online learning pipeline — nightly ONNX fine-tune from `evolution_dataset.jsonl` | v4.22 | ✅ |
| AR-10 | Federated threat model — share anonymised rule deltas between tenants without raw data | v4.22 | ✅ |
| AR-11 | Red-team autopilot — SOVA generates novel jailbreak probes against own pipeline | v4.22 | ✅ |
| AR-12 | Curriculum learning scheduler — prioritise training on rarest attack classes | v5.0 | 📋 |

---

## Production Infrastructure Status

| Component | URL | Status |
|-----------|-----|--------|
| API Gateway | `https://api.shadow-warden-ai.com` | ✅ Live |
| Tenant Portal | `https://app.shadow-warden-ai.com` | ✅ Live |
| Landing Page | `https://shadow-warden-ai.com` | ✅ Live |
| Redoc API Docs | `https://docs.shadow-warden-ai.com` | ✅ Live |
| Community Dashboard | `https://shadow-warden-ai.com/community` | ✅ Live (Vercel) |
| Public Incident Page | `https://shadow-warden-ai.com/incident` | ✅ Live (Vercel) |
| SOC Dashboard | `https://dash.shadow-warden-ai.com` | ✅ Live |
| Grafana | `http://91.98.234.160:3000` | ✅ Live |
| Jaeger UI | `http://91.98.234.160:16686` | ✅ Live |
| Hetzner VPS | `91.98.234.160` | ✅ Live |

---

## Release Timeline

| Version | Date | Theme |
|---------|------|-------|
| v1.0 | 2025 | Core 9-layer filter pipeline |
| v2.0 | 2025 | Multi-tenant auth, shadow ban, SIEM |
| v3.0 | 2025-Q4 | SOVA Agent, MasterAgent, WardenHealer |
| v3.3 | 2026-Q1 | ScreencastRecorder, visual_patrol, Playwright |
| v4.0 | 2026-04 | Agentic SOC, MasterAgent sub-agents |
| v4.1 | 2026-04 | Post-Quantum Cryptography (ML-DSA-65 + ML-KEM-768) |
| v4.2 | 2026-04 | Shadow AI Governance (18-provider detection) |
| v4.3 | 2026-04 | Explainable AI 2.0 (9-stage DAG, HTML/PDF) |
| v4.4 | 2026-04 | Sovereign AI Cloud (8 jurisdictions, MASQUE) |
| v4.5 | 2026-04 | Billing add-ons, tier feature gates |
| v4.6 | 2026-04 | Syndicate Exchange Protocol (SEP, UECIID) |
| v4.7 | 2026-04 | Security hardening P0/P1, Causal Transfer Guard, STIX |
| v4.8 | 2026-04 | Community Charter, Behavioral Anomaly, OAuth Discovery |
| v4.9 | 2026-04 | Secrets Governance (4 connectors, lifecycle, 14 endpoints) |
| v4.10 | 2026-05-01 | Obsidian Business Community Integration |
| v4.11 | 2026-05-03 | SOVA v2 (visual_diff, OLS trend, Haiku healer), Accessibility |
| v4.12 | 2026-05-04 | Community Governance + Intelligence Layer |
| v4.13 | 2026-05-05 | OTel tracing, SOC Next.js dashboard, CI hardening |
| v4.14 | 2026-05-05 | Redoc docs, Trivy CVE, k6, SLO burn-rate, Dashboard auth |
| v4.15 | 2026-05-06 | Public Community Intelligence, SOVA community tools |
| v4.16 | 2026-05-07 | MISP connector, Reputation system, Public incident page |
| v4.17 | 2026-05-07 | SOVA + Obsidian + Slack unification |
| v4.18 | 2026-05-07 | Obsidian sidebar, frontmatter tagging, local pre-validation |
| v4.19 | 2026-05-07 | Obsidian Dataview dashboard, offline queue, XAI viz, scheduler |
| v4.20 | 2026-05-17 | Community & Tunnel SPA, castle logo, interactive /pricing, SOC Dashboard DNS live, roadmap: CR-13–15 (PQC/HSM/MASQUE), CP-22–26 (ISO/HIPAA/NIS2/compliance), IN-14–22 (VS Code/GitHub/Jira/Teams/Notion/STIX/OTel/MISP), OB-26–28, IF-19–20, BL-19–20, a11y contrast fix |
| v4.21 | 2026-05-18 | DataPrivacyAgent, GitHub Actions integration, Jira/Teams integrations, Grafana unified, mobile SOC, dark/light theme, FE-12–14, AG-23, SP-23 scaffolds |
| **v4.22** | **2026-05-18** | **Sprint 3: WebSocket stream (OB-26), onboarding wizard (FE-15), integration tests (TQ-18), chaos testing (TQ-19), online learning (AR-09), federated threats (AR-10), red-team autopilot (AR-11), VS Code extension (IN-14), community federation (CM-26), TAXII consumer (IN-19), pgvector memory (AG-24), multi-modal guard (SP-22), HSM PKCS#11 (CR-14), k8s HPA (IF-19), model sharing (CM-27)** |
| v4.30 | 2026-05-22 | Business Intelligence (CM-39): 8-category analytics, OLS prediction, benchmarking, 15-min SQLite cache |
| v5.0 | 2026-05-25 | Agentic Commerce (UCP/AP2/MCP), FIDO2 passkeys, Web3 Sepolia mandates |
| **v5.1** | **2026-05-29** | **Semantic Layer Headless BI (FE-42), Settings Hub (FE-43), site 15-layer refresh, /roadmap page, CI lint+mypy 0-error** |
| **v5.2** | **2026-05-31** | **AI Analytics Hub (FE-47): 9 semantic models, Redis cache, SOVA tools; Commerce Budget Guardian (FE-48): Semantic Layer–backed AP2 pre-flight; Self-Service Catalog (FE-49): tenant model registration; /analytics landing page** |
| **v5.3** | **2026-06-05** | **GitHub Actions CI gate (IN-15): composite action + pre-commit hook, 93-control scan, PR comment, 90-day audit; ISO 27001:2022 Annex A full mapping (CP-22): 93 controls × 4 themes, HTML report, Streamlit + SOC drilldown, Enterprise gate; Continuous Compliance Scoring (CP-25): 5-standard posture, 168-snapshot ring buffer, 30s auto-refresh, Streamlit + SOC page, Pro+ gate; lint fixes: ruff I001/F401/SIM105/SIM117/B904/N812/C408/B007/E401** |
| **v5.4** | **2026-06-06** | **Document Intelligence (FE-50, SP-25, AG-26): MarkItDown converter — file-type TTLs (PDF 24h/audio 7d/images 1h), 50 MB gate, 30s thread timeout, SHA-256 Redis cache; 6 `/document-intel/*` endpoints; `file_base64` filter hook in POST /filter (fail-open); Prometheus counters × 3; SOVA tool #50 `scan_document`; Portal `/doc-scanner/` + server proxy; Streamlit page 19; Site `/cyber-security/document-intelligence`; 10 tests green** |
| **v5.5** | **2026-06-06** | **Real-time Compliance Gap Dashboard (CP-30, AG-27/28): `CompliancePostureService` — 19 controls (GDPR/SOC2/ISO27001/HIPAA), all checks fail-safe; Redis cache 5min TTL + Pub/Sub; 4 new `/compliance/*` endpoints; WebSocket `/compliance/ws`; SOVA tools #51 `get_compliance_report` + #52 `remediate_gap`; Portal `/compliance/` SVG score ring + gap list + "Fix →" deep-links; Streamlit 5-tab gap manager; 28 compliance tests (16 CP-25 + 12 CP-30)** |
| **v5.6** | **2026-06-12** | **Community M2M Agentic Marketplace (Phases 1-3): agent DID registration, asset tokenization, escrow flow, multi-agent auctions, marketplace analytics; Community Event Notifications (email/Slack/Teams); Deploy & Infrastructure Monitoring (`GET /deploy/status`, SOC status page, Portal deployment view); Public SDK & Developer Reference page; Node.js SDK `@shadow-warden/sdk` (SDK-01); AI-assisted onboarding wizard (ONB-01): 5 steps, SOVA tools #53–55** |
| **v6.0** | **2026-06-16** | **Voice-Commerce Agents (VC-01): `warden/voice/` — StreamingASR (whisper/deepgram/assemblyai), TTSEngine (elevenlabs/azure/edge), VoiceNLU (Claude Haiku + rule fallback), DialogueManager (Redis sessions, multi-turn confirm flow), VoiceBiometric (resemblyzer embeddings, Fernet-encrypted voiceprints), VoiceGuardian (coercion detection, spectral deepfake score, Z-score behavioural anomaly), X402Protocol (micropayment rail, payment channels, on-chain verify); 6 SOVA tools #62–67 (voice_search, voice_buy, voice_negotiate, voice_auction, voice_compliance_check, voice_trust_query); FastAPI `/voice/*` router (session, WebSocket stream, REST transcribe, x402 endpoints); 24 tests across 4 test files** |
| **v6.1** | **2026-06-17** | **Security Hardening Phase 2 (SEC-02–SEC-10): HSM key rotation + audit + lock/unlock (SEC-02); AutoResponder agent isolation/restore with STIX+Kafka (SEC-03); Prompt Injection Defense — 10 regex + delimiter-attack patterns, VoiceGuardian integrated (SEC-04); Decentralized key rotation lifecycle schedule/complete/overdue (SEC-05); FederatedTrustRegistry cross-community threat flags SQLite + Redis pub/sub (SEC-06); SecureWipe + secure_memory decorator tests (SEC-07); hybrid Ed25519+ML-DSA-65 asset signature tests (SEC-08); BehavioralAnomalyDetector Z-score tests (SEC-09); data lifecycle tests (SEC-10); Voice-Commerce Prometheus metrics + Kafka consumer bridge + Grafana dashboard + alerting rules (VC-02); 54 new tests** |
| **v6.2** | **2026-06-17** | **Unified Professional Design System (DS-01): `packages/ui/` monorepo package — 10 components (Card, Button, Badge, Input, Select, Modal, Table, Tabs, Chart, ThemeToggle) + ThemeProvider; portal components: Card/Button/Table/Tabs/ThemeProvider updated to DS-01 tokens; dashboard components: card/button/tabs/theme-provider updated; `.streamlit/config.toml` dark theme; `warden/analytics/components.py` (card, metric_card, badge, section_header, alert, divider); `site/src/styles/tokens.css` DS-01 bridge + light mode vars; ThemeToggle in Astro BaseLayout navbar (localStorage persistence, `.light` class on `<html>`)** |
| **v6.3** | **2026-06-18** | **Phase 2 Infrastructure & Scalability (SC-01–SC-05): Helm chart — 11 services, HPA (warden 2-10, app 2-6), KEDA arq-worker; Terraform Hetzner (cx31 + 100GB + floating IP + cloud-init); RegionMiddleware X-Region/X-Region-Prefer headers; Canary deploy script (10%→50%→100%, Prometheus error-rate gate, helm rollback)** |
| **v6.4** | **2026-06-18** | **Phase 3 Advanced Detection (DET-01–DET-05): Multimodal jailbreak detection — image_base64 (Claude Vision OCR/jailbreak) + audio_base64 (VoiceGuardian ASR + deepfake); Agentic Loop Monitor β₂ Betti topology (loop_monitor.py); Live Threat Feed Sync — MITRE ATLAS + OWASP LLM + HuggingFace → EvolutionEngine every 4h; Adversarial Benchmark Suite — 65-prompt corpus, BLOCK recall gate ≥95%; Deepfake Audio Pipeline — mel-spectrogram delta variance + VALL-E/Voicebox signatures in detect_deepfake_enhanced()** |
| **v6.5** | **2026-06-18** | **Phase 4 Developer Experience (DEV-01–DEV-05): Python SDK — WardenClient + AsyncWardenClient + FilterResult dataclass; OTel WardenSpanProcessor — fire-and-forget PII redaction on llm.prompt/gen_ai.completion attrs; VS Code Extension gutter icons (SVG data URIs, 4 severity tiers); API Playground /playground Astro page — live /filter with verdict banner + pipeline timing; Webhook Event System — HMAC-SHA256 delivery, ≤3 retries, 6 event types at /webhooks/*; all mounted in main.py** |
| **v6.6** | **2026-06-18** | **Phase 5 Enterprise Features (ENT-01–ENT-05): SSO/SAML 2.0 — SP AuthnRequest + ACS validation + replay protection + JIT tenant provisioning; White-Label Mode — per-tenant domain/logo/colors/CSS + Caddy vhost snippet; Custom Compliance Framework Builder — controls editor + weighted score + SQLite; AI Usage Budgets — per-department monthly caps, warn/block thresholds, Slack alerts; SLA Status Page /status — live component health + 90-day SLA metrics** |
| **v6.7** | **2026-06-19** | **Voice-Commerce E2E + Security Gap Closure: `tool_voice_portfolio` (SOVA tool #68) — spoken active-escrow summary; 16 e2e voice tests (`test_voice_e2e.py`) covering search→buy→portfolio→metrics; feature gates `federated_trust_enabled`/`auto_isolation_enabled` in all 5 TIER_LIMITS tiers; SEC-02–SEC-10 rows in ROADMAP; `docs/multi-region.md`; IF-20 status ✅; SQLite pragma hardening (DB-01); consolidation migration script (DB-02). 4078 tests · 79.26% coverage.** |
| **v6.8** | **2026-06-24** | **M2M 4-Stage Lifecycle Protocol (MKT-15): unified dispatcher 14 action types, `GET /protocol` v1.1 headers, `GET /protocol/schema/{action}` JSON Schema discovery, `POST /clear` ClearingEngine dual-write; Brand Agent seller-side gateway 4-gate filter (BGA-01); Three-Layer Context DB — AgentHandoffMemory ~61% token savings + pgvector Layer 3 (TDB-01); First-Proposal Bias Guard minimum 3 alternatives + Confused Deputy SQL scoping (MKT-16); SOVA tools #70–74; 71 marketplace tests** |
| **v6.9** | **2026-06-26** | **Dynamic Model Router (MKT-17): 4-factor complexity scoring routes Haiku/Sonnet/Opus per dispatch action; wired into dispatch_action() with OTel span attrs; env-configurable thresholds + force-override; Model Tier Analytics (MKT-18): `GET /analytics/model-tiers`, cost savings vs all-Opus baseline, sparse-data fallback; Marketplace Intelligence Charts (FE-51): First-Proposal Bias + Model Tier doughnuts on marketplace.astro with Chart.js; CI Docker Scout gate (IF-23)** |
| v7.0 | Q3 2026 | x402 Nanopayment Gate for search, Platform Take Rate (1.5% ClearingEngine), Sponsored Listing boost (+0.15 pgvector), Real-time Document Firehose (Google Drive/SharePoint) |
