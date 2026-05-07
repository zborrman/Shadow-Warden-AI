# Shadow Warden AI — Full Product Roadmap

**Version 4.19 · Last updated 2026-05-07**

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
| SP-22 | Multi-modal content guard — image prompt injection detection | — | Pro+ | 📋 |
| SP-23 | Audio/video transcription guard — Whisper pre-scan before LLM | — | Enterprise | 📋 |
| SP-24 | Fine-tuned ONNX model export — <1ms inference, eliminates MiniLM cold start | — | All | 📋 |

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
| AG-21 | SOVA tool #46 — `generate_threat_report` (full PDF/HTML export via XAI renderer) | — | Pro+ | 📋 |
| AG-22 | SOVA tool #47 — `block_ip_range` (ERS hard block, tenant-scoped) | — | Enterprise | 📋 |
| AG-23 | MasterAgent sub-agent #5 — DataPrivacyAgent (GDPR Art.17 right-to-erasure automation) | — | Enterprise | 📋 |
| AG-24 | SOVA memory expansion — vector search (pgvector) over past conversations | — | Pro+ | 📋 |
| AG-25 | Voice-activated SOC operator — WebRTC audio → Whisper → SOVA → TTS response | — | Enterprise | 📋 |

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
| CM-24 | `TRUSTED_ENTRY +3` reputation cron — 30-day no-report entries auto-awarded | — | Community+ | 📋 |
| CM-25 | `SEARCH_HIT +1` reputation — awarded on `search_community_feed` result match | — | Community+ | 📋 |
| CM-26 | Community threat score federation — broadcast verified verdicts to federated peers | — | Enterprise | 📋 |
| CM-27 | Community AI model sharing — share fine-tuned detection rules as signed UECIID bundles | — | Enterprise | 📋 |
| CM-28 | Community SLA contracts — codify data residency + retention commitments in charter | — | Enterprise | 📋 |

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
| IN-14 | VS Code extension — inline risk annotation on selected text | — | Individual+ | 📋 |
| IN-15 | GitHub Actions integration — pre-commit hook that scans commit message + diff | — | Pro+ | 📋 |
| IN-16 | Jira integration — auto-create security tickets on HIGH/BLOCK verdicts | — | Pro+ | 📋 |
| IN-17 | Microsoft Teams slash command — `/warden` equivalent for Teams channels | — | Pro+ | 📋 |
| IN-18 | Notion integration — scan Notion pages via API, write risk tags as properties | — | Community+ | 📋 |
| IN-19 | STIX/TAXII feed consumer — ingest external threat intel from any TAXII 2.1 server | — | Enterprise | 📋 |
| IN-20 | Zapier / Make connector — webhook trigger + filter action blocks | — | Individual+ | 📋 |
| IN-21 | OpenTelemetry SDK library — `WardenSpanProcessor` for any OTel-enabled app | — | Pro+ | 📋 |
| IN-22 | MISP syslog bridge — route MISP ZMQ feed into Shadow Warden syslog sink | — | Pro+ | 📋 |

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
| CP-22 | ISO 27001 Annex A control mapping | — | Enterprise | 📋 |
| CP-23 | HIPAA technical safeguards attestation (encryption, audit, access control) | — | Enterprise | 📋 |
| CP-24 | NIS2 Directive compliance report | — | Enterprise | 📋 |
| CP-25 | Continuous compliance scoring dashboard — real-time SOC 2 / GDPR / ISO posture | — | Pro+ | 📋 |
| CP-26 | Data retention policy enforcement — tenant-configurable per data_class | — | Community+ | 📋 |

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
| CR-13 | ML-KEM-1024 upgrade path (FIPS 203 Level 5) | — | Enterprise | 📋 |
| CR-14 | HSM integration — PKCS#11 bridge for sovereign key material | — | Enterprise | 📋 |
| CR-15 | Certificate-pinned MASQUE tunnels — TOFU → CA-signed upgrade path | — | Enterprise | 📋 |

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
| IF-19 | Kubernetes horizontal pod autoscaler for warden + dashboard services | — | Enterprise | 📋 |
| IF-20 | Multi-region active-active deployment (EU + US) | — | Enterprise | 📋 |
| IF-21 | cosign + SBOM CI signing on Docker images | v4.13 | — | ✅ |
| IF-22 | Mutation testing — mutmut on `secret_redactor.py` + `semantic_guard.py` | v2.0 | — | ✅ |

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
| OB-26 | Real-time anomaly WebSocket stream — push XAI events to dashboard without polling | — | Pro+ | 📋 |
| OB-27 | Grafana unified dashboard for all 11 services | — | All | 📋 |
| OB-28 | Mobile SOC app — React Native, push alerts for HIGH/BLOCK verdicts | — | Pro+ | 📋 |

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
| FE-12 | SOC dashboard DNS A record (`dash.shadow-warden-ai.com → 91.98.234.160`) | — | — | 📋 |
| FE-13 | Analytics API live endpoints in SOC dashboard (replace mock/placeholder data) | — | All | 📋 |
| FE-14 | Mobile-responsive SOC dashboard | — | All | 📋 |
| FE-15 | Onboarding flow — guided 5-step setup wizard for new tenants | — | All | 📋 |
| FE-16 | Dark/light theme toggle in portal and SOC dashboard | — | All | 📋 |
| FE-17 | `shadow-warden-ai.com/pricing` — interactive tier comparison + add-on calculator | — | Public | 📋 |

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
| BL-19 | Request overage billing — automatic charge per 1k requests above Pro tier | — | Pro+ | 📋 |
| BL-20 | Add-on: Obsidian Business Pack — bundled plugin features +$8/mo | — | Individual+ | 📋 |
| BL-21 | Marketplace listing — AWS / Azure / Google Cloud Marketplace | — | Enterprise | 📋 |

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
| TQ-16 | Coverage gate raise to 80% | — | 📋 |
| TQ-17 | Property-based testing (Hypothesis) on SecretRedactor + TopologicalGatekeeper | — | 📋 |
| TQ-18 | Integration test suite against live Docker Compose stack | — | 📋 |
| TQ-19 | Chaos engineering — random service kill + traffic replay, verify fail-open | — | 📋 |

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
| AR-09 | Online learning pipeline — nightly ONNX fine-tune from `evolution_dataset.jsonl` | — | 📋 |
| AR-10 | Federated threat model — share anonymised rule deltas between tenants without raw data | — | 📋 |
| AR-11 | Red-team autopilot — SOVA generates novel jailbreak probes against own pipeline | — | 📋 |
| AR-12 | Curriculum learning scheduler — prioritise training on rarest attack classes | — | 📋 |

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
| SOC Dashboard | `https://dash.shadow-warden-ai.com` | ⚠️ Needs DNS A record |
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
| **v4.19** | **2026-05-07** | **Obsidian Dataview dashboard, offline queue, XAI viz, scheduler** |
| v5.0 | Q3 2026 | Multi-region active-active, ONNX online learning, HIPAA |
