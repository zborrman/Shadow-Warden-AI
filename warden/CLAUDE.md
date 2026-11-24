# warden/CLAUDE.md — the internal engine

The root `CLAUDE.md` defines the product (seller protection) and the rules that
bind the whole repo. This file holds the gateway's own architecture and key-file
map, moved here on 2026-11-24 when the gateway became the internal engine rather
than a product. Nothing here is a sales claim; public wording is governed by
`docs/capability-matrix.md`.

## Architecture

```
POST /filter → TopologicalGatekeeper (n-gram point cloud → β₀/β₁ Betti numbers, < 2ms)
                → ObfuscationDecoder (base64/hex/ROT13/Caesar/word-split/UUencode/homoglyphs, depth-3 recursive)
                → SecretRedactor (15 regex patterns + Shannon entropy scan for unknown secrets)
                → SemanticGuard (rules, compound risk escalation)
                → HyperbolicBrain (MiniLM → Poincaré ball, 70% cosine + 30% hyperbolic blend)
                → CausalArbiter (gray-zone: Bayesian DAG P(HIGH_RISK|evidence) via do-calculus)
                → ERS (Redis sliding window, shadow ban at score ≥ 0.75)
                → Decision
                    ↓
    EvolutionEngine (background, Claude Opus) ← HIGH/BLOCK
                ↓ add_examples() hot-reload
    _brain_guard corpus
                ↓
    event_logger → data/logs.json → Streamlit admin UI (:8502)
                ↓ background S3 ship (fail-open)
    MinIO on-prem object store (S3_ENABLED=true)
        warden-evidence/bundles/<session_id>.json   ← Evidence Vault
        warden-logs/logs/<date>/<request_id>.json   ← analytics

Agent pipeline:
    AgentMonitor.record_tool_event() → _check_injection_chain() (+ 6 other patterns)
    MaskingEngine.mask/unmask()      → Fernet-encrypted vault (HMAC-SHA256 reverse map)
    openai_proxy._stream_gen()       → 400-char fast-scan → live-emit (progressive streaming)

SOVA Agent (autonomous operator):
    POST /agent/sova            → run_query() → Claude Opus 4.6 agentic loop (≤10 iter)
    DELETE /agent/sova/{sid}    → clear_history()
    POST /agent/sova/task/{job} → trigger scheduled job manually (incl. visual-patrol)
    ARQ cron:
        sova_morning_brief  08:00 UTC daily
        sova_threat_sync    every 6h (00:05, 06:05, 12:05, 18:05)
        sova_rotation_check 02:00 UTC daily
        sova_sla_report     Monday 09:00 UTC
        sova_upgrade_scan   Sunday 10:00 UTC
        sova_corpus_watchdog every 30 min (delegates to WardenHealer — no LLM)
        sova_visual_patrol  03:00 UTC daily (ScreencastRecorder + Claude Vision → MinIO, smart priority weights)
    Memory: Redis sova:conv:{session_id} JSON (6h TTL, 20-turn cap)
    Tools: 30 tool handlers → http://localhost:8001 X-API-Key calls
        #28: visual_assert_page — BrowserSandbox + Claude Vision (in-process)
        #29: scan_shadow_ai     — Shadow AI Discovery (ShadowAIDetector, 18 providers, subnet probe + DNS)
        #30: explain_decision   — Causal chain retrieval from logs + XAI rationale
        #31: visual_diff        — Claude Vision baseline vs candidate screenshot comparison
    Healer: WardenHealer — autonomous anomaly detection (CB, bypass spike, corpus DEGRADED, canary probe, OLS trend prediction, Haiku incident classification, SQLite recipe cache)

MasterAgent (multi-agent SOC coordinator — v4.0):
    POST /agent/master               → run_master() → decompose → parallel sub-agents → synthesis
    POST /agent/approve/{token}      → approve or reject pending high-impact action
    GET  /agent/approve/{token}      → check approval status
    Sub-agents (each has specialized tool subset + system prompt):
        SOVAOperator   — health, stats, billing, config, key rotation
        ThreatHunter   — CVE triage, ArXiv intel, adversarial analysis
        ForensicsAgent — agent activity, GDPR Art.30, Evidence Vault, visual patrol
        ComplianceAgent— SLA monitors, SOC 2 controls, ROI proposals
    Task tokens: HMAC-SHA256 binding (sub_agent, task_hash, issued_at) — cross-agent injection prevention
    Human-in-the-Loop: REQUIRES_APPROVAL actions → Slack webhook → Redis pending (1h TTL) → /agent/approve/{token}
```

24 Docker services. Gateway and UIs: `proxy` (80/443), `warden` (8001), `analytics` (8002), `admin` (8502, Streamlit), `dashboard` (3002, Next.js SOC), `portal` (3001). Data: `postgres` (TimescaleDB), `redis`, `clickhouse`, `minio` (9000/9091), `minio-init`. Workers: `arq-worker`, `autoheal`. Observability: `prometheus`, `grafana` (3000), `loki`, `promtail`, `jaeger`, `otel-collector`, `cadvisor`, `node-exporter`, `postgres-exporter`, `redis-exporter`. Edge: `cloudflared`.

## Two Distinct Guard Classes (critical distinction)

| Class | Module | Method | Purpose |
|-------|--------|--------|---------|
| `SemanticGuard` | `warden.semantic_guard` | `analyse()` | Regex rule engine + compound risk escalation |
| `SemanticGuard` (alias `BrainSemanticGuard`) | `warden.brain.semantic` | `check()` / `check_async()` | MiniLM ML cosine similarity |

Both run in the `/filter` pipeline (Stage 2 + Stage 2b). The Evolution Engine must receive `_brain_guard` (not `_guard`) because only the ML guard has `add_examples()`.

## Key Files

| File | Role |
|------|------|
| `warden/main.py` | FastAPI gateway — auth, rate-limit, cache, multi-tenant, Prometheus, GDPR, alerting, batch |
| `warden/topology_guard.py` | TDA Gatekeeper — n-gram point cloud, Betti numbers (β₀/β₁), ripser optional |
| `warden/brain/hyperbolic.py` | Poincaré ball projection + vectorized hyperbolic distance (pure numpy) |
| `warden/causal_arbiter.py` | Bayesian DAG causal inference — 5 nodes, Pearl do-calculus, backdoor correction |
| `warden/brain/semantic.py` | ML jailbreak detector — MiniLM + hyperbolic blend, adversarial suffix stripping |
| `warden/brain/evolve.py` | Claude Opus auto-rule generation + `synthesize_from_intel()` (ArXiv paper → attack examples) |
| `warden/obfuscation.py` | Obfuscation decoder pre-filter (base64, hex, ROT13, unicode homoglyphs) |
| `warden/secret_redactor.py` | 15 PII/secret regex patterns + Shannon entropy scan for unknown secrets |
| `warden/semantic_guard.py` | Rule-based semantic analyser, compound risk escalation (3+ MEDIUM → HIGH) |
| `warden/schemas.py` | Pydantic models (`FilterRequest` with `tenant_id`, `FilterResponse` with `processing_ms`) |
| `warden/cache.py` | Redis SHA-256 content hash cache (5-min TTL, fail-open) |
| `warden/auth_guard.py` | Per-tenant API keys (JSON multi-key + SHA-256 hash lookup), constant-time compare |
| `warden/openai_proxy.py` | OpenAI-compatible `/v1/chat/completions` proxy — progressive streaming (400-char fast-scan buffer → live-emit) |
| `warden/agent_monitor.py` | Session-level threat patterns incl. INJECTION_CHAIN — cryptographic attestation chain |
| `warden/masking/engine.py` | PII masking engine — Fernet-encrypted vault, HMAC-SHA256 reverse map, no plaintext in memory |
| `warden/alerting.py` | Slack + PagerDuty real-time alerts on HIGH/BLOCK |
| `warden/analytics/logger.py` | NDJSON logger + GDPR helpers (`purge_before`, `read_by_request_id`) |
| `warden/analytics/dashboard.py` | Streamlit security dashboard (reads logs.json directly) |
| `warden/analytics/pages/2_Settings.py` | Streamlit Settings page — Threat Radar tab + Intel Bridge tab + Causal Arbiter interactive visualizer |
| `warden/intel_ops.py` | Threat Radar — OSV API dependency CVE scanner + ArXiv LLM-attack paper hunter; saves `data/intel_report.json` |
| `warden/intel_bridge.py` | Auto-Evolution Bridge — ArXiv papers → `synthesize_from_intel()` → `SemanticGuard.add_examples()` hot-reload |
| `warden/analytics/siem.py` | Splunk HEC + Elastic ECS SIEM integration |
| `warden/integrations/langchain_callback.py` | LangChain duck-typed callback (`WardenCallback`) |
| `warden/tools/browser.py` | Playwright headless Chromium sandbox (`Context7Manager`) |
| `warden/Dockerfile` | **Multi-stage (P-3a)**: builder compiles liboqs + installs deps `-c constraints.txt`; runtime is `python:3.11-slim` with no compiler. CPU-only torch (build-asserted), non-root UID/GID 10001 |
| `warden/storage/s3.py` | S3-compatible object storage backend — MinIO / AWS S3 (lazy boto3, background threads, fail-open) |
| `warden/storage/__init__.py` | Package init for storage backends |
| `docker-compose.yml` | Full orchestration with healthchecks + resource limits (includes minio + minio-init) |
| `warden/shadow_ban.py` | Shadow Ban Engine — differentiated strategies: gaslight (prompt injection), delay (bot/stuffing), standard |
| `warden/metrics.py` | Prometheus metric singletons — incl. `SHADOW_BAN_TOTAL`, `SHADOW_BAN_COST_SAVED_USD` (v2.2) |
| `grafana/provisioning/alerting/warden_alerts.yml` | SLO alerts: P99 latency + 5xx rate + availability + shadow ban rate + corpus drift |
| `docs/security-model.md` | 9-layer defense model, OWASP LLM Top 10 coverage, threat model, crypto controls |
| `docs/dpia.md` | GDPR Art. 35 Data Protection Impact Assessment |
| `docs/soc2-evidence.md` | SOC 2 Type II evidence guide — control mapping + auditor collection procedures |
| `warden/financial/impact_calculator.py` | Dollar Impact Calculator — IBM 2024 benchmarks, industry multipliers, ROI tiers, ASCII report |
| `warden/financial/metrics_reader.py` | Live data adapter — reads logs.json, Redis ERS, Prometheus for real impact numbers |
| `warden/api/financial.py` | FastAPI router `/financial/*` — impact, cost-saved, roi, generate-proposal endpoints |
| `scripts/impact_analysis.py` | CLI entry point — `--live`, `--industry`, `--requests`, `--export`, `--interactive` |
| `.github/workflows/ci.yml` | Test matrix (3.11/3.12) + lint + Docker smoke + mutation testing |
| `warden/secrets_gov/vault_connector.py` | Abstract vault connectors — AWS SM / Azure KV / HashiCorp / GCP SM / env (metadata-only, no plaintext) |
| `warden/secrets_gov/inventory.py` | SQLite-backed secrets inventory — risk scoring, auto-retire, expiry tracking |
| `warden/secrets_gov/policy.py` | Secrets Policy Engine — per-tenant governance rules, compliance audit scoring |
| `warden/secrets_gov/lifecycle.py` | Lifecycle Manager — expiry alerts, auto-retire, rotation scheduling |
| `warden/api/secrets.py` | FastAPI router `/secrets/*` — 14 endpoints: vaults, inventory, lifecycle, policy, audit, report |
| `warden/analytics/pages/6_Secrets_Governance.py` | Streamlit dashboard — 6-tab secrets governance UI |
| `warden/integrations/obsidian/note_scanner.py` | Obsidian note scanner — YAML frontmatter parse, data classification, SecretRedactor integration |
| `warden/api/obsidian.py` | FastAPI router `/obsidian/*` — 5 endpoints: scan, share (SEP UECIID), feed, ai-filter, stats |
| `obsidian-plugin/main.ts` | TypeScript Obsidian plugin — ribbon, status bar, 5 commands, auto-scan on modify, settings tab |
| `warden/api/monitor.py` | Uptime Monitor REST API — `/monitors/*` CRUD + `/status` + `/uptime` + `/history` |
| `warden/workers/probe_worker.py` | Async probe scheduler — HTTP/SSL/DNS/TCP checks, TimescaleDB write, Redis Pub/Sub publish |
| `warden/db/migrations/versions/0010_uptime_monitors.py` | TimescaleDB migration — hypertable, continuous aggregate, retention + compression policies |
| `warden/phishing_guard.py` | PhishGuard + SE-Arbiter — URL phishing + social engineering detection (SEC-GAP-002 fixed) |
| `warden/agent/master.py` | MasterAgent — supervisor loop, 4 sub-agents, HMAC task tokens, human-in-the-loop approval gate |
| `warden/crypto/pqc.py` | Post-Quantum Cryptography — HybridSigner (Ed25519+ML-DSA-65), HybridKEM (X25519+ML-KEM-768), CryptoBackend, `pqc_selfcheck()`; liboqs fail-open in code, build-asserted in the image |
| `warden/crypto/__init__.py` | Package init for crypto backends |
| `warden/communities/keypair.py` | Community keypair — classical + hybrid PQC (`generate_community_keypair(pqc=True)`, `upgrade_to_hybrid()`) |
| `warden/shadow_ai/signatures.py` | AI provider fingerprint DB — 18 providers, domains, URL patterns, local ports, risk levels |
| `warden/shadow_ai/discovery.py` | `ShadowAIDetector` — async subnet probe + DNS telemetry classifier; Redis findings store |
| `warden/shadow_ai/policy.py` | `ShadowAIPolicy` — per-tenant MONITOR/BLOCK_DENYLIST/ALLOWLIST_ONLY governance; Redis-backed |
| `warden/api/shadow_ai.py` | FastAPI router `/shadow-ai/*` — scan, dns-event, findings, report, policy, providers |
| `warden/xai/chain.py` | `CausalChain` + `build_chain()` — 9-stage pipeline graph, primary cause, counterfactuals |
| `warden/xai/renderer.py` | HTML + PDF (reportlab optional) report renderer — self-contained, print-ready |
| `warden/api/xai.py` | FastAPI router `/xai/*` — explain, batch, HTML report, PDF download, dashboard |
| `warden/sovereign/jurisdictions.py` | 8-jurisdiction registry (EU/US/UK/CA/SG/AU/JP/CH) + transfer rules matrix |
| `warden/sovereign/tunnel.py` | `MASQUETunnel` registry — MASQUE_H3/H2/CONNECT_TCP, TOFU pinning, health probing |
| `warden/sovereign/policy.py` | Per-tenant routing policy — BLOCK/DIRECT fallback, data-class overrides, Redis |
| `warden/sovereign/router.py` | Routing engine — picks best tunnel, compliance check, adequacy decisions |
| `warden/sovereign/attestation.py` | `SovereigntyAttestation` — HMAC-SHA256 signed, Redis 7yr TTL, verify endpoint |
| `warden/api/sovereign.py` | FastAPI router `/sovereign/*` — jurisdictions, tunnels, policy, route, attest, report |
| `warden/billing/pricing.py` | **Canonical price list (FM-7)** — `TIER_PRICE_USD_MONTH`, `TIER_ALIASES`/`canonical_tier()`, `ANNUAL_DISCOUNT`, `TARGET_GROSS_MARGIN`, and **derived** `ANNUAL_PRICING`. Pure data, no warden imports (so `finops` can import it without a cycle) |
| `warden/billing/addons.py` | Add-on SKU registry — `ADDON_CATALOG`, grant/revoke/check (Redis), `require_addon_or_feature()` FastAPI dep (HTTP 403 tier too low / 402 not purchased) |
| `warden/billing/router.py` | Billing API — tier catalog (sold plans only), addon catalog+checkout+grant+revoke, `GET /billing/margin` (revenue vs. MTD LLM cost), `_calculate_overage()` |
| `warden/finops/llm_budget.py` | Per-tenant monthly LLM allowance + soft model gate (FM-7) — `tier_llm_budget_usd`, `mtd_spend_usd`, `budget_status`, `choose_model` (fail-open, never below `candidates[0]`), `choose_platform_model`/`record_platform_cost` (platform cost centre), `month_start_ts`, `cache_savings_mtd_usd`, `margin_report` |
| `warden/billing/overage_ledger.py` | Idempotent overage settlement (FM-7) — `billing_overage_charges` keyed on `(tenant_id, period)`; `settle()`, `get_charge()`, `list_period()`; `OVERAGE_CHARGE_ENFORCED` gates whether a charge is presented to a provider |
| `scripts/finops_report.py` | FinOps CLI — unit economics per tier, per-model turn cost, compose mem-limit audit + M/G/1 capacity ceiling (`--json` for machine use) |
| `warden/communities/sep.py` | SEP core — UECIID codec (Snowflake→base-62 `SEP-{11}`) + UECIID index + Causal Transfer Proof (HMAC + optional ML-DSA-65 pqc_signature) + Sovereign Pod Tags |
| `warden/communities/peering.py` | Inter-community peering — MIRROR_ONLY/REWRAP_ALLOWED/FULL_SYNC; HMAC handshake token; `transfer_entity()` → TransferGuard → CTP → STIX audit chain |
| `warden/communities/knock.py` | Knock-and-Verify invitations — Redis-backed tokens (72h TTL); `issue_knock()`, `verify_and_accept_knock()` |
| `warden/communities/transfer_guard.py` | Causal Transfer Guard — maps SEP context → CausalArbiter evidence; blocks exfiltration (P≥0.70) in <20ms; `TRANSFER_RISK_THRESHOLD` env var |
| `warden/communities/data_pod.py` | Sovereign Data Pods — per-jurisdiction MinIO routing; `register_pod()`, `get_pod_for_entity()`, `probe_pod()`; Fernet-encrypted secret keys |
| `warden/communities/stix_audit.py` | STIX 2.1 Tamper-Evident Audit Chain — SHA-256 prev_hash chain; `append_transfer()`, `verify_chain()`, `export_chain_jsonl()`; SQLite `sep_stix_chain` |
| `warden/api/sep.py` | SEP REST API `/sep/*` — 24 endpoints: UECIID, pod tags, peerings, knock, pods CRUD+probe, audit-chain list/verify/export |
| `warden/agent/sova.py` | SOVA core — Claude Opus 4.6 agentic loop, prompt caching, tool dispatch, Redis memory |
| `warden/agent/tools.py` | 30 tool handlers + Anthropic schema defs + TOOL_HANDLERS dispatch table |
| `warden/tools/browser.py` | BrowserSandbox (Playwright headless Chromium) + `ScreencastRecorder` (video → MinIO SOC 2 evidence) |
| `warden/agent/memory.py` | Redis-backed conversation memory (sova:conv:{sid}, 6h TTL, 20-turn cap) |
| `warden/agent/scheduler.py` | 7 ARQ job functions for SOVA scheduled tasks |
| `warden/agent/healer.py` | WardenHealer — autonomous anomaly detection (CB, bypass spike, corpus DEGRADED, canary probe, OLS trend prediction, Haiku classification, SQLite recipe cache) |
| `warden/api/agent.py` | FastAPI router `/agent/sova` — query, clear session, trigger task |
| `warden/testing/context.py` | SWFE FakeContext — unified fake activation via mock.patch, X-Simulation-ID isolation |
| `warden/testing/fakes/` | SWFE fake layer — FakeAnthropicClient, FakeNvidiaClient, FakeS3Storage, FakeEvolutionEngine |
| `warden/telemetry.py` | OTel TracerProvider, gRPC exporter, `trace_stage()` context manager (all 9 pipeline stages) |
| `dashboard/` | Next.js 15.5 SOC Dashboard — App Router, TanStack Query, Recharts, Tailwind dark theme |
| `dashboard/src/lib/api.ts` | API client — stats, events, event detail, threats, roi, compliance, health, filter |
| `dashboard/src/app/(soc)/` | Route group — overview, events, events/[id], threats, sandbox, platform/metrics, platform/traces |
| `dashboard/Dockerfile` | Multi-stage Node 20 Alpine build (deps → builder → runner), port 3002 |
| `packages/ui/` | Shared DS-01 design system — 10 components (Card, Button, Badge, Input, Select, Modal, Table, Tabs, Chart, ThemeToggle) + ThemeProvider; standalone npm package, not a workspace member |
| `docker/Caddyfile` | Caddy v2 vhosts — api/app/analytics/landing/dash.shadow-warden-ai.com |
| `warden/testing/scenarios/` | SWFE Scenario DSL — ScenarioRunner, ScenarioStep, build_core_scenarios(), YAML loader |
| `docs/sla.md` | SLA text — attached to the withdrawn Pro/Enterprise plans; no sold plan carries it (internal objective only) |
| `site/src/pages/community/*.astro` | 7-page Community & Tunnel Astro SPA — `view`, `members`, `tunnel`, `integrations`, `activity`, `settings`, `new`; all data in `localStorage` key `sw_communities`; member roles (Owner/Admin/Member), join request flow, E2EE key simulation, audit log, disappearing messages, GDPR export |
| `site/src/layouts/BaseLayout.astro` | Astro base layout — navbar + footer + mobile menu + `og:image` + favicon; uses `/logo.png` (castle PNG); wraps all 40 site pages |
| `site/public/logo.png` | Shadow-Warden-AI castle logo PNG — primary brand asset on all 40 Astro pages, og:image, favicon |
| `warden/vendor_gov/registry.py` | AI Vendor Governance Register — `VendorRecord`, `DPARecord`, expiry alerts, vendor stats (BL-22) |
| `warden/financial/cost_allocation.py` | AI Cost Allocation — per-dept/vendor SQLite spend tracking, monthly summaries (BL-23) |
| `warden/financial/budget.py` | AI Budget Dashboard — budget caps, threshold alerts, approval workflow (BL-24) |
| `warden/communities/incident_register.py` | AI Incident Register — STIX-linked severity journal, auto-log from filter events (CM-35) |
| `warden/communities/supplier_risk.py` | Supplier AI Risk Assessment — 5-criteria composite scoring, peering-based (CM-36) |
| `warden/communities/prompt_library.py` | Shared Prompt Library — UECIID provenance, injection screening, community sharing (CM-37) |
| `warden/communities/training_records.py` | Employee AI Training Records — HMAC-SHA256 attestation, behavioral hooks (CM-38) |
| `warden/integrations/smb_suite.py` | SMB AI Governance Suite — single-wizard provisioning of all 7 SMB modules (IN-25) |
| `warden/api/vendor_gov.py` | FastAPI router `/vendor-gov/*` — 7 endpoints (BL-22) |
| `warden/api/cost_allocation.py` | FastAPI router `/financial/allocation/*` — 5 endpoints (BL-23) |
| `warden/api/budget.py` | FastAPI router `/financial/budget/*` — 5 endpoints (BL-24) |
| `warden/api/incident_register.py` | FastAPI router `/incidents/*` — 5 endpoints (CM-35) |
| `warden/api/supplier_risk.py` | FastAPI router `/supplier-risk/*` — 3 endpoints (CM-36) |
| `warden/api/prompt_library.py` | FastAPI router `/prompt-library/*` — 6 endpoints (CM-37) |
| `warden/api/training_records.py` | FastAPI router `/training/*` — 5 endpoints (CM-38) |
| `warden/api/smb_suite.py` | FastAPI router `/smb-suite/*` — 3 endpoints (IN-25) |
| `warden/analytics/pages/10_SMB_Governance.py` | Streamlit SMB Governance — 6 tabs: Incidents, Vendors, Training, Prompt Library, Supplier Risk, Budget |
| `warden/business_intelligence/service.py` | BI analytics — 8 functions: usage, threats, vendors, costs, compliance, benchmarks, predictions, reports (CM-39) |
| `warden/business_intelligence/repository.py` | BI SQLite cache — 15-min TTL, `cache_get/set/invalidate/purge_expired/stats` |
| `warden/business_intelligence/predictive.py` | Pure-Python OLS extrapolation — `moving_average`, `linear_trend`, `predict_next`, `r_squared`, `trend_direction` |
| `warden/business_intelligence/benchmarking.py` | Community benchmarking — `percentile`, `percentile_rank`, `benchmark_metric`, `build_benchmarks` |
| `warden/business_intelligence/router.py` | FastAPI router `/business-intelligence/*` — 11 endpoints (CM-39) |
| `warden/analytics/pages/12_Business_Intelligence.py` | Streamlit BI dashboard — 8 tabs: Usage, Threats, Vendors, Costs, Compliance, Benchmarks, Predictions, Report Builder |
| `warden/semantic_layer/__init__.py` | Semantic Layer (Headless BI) package — FE-42 |
| `warden/semantic_layer/models.py` | Pydantic models — `SemanticModel`, `Metric`, `Dimension`, `QueryObject`, `QueryResult`; dual field-name aliases for repo/engine compat |
| `warden/semantic_layer/engine.py` | `SemanticEngine` — deterministic SQL generator, 3 built-in models, access-rule enforcement, parameterised output |
| `warden/semantic_layer/api.py` | FastAPI router `/semantic-layer/*` — 5 endpoints: list/get/register models, query, AI query (Pro+ gate) |
| `warden/analytics/pages/15_Semantic_Layer.py` | Streamlit Semantic Layer — 4 tabs: Models, Query Builder, AI Query, Docs |
| `dashboard/src/app/(soc)/semantic-layer/page.tsx` | SOC Dashboard semantic-layer page — model cards, AI query widget, architecture panel |
| `warden/settings/__init__.py` | Settings Hub package — FE-43 |
| `warden/settings/models.py` | Settings Pydantic models — `AgentSettings`, `CommerceSettings`, `SemanticSettings`, `NotificationChannel` + API-router aliases |
| `warden/settings/service.py` | `SettingsService` — Redis + in-process fallback; 10 module-level shims for `/api/settings.py` compatibility |
| `warden/settings/api.py` | FastAPI router `/settings/*` — agents, notifications, commerce, semantic config |
| `warden/api/settings.py` | Original settings router — API keys, secrets, agent config, notification channels; imports shims from `warden/settings/service` |
| `warden/analytics/pages/16_Settings.py` | Streamlit Settings Hub — 6 tabs: API Keys, Secrets, Agents, Notifications, Commerce, Semantic |
| `dashboard/src/app/(soc)/settings/page.tsx` | SOC Dashboard settings status page — config snapshot, quick links |
| `warden/semantic_layer/catalog.py` | Self-Service tenant model registry — register/update/delete/list with SQLite persistence + hot-reload into SemanticEngine singleton; `bootstrap_tenant_models()` on startup |
| `warden/business_community/agentic_commerce/semantic_budget.py` | Commerce Budget Guardian — `check_budget()` reads limits from Settings Hub, queries `ai_spend` Semantic Layer model for MTD spend, returns allow/require_approval/block; `get_spend_summary()` for dashboards |
| `site/src/pages/analytics.astro` | AI Analytics Hub landing page — /analytics; 9-model grid, architecture flow, Budget Guardian + Self-Service + SOVA tool docs, SQL example, CTA |
| `site/src/components/WhatsNew.astro` | Changelog section — v5.3/v5.2/v5.1 entries, wired into index.astro |
| `site/src/pages/roadmap.astro` | /roadmap page — 25 shipped + 3 planned features, JS filter by status + tier |
| `ROADMAP.md` | Machine-readable feature registry — FE-01…FE-49, CP-22/25, IN-15, status, tier, version |
| `scripts/warden_github_scan.py` | GitHub Actions & pre-commit scan driver — `ci` mode (commit message + per-file diff, skip binaries) + `pre-commit` mode (staged diff + COMMIT_EDITMSG); `build_step_summary()` + `build_pr_comment()` renderers |
| `.github/workflows/warden-scan.yml` | GitHub Actions CI gate — triggers on push/PR to main/develop/master; per-file diff scanning, step summary table, PR comment, 90-day audit artifact, `workflow_dispatch` with `fail-on` choice |
| `.github/actions/warden-scan/action.yml` | Reusable composite action — `verdict`, `files-scanned`, `high-risk-count` outputs; wraps `warden_github_scan.py` |
| `warden/analytics/pages/17_Compliance_Scoring.py` | Streamlit compliance scoring — 4 tabs: Posture (SVG ring + Altair bar), Timeline (area chart + sparklines), Standards (drilldown cards), Evidence (download links); 30s auto-refresh |
| `warden/analytics/pages/18_ISO27001.py` | Streamlit ISO 27001:2022 — 4 tabs: Overview (KPI + theme coverage), Controls (searchable 93-item matrix), Themes (per-theme drilldown), Report (HTML + JSON links) |
| `dashboard/src/app/(soc)/compliance/page.tsx` | SOC Dashboard compliance page — real-time 5-standard posture, SVG score ring, bar chart, timeline, evidence download section |
| `dashboard/src/app/(soc)/compliance/iso27001/page.tsx` | SOC Dashboard ISO 27001 drilldown — KPI tiles, theme bars, Recharts bar chart, full 93-control searchable matrix with theme/status filters |
| `dashboard/src/app/(soc)/community/page.tsx` | SOC Dashboard Community Hub list — 4 StatCards (total/active/public/suspended), community cards sorted desc by `created_at`, click → detail; `NEXT_PUBLIC_TENANT_ID` fallback |
| `dashboard/src/app/(soc)/community/[id]/page.tsx` | SOC Dashboard Community Hub detail — 6 tabs: Overview/Members/Data/Compliance/Evolution/Analytics; WebSocket live-metrics banner (`useCommunityWebSocket`); members sorted desc by `joined_at`; dates in `dd/mm/yy` |
| `dashboard/src/hooks/useCommunityWebSocket.ts` | Community WebSocket hook — connects `wss://.../ws/community/{id}`, `WsStatus` type, 30s auto-reconnect on unclean close, unmount cleanup |
| `warden/analytics/pages/22_Community_Hub.py` | Streamlit Community Hub — 7 tabs: My Communities / Explore / Members / Data / Compliance / Evolution / Settings; `fmt_date()` dd/mm/yy helper; `st_toast()` fallback wrapper; descending date sort on all lists |
| `warden/app_factory.py` | Application Factory (v7.2) — `RouterSpec` + `register_router_safe()` (catches all `Exception`, not just `ImportError`); `register_staff_routers()` isolates the Digital Staff subsystem; `OPTIONAL_ROUTERS` registry of 30+ routers for gradual migration |
| `warden/staff/economics.py` | Unit Economics Token Tracker (v7.2) — `TokenCostTracker` SQLite per-action LLM cost (Haiku/Sonnet/Opus pricing, `cached_tokens` at 10%); `get_report()`, `get_margin_alerts()`, `get_total_cost()`, `get_cost_since()`. Every LLM path in the product records here |
| `warden/staff/a2a.py` | Agent-to-Agent Protocol (v7.2) — `A2ARouter` HMAC-SHA256 call tokens, `ALLOWED_ROUTES` whitelist, SQLite audit trail; SupportAgent → ComplianceAgent KYC pre-check |
| `warden/staff/structured_log.py` | Structured JSON Logging (v7.2) — `emit()` fixed-schema JSON lines to `warden.staff` logger; `AgentSpan` context object for correlated agent/tool lifecycle events |
| `warden/tests/test_contract_security.py` | Security Contract Tests (v7.2) — 52 invariant tests across SecretRedactor / SemanticGuard / TopologicalGatekeeper / ObfuscationDecoder / MaskingEngine |
| `warden/tests/test_staff_economics.py` | Unit tests for `TokenCostTracker` — cost computation, reporting, margin alerts |
| `warden/tests/test_staff_a2a.py` | Unit tests for `A2ARouter` — HMAC tokens, route whitelist, audit log |
| `docs/cloudflare-waf.md` | Cloudflare WAF documentation — rate limit rules, custom WAF rules, DNS/SSL config, Workers preflight stub |
| `warden/sac/guard.py` | SAC Inner Warden execution guard — screens agent tool calls (SSRF/exfil URL block fail-CLOSED via `net_guard`, secret-path denylist); first GSAM producer, metadata-only, fail-OPEN telemetry (FE-52) |
| `warden/gsam/jit_lease.py` | GSAM Hermes JIT credential lease — single-use HMAC leases on `gsam_leases`, fail-CLOSED (503 without key), secret never in response; mirrors `protocols/acp/token_vault.py` (FE-52) |
| `warden/gsam/api.py` | GSAM REST API — `/gsam/lease*` (issue/redeem/revoke/get); read surface (`/gsam/heatmap` etc.) added in a later slice (FE-52) |
| `docs/sac-architecture.md` | SAC architecture — pillar 1 (execution guard) + pillar 2 (JIT lease), config, non-goals (eBPF/Kata/COW/ZK/AMM), follow-on slices |
| `warden/gsam/drift.py` | GSAM drift math (pure) — L1/total-variation distance, EWMA drift, poisoning-gated baseline update, anti-inflation clamp |
| `warden/gsam/rollup.py` | GSAM rollup sink — folds observation batches → `gsam_agent_stats` (hourly upsert) + drift baselines; `read_agent_stats`/`read_heatmap`/`compliance_score` read helpers |
| `warden/gsam/quarantine.py` | GSAM drift quarantine — `quarantine_agent`/`is_quarantined`/`release_agent`; Redis flag + in-proc TTL fallback |
| `docs/modernization-plan-v8.md` | Deep-eng/math modernization plan — 1–100 assessment, 7-phase roadmap, cybersecurity deep-dive; Phase 1 (GSAM downstream) done |
