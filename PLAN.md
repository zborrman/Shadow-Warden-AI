# PLAN.md — Shadow Warden AI Product Roadmap

**Version 5.2 · Last updated 2026-05-31**

Product roadmap, tier feature matrix, and sprint delivery status.

---

## Delivery Blocks

### Block A — Core Gateway (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| A-01 | TopologicalGatekeeper (Betti numbers, < 2ms) | ✅ |
| A-02 | ObfuscationDecoder (base64/hex/ROT13/homoglyphs, depth-3) | ✅ |
| A-03 | SecretRedactor (15 patterns + Shannon entropy) | ✅ |
| A-04 | SemanticGuard (rule engine + compound risk) | ✅ |
| A-05 | HyperbolicBrain (MiniLM + Poincaré ball) | ✅ |
| A-06 | CausalArbiter (Bayesian DAG, do-calculus) | ✅ |
| A-07 | ERS (Redis sliding window, shadow ban ≥ 0.75) | ✅ |
| A-08 | EvolutionEngine (Claude Opus auto-rule gen, hot-reload) | ✅ |
| A-09 | Analytics + Streamlit dashboard | ✅ |
| A-10 | MinIO Evidence Vault (S3-compatible, fail-open) | ✅ |

---

### Block B — Observability & Operations (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| B-01 | PhishGuard + SE-Arbiter (URL phishing + social engineering) | ✅ |
| B-02 | Prometheus + Grafana SLO alerts (P99, 5xx, shadow ban rate) | ✅ |
| B-03 | SIEM integration (Splunk HEC + Elastic ECS) | ✅ |
| B-04 | LangChain callback (WardenCallback duck-typed) | ✅ |
| B-05 | SOVA Agent (Claude Opus 4.6, ≤10 iter, 30 tools) | ✅ |
| B-06 | ARQ cron scheduler (7 jobs) | ✅ |
| B-07 | WardenHealer (autonomous anomaly detection, LLM-free) | ✅ |
| B-08 | Uptime Monitor REST API + TimescaleDB hypertable | ✅ |
| B-09 | Financial Impact Calculator (IBM 2024 benchmarks, ROI) | ✅ |

---

### Block C — SMB Foundations (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| C-01 | SMB compose isolation (docker-compose.smb.yml) | ✅ |
| C-02 | DOCX / XLSX scanner (warden/smb/file_scan.py) | ✅ |
| C-03 | Offline Mode (9 filter layers, no external deps) | ✅ |
| C-04 | Community keypair (classical + hybrid PQC) | ✅ |
| C-05 | Email Guard (SMTP header injection + phish link + brand impersonation) | ✅ |

---

### Block D — SMB Tier Extensions (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| Q1.1 | API Key Rotation (warden/api/rotation.py) | ✅ |
| Q1.2 | Extension Risk Scoring (warden/api/extension_risk.py) | ✅ |
| Q1.3 | SMB Compliance Report PDF/JSON (warden/api/compliance_report.py) | ✅ |
| Q2.4 | Secrets Rotation Scheduler (ARQ cron, Redis warden:key_age:) | ✅ |
| Q2.5 | Agent Action Whitelist logic (warden/agentic/action_whitelist.py) | ✅ |
| Q2.6 | Agent Action Whitelist REST API (warden/api/action_whitelist.py) | ✅ |
| Q3.7 | SMB Billing Tier + Add-on gates | ✅ |
| Q3.8 | Shadow AI Dashboard for SMB | ✅ |
| Q4.10 | Knock-and-Verify invitation flow | ✅ |
| Q4.11 | STIX 2.1 Tamper-Evident Audit Chain | ✅ |
| Q4.12 | SOC Next.js Dashboard SPA | ✅ |

---

### Block E — Enterprise Pillars (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| E-01 | Post-Quantum Cryptography (HybridSigner Ed25519+ML-DSA-65, HybridKEM X25519+ML-KEM-768) | ✅ |
| E-02 | Shadow AI Governance (ShadowAIDetector, 18 providers, /24 subnet probe) | ✅ |
| E-03 | Explainable AI 2.0 (CausalChain, 9-stage DAG, HTML+PDF renderer) | ✅ |
| E-04 | Sovereign AI Cloud (8 jurisdictions, MASQUE tunnels, attestation) | ✅ |
| E-05 | MasterAgent SOC (4 sub-agents, HMAC tokens, human-in-the-loop) | ✅ |

---

### Block F — SEP Strategic Features (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| F-01 | Syndicate Exchange Protocol — UECIID codec + index | ✅ |
| F-02 | Inter-community peering (MIRROR_ONLY/REWRAP_ALLOWED/FULL_SYNC) | ✅ |
| F-03 | Knock-and-Verify invitations (Redis 72h TTL, one-time token) | ✅ |
| F-04 | Causal Transfer Guard (exfiltration P≥0.70 block, <20ms) | ✅ |
| F-05 | Sovereign Data Pods (per-jurisdiction MinIO routing, Fernet keys) | ✅ |
| F-06 | STIX 2.1 Audit Chain (SHA-256 prev_hash, OASIS-compatible JSONL) | ✅ |

---

### Block G — Secrets Governance (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| G-01 | Vault connectors: AWS SM / Azure KV / HashiCorp / GCP SM / env (metadata-only) | ✅ |
| G-02 | SQLite-backed secrets inventory — risk scoring, auto-retire, expiry tracking | ✅ |
| G-03 | Policy Engine — per-tenant governance rules, 7 violation types, compliance score | ✅ |
| G-04 | Lifecycle Manager — expiry alerts, auto-retire, rotation scheduling | ✅ |
| G-05 | FastAPI router `/secrets/*` — 14 endpoints | ✅ |
| G-06 | Feature gate — `secrets_governance` (Community Business+) + `secrets_vault` add-on $12/mo | ✅ |
| G-07 | Streamlit dashboard — 6-tab secrets governance UI | ✅ |
| G-08 | 48 tests in test_secrets_governance.py | ✅ |

---

### Block H — Obsidian Business Community Integration (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| H-01 | `warden/integrations/obsidian/note_scanner.py` — scan_note(), data classification | ✅ |
| H-02 | `warden/api/obsidian.py` — 6 endpoints: /scan, /share, /feed, /ai-filter, /reputation, /stats | ✅ |
| H-03 | `obsidian-plugin/main.ts` v4.10 — TypeScript plugin: ribbon, 5 commands, auto-scan | ✅ |
| H-04 | 25 tests in test_obsidian_integration.py (6 classes) | ✅ |

---

### Block I — OTel Distributed Tracing (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| I-01 | `warden/telemetry.py` — TracerProvider, gRPC exporter, `trace_stage()` context manager | ✅ |
| I-02 | Per-layer spans in all 9 pipeline stages (topology → ers) | ✅ |
| I-03 | Per-module inner spans in topology_guard, obfuscation, secret_redactor, semantic_guard, brain/semantic, phishing_guard | ✅ |
| I-04 | OTel Collector service (otel/opentelemetry-collector-contrib:0.103.1) | ✅ |
| I-05 | Jaeger 1.58 (OTLP gRPC → collector → Jaeger) | ✅ |
| I-06 | Helm chart values: `otel.*` + `otelCollector.*` blocks | ✅ |
| I-07 | py-spy profiling script + k6 load harness (`scripts/profile_under_load.sh`) | ✅ |
| I-08 | Redoc static docs page (docs/redoc.html) at docs.shadow-warden-ai.com | ✅ |

---

### Block J — SOC Next.js Dashboard (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| J-01 | `dashboard/` — Next.js 14.2 App Router, TanStack Query, Recharts, Tailwind dark theme | ✅ |
| J-02 | SOC Overview page — KPI cards, 24h area chart, verdict pie, threat breakdown, ROI + compliance | ✅ |
| J-03 | Events table — filter by verdict/search, pagination, click-through to detail | ✅ |
| J-04 | Event detail page — 9-stage pipeline timeline with scores | ✅ |
| J-05 | Threats page — bar chart, radar chart, 14-day stacked trend | ✅ |
| J-06 | Filter Sandbox — live `/filter` test harness with example prompts | ✅ |
| J-07 | Platform Metrics — Grafana iframe panel grid | ✅ |
| J-08 | Platform Traces — Jaeger iframe embed | ✅ |
| J-09 | `docker-compose.yml` — `dashboard` service (port 3002) | ✅ |
| J-10 | Caddyfile — `dash.shadow-warden-ai.com` vhost | ✅ |

---

### Block K — CI / Lint / Type Hardening (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| K-01 | ruff: 7 errors fixed (F401, I001×3, F541, UP037, I001) | ✅ |
| K-02 | mypy: `_sp: object → Any` in `secret_redactor._redact_inner` | ✅ |
| K-03 | CI: `--no-cache` pre-build for admin + arq-worker (corrupted layer guard) | ✅ |
| K-04 | admin/Dockerfile: `python3 -m pip` (PATH-resilient) | ✅ |
| K-05 | probe_worker: `User-Agent` header added (Cloudflare Bot Fight bypass) | ✅ |

---

### Block L — Public Community Intelligence (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| L-01 | SOVA community tools #38–40 (`search_community_feed`, `publish_to_community`, `get_community_recommendations`) | ✅ |
| L-02 | `sova_threat_sync` cross-reference community feed (4 keywords + Slack alert) | ✅ |
| L-03 | `POST /agent/sova/community/lookup` endpoint + models | ✅ |
| L-04 | `GET /public/community` unauthenticated GDPR-safe stats endpoint | ✅ |
| L-05 | `shadow-warden-ai.com/community` Storytelling Dashboard (Astro, SVG chart, live feed) | ✅ |
| L-06 | Community Defense Widget in SOC dashboard Overview page | ✅ |
| L-07 | Community Recommendations block in Event Detail page (blocked events) | ✅ |

---

### Block M — Collective Immunity & ISAC (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| M-01 | `warden/communities/reputation.py` — SQLite points ledger + badge ladder | ✅ |
| M-02 | `GET /public/leaderboard` — anonymised top-10 (no tenant_id) | ✅ |
| M-03 | Reputation points awarded automatically on `publish_to_community` tool | ✅ |
| M-04 | `warden/integrations/misp.py` — MISP REST → EvolutionEngine synthesis | ✅ |
| M-05 | SOVA tool #41 `sync_misp_feed` + `POST /agent/misp/sync` | ✅ |
| M-06 | `POST /agent/sova/community/apply/{ueciid}` — auto-apply with human-in-the-loop | ✅ |
| M-07 | `GET /public/incident/{ueciid}` — anonymised public incident card + XAI chain | ✅ |
| M-08 | `shadow-warden-ai.com/incident?id=SEP-xxx` — public incident Astro page | ✅ |
| M-09 | SOVA tool #42 `get_reputation` | ✅ |
| M-10 | Leaderboard section on community.astro (120s auto-refresh) | ✅ |

---

### Block N — SOVA + Obsidian + Slack Unification (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| N-01 | `warden/api/slack_commands.py` — Slack slash command handler (HMAC-SHA256, Block Kit, /warden scan/status/approve) | ✅ |
| N-02 | `warden/alerting.py` — `alert_obsidian_event()` Slack webhook (HIGH/BLOCK + share with UECIID) | ✅ |
| N-03 | `warden/api/obsidian.py` — `GET /obsidian/reputation` endpoint | ✅ |
| N-04 | `warden/agent/tools.py` — SOVA tools #43–45: scan_obsidian_note, get_obsidian_feed, share_obsidian_note | ✅ |
| N-05 | `warden/agent/scheduler.py` — `sova_obsidian_watchdog()` ARQ job (every 4h) | ✅ |
| N-06 | `warden/workers/settings.py` — registered sova_obsidian_watchdog cron | ✅ |
| N-07 | Lint: 6 ruff + 2 mypy errors fixed (agent.py, reputation.py, misp.py) | ✅ |

---

### Block O — Obsidian Plugin v4.18 — Sidebar + Pre-validation (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| O-01 | `WardenSidebarView` — ItemView right panel: scan result, reputation, feed, queue badge | ✅ |
| O-02 | `tagFrontmatter()` — async `processFrontMatter()` writes warden_* YAML tags | ✅ |
| O-03 | `prevalidate()` — 8 client-side regex patterns, instant PII warning before API call | ✅ |
| O-04 | `GET /obsidian/reputation` polling in sidebar (5min interval) | ✅ |
| O-05 | `styles.css` — `.warden-sidebar-*`, `.warden-pipeline-dot`, `.warden-queue-row` | ✅ |

---

### Block P — Obsidian Plugin v4.19 — Dashboard + Queue + XAI + Scheduler (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| P-01 | `buildDashboardNote()` — 5 Dataview query blocks (high-risk, scanned, distribution, flagged, clean) | ✅ |
| P-02 | `createSecurityDashboard()` — creates/opens `Warden Security Dashboard.md` | ✅ |
| P-03 | `PublishQueueItem` offline queue — `enqueueShare()`, `flushPublishQueue()`, `loadData()`/`saveData()` | ✅ |
| P-04 | Sidebar queue badge + Flush button; Settings tab queue section + Flush button | ✅ |
| P-05 | `PipelineStage` + `buildPipelineStages()` — 4-stage XAI viz derived from ScanResult | ✅ |
| P-06 | `verdictColor()` — hex mapping; modal table + sidebar mini colored dots | ✅ |
| P-07 | `scheduledScanEnabled` + `scheduledScanIntervalHours` — `startScheduledScan()` via setInterval | ✅ |
| P-08 | `manifest.json` version `1.0.0 → 4.19.0` | ✅ |
| P-09 | TypeScript compiles clean (`tsc --noEmit`) | ✅ |

---

### Block R — Billing v4.20 Enhancements (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| R-01 | `warden/billing/addons.py` — `on_prem_pack` add-on (+$29/mo, Pro+, unlocks `on_prem_deployment`) | ✅ |
| R-02 | `warden/billing/addons.py` — `community_seats` add-on (+$9/mo, stackable, +5 members/unit) | ✅ |
| R-03 | `warden/billing/addons.py` — `BUNDLE_CATALOG` + `power_user_bundle` ($29 → saves $7 vs $36) | ✅ |
| R-04 | `warden/billing/addons.py` — `grant_bundle()`, `get_seat_expansion()`, `increment_seat_units()` helpers | ✅ |
| R-05 | `warden/billing/trial.py` — NEW: 14-day Pro trial (10k req cap, no MasterAgent, Redis TTL, idempotent) | ✅ |
| R-06 | `warden/billing/feature_gate.py` — `ANNUAL_PRICING` dict (15% off: $51/$194/$703/$2541/yr) | ✅ |
| R-07 | `warden/billing/feature_gate.py` — `trial_eligible` flag per tier; `annual_pricing` in `as_dict()` | ✅ |
| R-08 | `warden/billing/router.py` — `POST /billing/trial/start`, `GET /billing/trial/status` | ✅ |
| R-09 | `warden/billing/router.py` — `GET /billing/addons/bundles`, `GET /billing/addons/bundle/{key}/checkout` | ✅ |
| R-10 | `warden/billing/router.py` — `POST /billing/community-seats/add`, `GET /billing/community-seats` | ✅ |
| R-11 | `warden/billing/router.py` — annual pricing in `/billing/tiers` response | ✅ |
| R-12 | `dashboard/src/components/ui/pricing-calculator.tsx` — interactive tier+addon+bundle calculator with annual toggle | ✅ |
| R-13 | `dashboard/src/components/ui/usage-progress.tsx` — quota progress bar, 80% upgrade CTA, 60s auto-refresh | ✅ |

---

### Block S — Community & Tunnel Web App (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| S-01 | 7-page Astro SPA: `view`, `members`, `tunnel`, `integrations`, `activity`, `settings`, `new` | ✅ |
| S-02 | Member Roles — Owner/Admin/Member hierarchy, `normalizeMember()` backward-compat, role badges, Owner-removal guard | ✅ |
| S-03 | Join Request System — pending approval flow, Approve/Decline on members page, activityLog entry | ✅ |
| S-04 | E2EE Key Simulation — `🔐 AES-256-GCM` label, `SW-PUB-`/`SW-PRV-` keypair via `crypto.getRandomValues()`, fingerprint, Export `.asc` | ✅ |
| S-05 | Search — live community search (name/ID) on `/community`; member search (USER-ID/role) on `/community/members` | ✅ |
| S-06 | GDPR Art. 20 Export — JSON download in Settings, `privateKey` excluded, `exportedAt` + legal note | ✅ |
| S-07 | Audit Log — `📊 Activity` 6th tab, `activityLog[]` in localStorage, 15+ event-type icons, owner-only Clear Log | ✅ |
| S-08 | Disappearing Messages — 24h auto-delete toggle in tunnel, persisted as `c.disappearingMessages` | ✅ |
| S-09 | Castle logo PNG (`site/public/logo.png`) on all 40 Astro pages — navbar + footer + `og:image` + favicon | ✅ |

---

## Next Sprint — Block Q (Planned)

| ID | Feature | Priority |
|----|---------|----------|
| Q-01 | DNS A record `dash.shadow-warden-ai.com → 91.98.234.160` (Cloudflare) | P0 |
| Q-02 | Analytics API live endpoints wired into dashboard (replace mock data) | P1 |
| Q-03 | `TRUSTED_ENTRY +3` reputation cron — 30-day no-report entries auto-awarded | P2 |
| Q-04 | `SEARCH_HIT +1` reputation — award on `search_community_feed` result match | P2 |
| Q-05 | MISP syslog bridge — route MISP ZMQ feed into Shadow Warden syslog sink | P3 |

---

## Production Infrastructure

| Component | URL / Location | Status |
|-----------|---------------|--------|
| API Gateway | `https://api.shadow-warden-ai.com` | ✅ Live |
| Tenant Portal | `https://app.shadow-warden-ai.com` | ✅ Live |
| Landing Page | `https://shadow-warden-ai.com` | ✅ Live |
| Redoc Docs | `https://docs.shadow-warden-ai.com` | ✅ Live |
| Community Dashboard | `https://shadow-warden-ai.com/community` | ✅ Live (Vercel) |
| Public Incident Page | `https://shadow-warden-ai.com/incident` | ✅ Live (Vercel) |
| SOC Dashboard | `https://dash.shadow-warden-ai.com` | ⚠️ Needs DNS A record |
| Grafana | `http://91.98.234.160:3000` | ✅ Live |
| Jaeger UI | `http://91.98.234.160:16686` | ✅ Live |
| Server | Hetzner Ubuntu VPS — `91.98.234.160` | ✅ Live |

---

### Block T — SMB AI Governance Suite v4.23–v4.29 (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| T-01 | Feature gates: 8 new keys in `feature_gate.py` (vendor_governance, cost_allocation, budget_dashboard, incident_register, supplier_risk, prompt_library, training_records, smb_suite) | ✅ |
| T-02 | Add-on: `smb_governance_suite` $29/mo (Individual+) in `addons.py` | ✅ |
| T-03 | BL-22: `warden/vendor_gov/registry.py` — VendorRecord + DPARecord, expiry alerts, risk tiers | ✅ |
| T-04 | BL-22: `warden/api/vendor_gov.py` — 7 endpoints at `/vendor-gov/*` | ✅ |
| T-05 | BL-22: 30+ tests in `warden/tests/test_vendor_governance.py` | ✅ |
| T-06 | BL-23: `warden/financial/cost_allocation.py` — per-dept/vendor spend, monthly summaries | ✅ |
| T-07 | BL-23: `warden/api/cost_allocation.py` — 5 endpoints at `/financial/allocation/*` | ✅ |
| T-08 | BL-23: 25+ tests in `warden/tests/test_cost_allocation.py` | ✅ |
| T-09 | BL-24: `warden/financial/budget.py` — caps, threshold alerts, approval workflow | ✅ |
| T-10 | BL-24: `warden/api/budget.py` — 5 endpoints at `/financial/budget/*` | ✅ |
| T-11 | BL-24: 20+ tests in `warden/tests/test_budget.py` | ✅ |
| T-12 | CM-35: `warden/communities/incident_register.py` — STIX-linked severity journal | ✅ |
| T-13 | CM-35: `warden/api/incident_register.py` — 5 endpoints at `/incidents/*` | ✅ |
| T-14 | CM-35: 25+ tests in `warden/tests/test_incident_register.py` | ✅ |
| T-15 | CM-36: `warden/communities/supplier_risk.py` — 5-criteria composite scoring | ✅ |
| T-16 | CM-36: `warden/api/supplier_risk.py` — 3 endpoints at `/supplier-risk/*` | ✅ |
| T-17 | CM-36: 20+ tests in `warden/tests/test_supplier_risk.py` | ✅ |
| T-18 | CM-37: `warden/communities/prompt_library.py` — UECIID + injection screening + versioning | ✅ |
| T-19 | CM-37: `warden/api/prompt_library.py` — 6 endpoints at `/prompt-library/*` | ✅ |
| T-20 | CM-37: 25+ tests in `warden/tests/test_prompt_library.py` | ✅ |
| T-21 | CM-38: `warden/communities/training_records.py` — HMAC-SHA256 attestation + behavioral hooks | ✅ |
| T-22 | CM-38: `warden/api/training_records.py` — 5 endpoints at `/training/*` | ✅ |
| T-23 | CM-38: 25+ tests in `warden/tests/test_training_records.py` | ✅ |
| T-24 | IN-25: `warden/integrations/smb_suite.py` — SMBProvisionResult + provision_suite() + health | ✅ |
| T-25 | IN-25: `warden/api/smb_suite.py` — 3 endpoints at `/smb-suite/*` | ✅ |
| T-26 | IN-25: 20+ tests in `warden/tests/test_smb_suite.py` | ✅ |
| T-27 | Streamlit: `warden/analytics/pages/10_SMB_Governance.py` — 6-tab governance dashboard | ✅ |
| T-28 | `warden/main.py` — 8 router mounts (vendor_gov, cost_allocation, budget, incidents, supplier_risk, prompt_library, training, smb_suite) | ✅ |

---

### Block U — Business Intelligence Module v4.30 (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| U-01 | `warden/business_intelligence/__init__.py` + `tests/__init__.py` | ✅ |
| U-02 | `warden/business_intelligence/models.py` — 7 Pydantic models (UsageSummary, ThreatSummary, VendorScorecard, ComplianceScore, BenchmarkResult, IncidentPrediction, ReportRequest) | ✅ |
| U-03 | `warden/business_intelligence/predictive.py` — pure-Python OLS: moving_average, linear_trend, predict_next, r_squared, trend_direction, predict_incidents | ✅ |
| U-04 | `warden/business_intelligence/benchmarking.py` — percentile, percentile_rank, benchmark_metric, build_benchmarks | ✅ |
| U-05 | `warden/business_intelligence/repository.py` — SQLite cache 15-min TTL, cache_get/set/invalidate/purge/stats | ✅ |
| U-06 | `warden/business_intelligence/service.py` — 8 analytics functions: usage, threats, vendors, costs, compliance, benchmarks, predictions, reports | ✅ |
| U-07 | `warden/business_intelligence/router.py` — 11 endpoints at `/business-intelligence/*` | ✅ |
| U-08 | `warden/business_intelligence/tests/test_intelligence.py` — 30 tests (TestPredictive, TestBenchmarking, TestRepository, TestService) | ✅ |
| U-09 | `warden/analytics/pages/12_Business_Intelligence.py` — 8-tab Streamlit BI dashboard | ✅ |
| U-10 | `warden/main.py` — BI router mount at `/business-intelligence` | ✅ |
| U-11 | `ROADMAP.md` — CM-39 row added | ✅ |
| U-12 | `site/src/data/roadmap.json` — CM-39 entry added | ✅ |
| U-13 | Lint: all ruff + mypy clean (0 errors) | ✅ |

---

### Block V — Agentic Commerce & Web3 v5.0 (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| V-01 | `warden/business_community/agentic_commerce/` — UCP/AP2/MCP procurement protocols | ✅ |
| V-02 | `warden/business_community/agentic_commerce/multi_agent/` — MultiAgentOrchestrator, claude/gemini/gpt connectors | ✅ |
| V-03 | `warden/business_community/agentic_commerce/api.py` — 10 endpoints at `/business-community/commerce/*` | ✅ |
| V-04 | `warden/business_community/agentic_commerce/ap2.py` — AP2 payment authorization protocol | ✅ |
| V-05 | `warden/business_community/agentic_commerce/mcp_bridge.py` — Model Context Protocol bridge | ✅ |
| V-06 | `warden/auth/fido.py` — FIDO2/WebAuthn passkey registration + authentication | ✅ |
| V-07 | `warden/blockchain/` — Sepolia Web3 mandate contract deployment + IPFS storage | ✅ |
| V-08 | `warden/analytics/pages/14_Agentic_Commerce.py` — Streamlit commerce dashboard | ✅ |
| V-09 | `site/src/components/` — Agentic Commerce + Web3 landing sections | ✅ |
| V-10 | `site/src/data/roadmap.json` — CM-40 Agentic Commerce entry | ✅ |

---

### Block W — Semantic Layer + Settings Hub v5.1 (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| W-01 | `warden/semantic_layer/models.py` — `SemanticModel`, `Metric`, `Dimension`, `QueryObject`, `QueryResult`; dual field-name aliases | ✅ |
| W-02 | `warden/semantic_layer/engine.py` — `SemanticEngine`: 3 built-in models, access-rule enforcement, deterministic SQL | ✅ |
| W-03 | `warden/semantic_layer/api.py` — 5 endpoints at `/semantic-layer/*`; Claude Haiku AI query (Pro+) | ✅ |
| W-04 | `warden/analytics/pages/15_Semantic_Layer.py` — Streamlit 4-tab page (Models, Query Builder, AI Query, Docs) | ✅ |
| W-05 | `dashboard/src/app/(soc)/semantic-layer/page.tsx` — SOC model cards + AI query widget | ✅ |
| W-06 | `warden/settings/models.py` — `AgentSettings`, `CommerceSettings`, `SemanticSettings`, `NotificationChannel` + 9 API aliases | ✅ |
| W-07 | `warden/settings/service.py` — `SettingsService` class + 10 module-level shims; Redis + in-memory fallback | ✅ |
| W-08 | `warden/settings/api.py` — 12 endpoints at `/settings/*` (agents, notifications, commerce, semantic) | ✅ |
| W-09 | `warden/analytics/pages/16_Settings.py` — Streamlit 6-tab Settings Hub | ✅ |
| W-10 | `dashboard/src/app/(soc)/settings/page.tsx` — SOC config status + quick links | ✅ |
| W-11 | `portal/src/app/settings/page.tsx` — +AgentsSection, +CommerceSection, +SemanticLayerSection | ✅ |
| W-12 | `warden/tests/test_settings.py` — 19 tests (models, service, API) | ✅ |
| W-13 | `ROADMAP.md` — FE-42 + FE-43 entries | ✅ |

---

### Block X — Site v5.1 Refresh (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| X-01 | Version bump v4.x → v5.1 across Navbar, Footer, Hero, AuthModal, ZeroTrustDiagram, fraud-score | ✅ |
| X-02 | Layer count 14 → 15 in Hero, Navbar, Footer, ZeroTrustDiagram, FeaturesGrid, smb.astro, Layout.astro meta | ✅ |
| X-03 | `FeaturesGrid.astro` — layer #15 Semantic Layer added; "15-Layer Defense Stack" header | ✅ |
| X-04 | `Pricing.astro` — 14-layer → 15-layer, +Semantic Layer AI Query, +Settings Hub add-on entries | ✅ |
| X-05 | `site/src/components/WhatsNew.astro` — changelog timeline (v5.1, v4.20, v4.19); wired into index.astro | ✅ |
| X-06 | `site/src/pages/roadmap.astro` — `/roadmap` page: 22 shipped + 3 planned, JS filter by status/tier | ✅ |
| X-07 | `site/src/data/roadmap.json` — CM-39 bumped to v5.1 | ✅ |
| X-08 | `site/src/pages/business-community/index.astro` — v4.30 → v5.1 badges | ✅ |
| X-09 | `@astrojs/sitemap` installed — sitemap-index.xml now generated (53 pages) | ✅ |

---

### Block Y — CI Lint + Mypy Hardening v5.1 (✅ Complete)

| ID | Fix | Status |
|----|-----|--------|
| Y-01 | 48 ruff errors fixed (45 auto-fix + 3 manual SIM102 nested-if → `and`) in 13_Settings.py and others | ✅ |
| Y-02 | 47 mypy errors resolved across 7 files | ✅ |
| Y-03 | `warden/api/settings.py` — 22 attr-defined errors fixed by adding missing model types + service shims | ✅ |
| Y-04 | `warden/settings/service.py` — `isinstance(raw, dict)` narrowing × 3 (arg-type errors) | ✅ |
| Y-05 | `warden/semantic_layer/models.py` — `SemanticModel` extended with `owner_tenant`, `created_at`, `updated_at`, `to_dict()`; Metric/Dimension dual aliases | ✅ |
| Y-06 | `warden/semantic_layer/api.py` + `engine.py` — `hasattr(block,"text")` SDK union narrowing; `type: ignore[arg-type]` | ✅ |
| Y-07 | `warden/business_community/agentic_commerce/orchestrator.py` — `isinstance(p, AgentProposal)` narrows gather results | ✅ |
| Y-08 | `warden/business_community/agentic_commerce/service.py` — vendor_id, append_transfer kwargs, new_ueciid(), type: ignore for missing financial functions | ✅ |
| Y-09 | `warden/business_community/agentic_commerce/ap2.py` — Fernet key init split to avoid bytes.encode() | ✅ |
| Y-10 | `warden/tax/invoice_generator.py` — `put_object` → `put_object_async` via asyncio.run() | ✅ |
| Y-11 | `warden/business_community/agentic_commerce/mcp_bridge.py` — `send_alert` alias; removed spurious await | ✅ |

---

### Block AA — Document Intelligence v5.4 (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| AA-01 | `warden/document_intel/converter.py` — MarkItDownConverter: file-type TTLs (PDF 24h, audio 7d, images 1h), 50 MB gate, 30s thread timeout, SHA-256 Redis cache, Prometheus metrics | ✅ |
| AA-02 | `warden/document_intel/api.py` — 6 endpoints at `/document-intel/*`: convert, convert-and-scan, convert-batch, health, formats, stats | ✅ |
| AA-03 | `warden/schemas.py` — `file_base64` + `file_filename` fields on `FilterRequest`; filter hook converts doc before 9-layer pipeline (fail-open) | ✅ |
| AA-04 | `warden/communities/doc_converter.py` — lightweight community converter; `warden/api/doc_converter.py` — `/doc-converter/*` community API | ✅ |
| AA-05 | `POST /obsidian/scan-attachment` — upload file, convert + scan; `POST /prompt-library/from-file` — convert + inject-screen + add | ✅ |
| AA-06 | SOVA tool #50 `scan_document` — base64 file → full FilterResponse via `/filter` hook | ✅ |
| AA-07 | `warden/metrics.py` — 3 Prometheus counters: `warden_doc_intel_convert_total{ext,data_class}`, `warden_doc_intel_convert_errors_total{ext,error}`, `warden_doc_intel_cache_hits_total` | ✅ |
| AA-08 | Streamlit `19_Document_Scanner.py` — upload, convert, scan, dark/light themed | ✅ |
| AA-09 | Portal `/doc-scanner/` — drag-and-drop page + server proxy (X-API-Key server-side); Sidebar: Document Scanner link | ✅ |
| AA-10 | Site `/cyber-security/document-intelligence` — dedicated static Astro page: pipeline flow, 3 integration cards, cache TTL table, env vars, Prometheus section, feature list, CTA | ✅ |
| AA-11 | `site/src/data/roadmap.json` — 6 FE-50 entries under `Cyber Security / Document Intelligence`; `site/src/pages/cyber-security/index.astro` — 📄 icon added | ✅ |
| AA-12 | `warden/tests/test_document_intel.py` — 10 tests (data-class × 3, cache, batch, error, unavailable, empty) | ✅ |
| AA-13 | SOC Dashboard `overview/page.tsx` — Document Scans widget (5 metrics); `dashboard/src/lib/api.ts` — `DocScanStats` type + `api.docScans()` | ✅ |

---

### Block AB — Real-time Compliance Dashboard v5.5 (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| AB-01 | `warden/compliance/models.py` — `Gap`, `FrameworkScore`, `ComplianceReport` dataclasses with `to_dict()` and derived `status` | ✅ |
| AB-02 | `warden/compliance/posture_service.py` — `CompliancePostureService`: 19 controls across GDPR(6)/SOC2(5)/ISO27001(4)/HIPAA(4); Redis cache 5min TTL; Pub/Sub publish on recompute | ✅ |
| AB-03 | `warden/api/compliance_report.py` — 4 new endpoints: `GET /compliance/posture/gaps`, `GET /compliance/posture/{framework}`, `POST /compliance/posture/recalculate`, `WebSocket /compliance/ws` | ✅ |
| AB-04 | SOVA tool #51 `get_compliance_report` + tool #52 `remediate_gap` | ✅ |
| AB-05 | Streamlit `21_Compliance_Dashboard.py` — 5-tab gap management (Overview/GDPR/SOC2/ISO27001/HIPAA), per-severity filter, auto-refresh 30s | ✅ |
| AB-06 | Portal `/compliance/` — SVG score ring, 4 framework cards with progress bars, gap list with "Fix →" deep-links, 30s auto-refetch | ✅ |
| AB-07 | `portal/src/app/api/compliance/route.ts` — server proxy (X-API-Key injected); Sidebar: Compliance link (ShieldCheck icon) under Settings | ✅ |
| AB-08 | `site/src/data/roadmap.json` — CP-30 entry under `Cyber Security / Compliance & Privacy` | ✅ |
| AB-09 | `warden/tests/test_compliance_posture.py` — 12 new CP-30 tests (28 total) | ✅ |

---

### Block Z — AI Analytics Hub + Commerce Budget Guardian v5.2 (✅ Complete)

| ID | Feature | Status |
|----|---------|--------|
| Z-01 | `warden/semantic_layer/engine.py` — 9 built-in models: filter_events (expanded), ers_scores (expanded), billing_usage (expanded), incidents, vendor_contracts, agentic_orders, tunnel_sessions, compliance_attestations, ai_spend | ✅ |
| Z-02 | `warden/semantic_layer/engine.py` — Redis query cache on `generate()`: SHA-256 key from QueryObject, TTL=`SEMANTIC_CACHE_TTL` (default 600s), fail-open | ✅ |
| Z-03 | `warden/semantic_layer/catalog.py` (NEW) — Self-Service tenant model registry: register/update/delete/list with SQLite persistence + hot-reload into running SemanticEngine singleton | ✅ |
| Z-04 | `warden/semantic_layer/api.py` — Catalog CRUD: GET/POST `/models/catalog`, PUT/DELETE `/models/catalog/{id}` (Pro+ gate) | ✅ |
| Z-05 | `warden/agent/tools.py` — `semantic_query()`: SOVA queries any semantic model; `list_semantic_models()`: SOVA discovers models | ✅ |
| Z-06 | `warden/business_community/agentic_commerce/semantic_budget.py` (NEW) — `check_budget()`: reads limits from Settings Hub, queries `ai_spend` Semantic Layer model for MTD spend, returns allow/require_approval/block | ✅ |
| Z-07 | `warden/business_community/agentic_commerce/service.py` — `_check_budget()` replaced with `semantic_budget.check_budget()`; `requires_approval` flag propagated through purchase workflow | ✅ |
| Z-08 | `warden/business_community/agentic_commerce/api.py` — `GET /commerce/budget`, `GET /commerce/budget/check` endpoints | ✅ |
| Z-09 | `warden/agent/tools.py` — `check_commerce_budget()`, `get_spend_summary()` SOVA tools | ✅ |
| Z-10 | `site/src/pages/analytics.astro` (NEW) — AI Analytics Hub landing page: architecture flow, 9 model grid, three pillars, SQL example, CTA | ✅ |
| Z-11 | `site/src/components/WhatsNew.astro` — v5.2 Latest: AI Analytics Hub, Budget Guardian, Self-Service Catalog | ✅ |
| Z-12 | `site/src/components/FeaturesGrid.astro` — Layer #15 updated to AI Analytics Hub (9 Models · Redis Cache · Self-Service) | ✅ |
| Z-13 | `site/src/components/Pricing.astro` — Pro+ tier: +AI Analytics Hub, +Budget Guardian, +Self-Service | ✅ |
| Z-14 | `site/src/pages/roadmap.astro` — FE-47/48/49 shipped v5.2 | ✅ |
| Z-15 | `site/src/components/Hero.astro` — v4.19 → v5.2, 170 → 190 modules, subtext updated | ✅ |
