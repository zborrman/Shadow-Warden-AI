# Shadow Warden AI

**The AI Security Gateway for the US/EU Marketplace**

Shadow Warden AI is a self-contained, GDPR-compliant security layer that sits in front of every AI request in your application. It blocks jailbreak attempts, strips secrets and PII, shadow-bans attackers, enforces agentic safety guardrails, and self-improves — all without sending sensitive data to third parties.

**Version:** 4.19 · **License:** Proprietary · **Language:** Python 3.11+

📋 **Full public roadmap →** [ROADMAP.md](ROADMAP.md)

---

## Product Tiers — v4.19

| Tier | Price | Requests/mo | Key Features |
|------|-------|-------------|--------------|
| **Starter** | Free | 1,000 | Core filter pipeline, analytics dashboard |
| **Individual** | $5/mo | 5,000 | + XAI audit add-on eligible (+$9/mo) |
| **Community Business** *(SMB)* | $19/mo | 10,000 | + File Scanner, Shadow AI Monitor, Communities (3×10), 180-day retention, Secrets Governance, one-click install |
| **Pro** | $69/mo | 50,000 | + MasterAgent, Shadow AI Discovery add-on eligible (+$15/mo) |
| **Enterprise** | $249/mo | Unlimited | + PQC (ML-DSA-65 + ML-KEM-768), Sovereign AI Cloud, all add-ons |

**Add-ons** (billed via Lemon Squeezy):

| Add-on | Price | Min Tier | Feature key |
|--------|-------|----------|-------------|
| Secrets Vault Governance | +$12/mo | Individual | `secrets_governance` |
| XAI Audit Reports | +$9/mo | Individual | `xai_reports_enabled` |
| Shadow AI Discovery | +$15/mo | Pro | `shadow_ai_enabled` |
| On-Prem Deployment Pack | +$29/mo | Pro | `on_prem_deployment` |
| Community Seats (+5 members) | +$9/mo | Community Business | stackable |
| MasterAgent | Included in Pro | Pro | `master_agent_enabled` |

**Bundles** (save vs buying separately):

| Bundle | Price | Saves | Includes |
|--------|-------|-------|---------|
| Power User Bundle | $29/mo | $7/mo | Secrets Vault + XAI Audit + Shadow AI Discovery |

**Annual billing:** 15% off all paid tiers — Individual $51/yr · Community Business $194/yr · Pro $703/yr · Enterprise $2,541/yr

**14-day Pro trial:** available to Individual and Community Business tenants — 10,000 requests, no MasterAgent, one-time per account.

Enterprise includes PQC signing (`pqc_enabled`) and Sovereign AI Cloud (`sovereign_enabled`) — not available as add-ons.

---

## What's New in v4.19

| Feature | Description |
|---------|-------------|
| **Obsidian Plugin v4.19** | `obsidian-plugin/main.ts` — 4 new capabilities: **Dataview Dashboard** (`createSecurityDashboard()` command — generates `Warden Security Dashboard.md` with 5 Dataview query blocks: high-risk notes, all scanned, data-class distribution, flagged notes, clean notes); **Offline Publish Queue** (`PublishQueueItem` interface, `enqueueShare()` on network failure, `flushPublishQueue()` retries on reconnect, sidebar badge + Flush button, persisted via `loadData()`/`saveData()`); **XAI Pipeline Visualization** (`PipelineStage` + `buildPipelineStages()` derives 4 stages from scan response — SecretRedactor → DataClassification → SemanticGuard → RiskDecision; modal table + sidebar mini colored dots with `verdictColor()` hex); **Scan Scheduler** (`scheduledScanEnabled` + `scheduledScanIntervalHours` settings, `startScheduledScan()` via `setInterval`, full Settings tab section). TypeScript compiles clean (`tsc --noEmit`). |
| **Plugin version** | `manifest.json` version bumped `1.0.0 → 4.19.0`. |

---

## What's New in v4.18

| Feature | Description |
|---------|-------------|
| **Obsidian Sidebar Panel** | `WardenSidebarView extends ItemView` — persistent right-panel sidebar registered via `registerView()`. Shows: live scan result for active note (filename, risk badge, secrets/flags, pipeline dots), community reputation (badge emoji + points + tier), community feed (last 5 entries from `/obsidian/feed`), scan/share quick-action buttons, offline queue badge. Activated via ribbon icon or `activateSidebar()`. Tracks active note via `active-leaf-change` event. Auto-refreshes reputation every 5 minutes. |
| **Frontmatter Auto-Tagging** | `tagFrontmatter(file, result)` uses `processFrontMatter()` async API to write `warden_data_class`, `warden_risk`, `warden_flags`, `warden_scanned` into note YAML — enables Dataview queries. Fires on every scan (manual + auto-scan on modify + vault batch). Graceful fallback for pre-0.16 Obsidian. |
| **Local PII Pre-Validation** | `prevalidate(content)` checks 8 client-side regex patterns (email, phone, SSN, credit card, API key, private key, password, secret keyword) before any network call. Instant red warning banner in `ScanResultModal` listing detected PII types — no round-trip needed. |
| **Reputation Endpoint** | `GET /obsidian/reputation` — returns current tenant badge/points/entry_count from `warden.communities.reputation`. Sidebar polls every 5 min; displayed as emoji badge with animated transition. |
| **Sidebar CSS** | `styles.css` extended with `.warden-sidebar-*`, `.warden-pipeline-dot`, `.warden-queue-row`, `.warden-reputation-row` classes. |

---

## What's New in v4.17

| Feature | Description |
|---------|-------------|
| **Slack Slash Command Handler** | `warden/api/slack_commands.py` — `POST /slack/command` with HMAC-SHA256 signature verification (`X-Slack-Request-Timestamp` + `X-Slack-Signature`, 300s replay window). Commands: `/warden scan <text>` (calls `/filter`), `/warden status` (calls `/health`), `/warden approve <token>` (resolves MasterAgent approval). Responds with Block Kit JSON (`response_type: ephemeral`). Mounted on FastAPI app in `warden/main.py`. |
| **Obsidian Slack Alerts** | `warden/alerting.py` — new `alert_obsidian_event()`: fires Slack webhook on HIGH/BLOCK scan (`🔴`/`🚨`) and on successful note share (📒 with UECIID). Called as `BackgroundTasks` from `/obsidian/scan` and `/obsidian/share`. GDPR-compliant: filename/risk/flags/data_class only — no note content. |
| **SOVA Obsidian Tools (#43–45)** | `warden/agent/tools.py` — `scan_obsidian_note` (#43): POST to `/obsidian/scan`, returns full risk result. `get_obsidian_feed` (#44): GET `/obsidian/feed`, returns paginated entries. `share_obsidian_note` (#45): POST to `/obsidian/share`, registers UECIID. All registered in `TOOLS` schemas + `TOOL_HANDLERS` dispatch table. |
| **Obsidian Vault Watchdog** | `warden/agent/scheduler.py` — `sova_obsidian_watchdog()` ARQ job: every 4 hours, fetches community feed, flags CLASSIFIED/PHI entries and high-volume days (≥15 entries), sends Slack alert. Registered in `warden/workers/settings.py` as `cron(sova_obsidian_watchdog, hour={0,4,8,12,16,20}, minute=45, timeout=60)`. |
| **SOVA Morning Brief extended** | `sova_morning_brief` task string extended with step 7: Obsidian vault digest via `get_obsidian_feed`. |
| **Lint + Type fixes** | `warden/api/agent.py` — 6 ruff errors fixed (I001, SIM118→SIM401, E401, UP035, UP042). 2 mypy errors fixed: `synthesize_from_intel(source, title, link)` call in `misp.py`; `_brain_guard.add_examples()` via lazy `warden.main` import in `agent.py`. `warden/communities/reputation.py` — `from collections.abc import Generator`, `class Badge(StrEnum)`. |

---

## What's New in v4.16

| Feature | Description |
|---------|-------------|
| **Reputation System** | `warden/communities/reputation.py` — SQLite points ledger: `PUBLISH_ENTRY +5`, `SEARCH_HIT +1`, `REC_ADOPTED +10`, `TRUSTED_ENTRY +3`. Badge ladder: NEWCOMER→CONTRIBUTOR (25pt)→TOP_SHARER (100pt)→GUARDIAN (300pt)→ELITE (750pt). `award_points()` fires automatically on every `publish_to_community` tool call. `GET /public/leaderboard` returns top 10 anonymised (no tenant_id) — badge + points + entry_count. |
| **MISP Connector** | `warden/integrations/misp.py` — `MISPConnector.sync()`: httpx MISP REST API (`/events/restSearch`) → extracts 14 IoC attribute types (URL, domain, IP, MD5, SHA-256, CVE, YARA, Snort…) → converts to attack descriptions → `EvolutionEngine.synthesize_from_intel()`. Config: `MISP_URL`, `MISP_API_KEY`, `MISP_LOOKBACK_DAYS` (default 7), `MISP_TAG_FILTER`. SOVA tool #41 `sync_misp_feed`. `POST /agent/misp/sync` admin endpoint. |
| **Auto-Apply Recommendations** | `POST /agent/sova/community/apply/{ueciid}` — fetches published UECIID from SEP SQLite, derives attack example, issues Redis human-in-the-loop approval token (1h TTL). Fail-open in dev (no Redis = immediate apply). On commit: awards `REC_ADOPTED +10` reputation. Resolve via `/agent/approve/{token}?action=approve`. |
| **Public Incident Page** | `GET /public/incident/{ueciid}` — anonymised incident card: verdict, risk_level, data_class, reconstructed 9-stage XAI pipeline (metadata only). `shadow-warden-ai.com/incident?id=SEP-xxx` — client-side Astro page with GDPR notice, pipeline table, CTA. 5-min browser cache. |
| **Public Leaderboard** | `GET /public/leaderboard` — top 10 reputation entries on the community page. 2-min browser cache. Leaderboard section added to `community.astro`. |
| **SOVA tools #41–42** | `sync_misp_feed` (#41): trigger MISP → Evolution Engine sync from SOVA agentic loop. `get_reputation` (#42): query community badge + points for any tenant. Both registered in `TOOL_HANDLERS`. |
| **Community Defense Widget (dashboard)** | `dashboard/src/components/ui/community-defense-widget.tsx` — live SEP feed (90s auto-refresh), SOVA search input → inline recommendations panel, "Ask SOVA" button. Placed on Overview page in 3-col grid alongside Threat breakdown. |
| **Community Recommendations (dashboard)** | `dashboard/src/components/ui/community-recommendations.tsx` — collapsible block in Event Detail page (blocked events only). MITRE ATT&CK tag from flags, SOVA lookup on expand, similar community reports list. |

---

## What's New in v4.15

| Feature | Description |
|---------|-------------|
| **SOVA Community Tools (#38–40)** | `search_community_feed` (#38): search SEP UECIID index by keyword, returns ranked results. `publish_to_community` (#39): PII-gate via `/filter` then registers UECIID in SEP hub. `get_community_recommendations` (#40): queries CommunityIntelReport + MITRE ATT&CK fallback. All in `TOOL_HANDLERS`. |
| **`sova_threat_sync` extension** | After standard CVE+ArXiv sync, cross-references community feed on 4 keywords (jailbreak, prompt injection, exfiltration, adversarial). Sends Slack alert when community matches found with recommendations. |
| **`POST /agent/sova/community/lookup`** | Single-call: search community feed + get SOVA recommendations + optional `auto_publish`. `CommunityLookupRequest/Response` models. `community-lookup` in `_MANUAL_TASKS`. |
| **Public Community Dashboard** | `shadow-warden-ai.com/community` — Storytelling Dashboard. Animated KPI counters (members, entries, attacks blocked, block rate), SVG bar chart (7-day BLOCK/HIGH/ALLOW trend), top threat categories, live incident feed. 60-second auto-refresh. Graceful fallback to placeholder numbers on API error. GDPR disclaimer. |
| **`GET /public/community`** | Unauthenticated, GDPR-safe aggregated endpoint. No tenant_id, no content. Members count (distinct tenant count), 7d trend by date, top 5 flag types (30-day), 10 most recent incidents (verdict + risk_level + date + flags only). 60-second browser cache. |

---

## What's New in v4.14

| Feature | Description |
|---------|-------------|
| **Public Redoc** | `GET /openapi-public.json` — always-public OpenAPI schema endpoint (no `DOCS_PASSWORD` auth). `docs.shadow-warden-ai.com` added to CORS allowed origins. `docs/redoc.html` updated to fetch from `/openapi-public.json` so the Caddy-served static docs site works cross-domain without credentials. Caddy already mounts `./docs/redoc.html` → `/srv/docs/index.html`. |
| **Load Profiling** | `scripts/profile_under_load.sh` fully fixed and extended. Corrected broken k6 script path (`tests/load/filter_bench.js` → `k6/load_test.js`), fixed env var (`API_KEY` → `WARDEN_API_KEY`), replaced unsupported `--vus/--duration` with `--env SCENARIO=` (baseline \| ramp \| spike \| soak \| all). Auto-detects Docker container by both `shadow-warden-warden-1` and `warden-warden`. New step 4: MinIO upload via `mc` client — flamegraph SVG + Speedscope JSON + k6 metrics + summary stored at `warden-evidence/profiles/<timestamp>/`. |
| **SLO Burn-Rate Alerts** | Two new Grafana provisioned alert rules using Google SRE multi-window burn-rate methodology. **Fast burn (critical)**: 1h + 5min windows, threshold 14.4× SLO error rate — fires when 2% of the monthly error budget burns per hour; pages immediately. **Slow burn (warning)**: 6h + 30min windows, threshold 6× — fires when 5% burns per 6h; creates ticket. AND-gate multi-window pattern eliminates false positives from transient spikes. |
| **CI: Trivy CVE Scan** | `docker-build` job now runs `aquasecurity/trivy-action@0.28.0` on `warden-ci:${{ github.sha }}` after build. CRITICAL/HIGH CVEs only; ignores unfixed; uploads SARIF to GitHub Security tab (`security-events: write` permission). `continue-on-error` so CVEs never block hotfix deploys. |
| **CI: k6 Smoke Test** | New `k6-smoke` job after `deploy` (main branch only). Installs k6 from official apt repo, runs `k6/smoke_test.js` (1 VU, 30s) against `api.shadow-warden-ai.com`. Publishes last 40 lines to GitHub job summary. Uploads `k6-results.json` + `k6-summary.json` + `k6-output.txt` as 30-day artifact. |
| **CI: pip-audit SCA** | Dedicated `pip-audit` CI job scans Python dependencies for known CVEs. Uploads `pip-audit-report.txt` as 30-day artifact. `continue-on-error` — informational, does not block merges. |
| **CI: JUnit Test Reports** | `--junitxml=results/test-{version}.xml` added to pytest command. `dorny/test-reporter@v1` publishes results as GitHub Checks (pass/fail per test visible in PR). `checks: write` permission added to `test` job. |
| **CI: Slack Deploy Notify** | `notify-deploy` job posts ✅/🚨 Slack attachment after every deploy attempt. Includes commit SHA, actor, run URL. Reads `SLACK_WEBHOOK_URL` secret; gracefully skips if unset. |
| **Dashboard Auth Gate** | `dashboard/src/middleware.ts` — Next.js edge middleware validates `warden_auth` httpOnly cookie against `DASHBOARD_API_KEY` env var. Public prefixes (`/login`, `/api/auth`, `/_next`) bypass auth. `dashboard/src/app/login/page.tsx` — dark-themed password form with show/hide toggle. `dashboard/src/app/api/auth/route.ts` — POST sets 8h cookie; DELETE clears it (logout). |
| **Dashboard Live Analytics** | `dashboard/src/lib/api.ts` rewritten — all paths corrected to `/api/v1/*` prefix. Typed exports: `EventEntry`, `StatsResponse`, `EventsResponse`, `ThreatEntry`. `overview/page.tsx`, `events/page.tsx`, `threats/page.tsx`, `events/[id]/page.tsx` all consume real API data with `placeholderData` mock fallback. |
| **OTel Adaptive Sampling** | `warden/telemetry.py` — `OTEL_SAMPLE_RATE=0.1` (ALLOW traffic, 10%) and `OTEL_SAMPLE_RATE_HIGH=1.0` (HIGH/BLOCK, 100%). `mark_high_risk(span)` sets `sampling.priority=1` for Collector tail-sampling override. Configures tail-sampling in OTel Collector without code changes. |

---

## What's New in v4.13

| Feature | Description |
|---------|-------------|
| **OTel Distributed Tracing** | `warden/telemetry.py` — `TracerProvider` + gRPC OTLP exporter + `trace_stage()` context manager. Per-layer spans in all 9 pipeline stages (topology → decision) plus per-module inner spans in topology_guard, obfuscation, secret_redactor, semantic_guard, brain, phishing_guard. OTel Collector (`otel/opentelemetry-collector-contrib:0.103.1`) + Jaeger 1.58 pipeline. Activated via `OTEL_ENABLED=true`. Zero overhead when disabled (no-op context manager). GDPR-safe span attributes — raw content is never set on spans (see Rule.md §21). py-spy profiling script + k6 load harness in `scripts/profile_under_load.sh`. |
| **SOC Next.js Dashboard** | `dashboard/` — Next.js 14.2 App Router SPA with TanStack Query v5, Recharts 2.12, Tailwind CSS dark custom theme (`surface.0-4` + `accent.*`), lucide-react icons. 8 pages: **Overview** (KPI cards + 24h area chart + verdict pie + ROI grid + compliance), **Events** (filter tabs + search + pagination + row click-through), **Event Detail** (9-stage pipeline timeline with scores), **Threats** (bar chart + radar chart + 14-day stacked trend), **Filter Sandbox** (live POST /filter harness with example prompts), **Platform Metrics** (4 Grafana iframe panels), **Platform Traces** (Jaeger iframe). Docker multi-stage build (Node 20 Alpine, `output: "standalone"`). Deployed at `dash.shadow-warden-ai.com` via Caddy vhost (pending DNS A record `→ 91.98.234.160`). |
| **CI / Lint / Type Hardening** | 7 ruff errors fixed (F401 ×2, I001 ×3, F541, UP037) across `warden/api/gdpr.py` and `warden/workers/settings.py`. mypy `attr-defined` fixed in `secret_redactor._redact_inner` (`_sp: object → Any`). `admin/Dockerfile`: `pip install` → `python3 -m pip install` (PATH-resilient; fixes exit 127 in CI). `--no-cache` pre-build for `admin` + `arq-worker` in `ci.yml` (guards against corrupted BuildKit layer cache). Probe worker `User-Agent` header added (`ShadowWarden-UptimeProbe/1.0`) — bypasses Cloudflare Bot Fight Mode 403. |

---

## What's New in v4.11

| Feature | Description |
|---------|-------------|
| **Obsidian Plugin** | `obsidian-plugin/main.ts` — TypeScript Obsidian plugin. Ribbon icon + status bar item + 5 commands: **Scan Current Note** (risk badge + secrets + data class modal), **Share Note to Community** (SEP UECIID registration), **Scan Vault** (batch scan with progress modal), **Community Feed** (paginated shared-note feed), **Check Connection** (server health ping). Auto-scan on file modify (debounced). `WardenSettingTab` with server URL, API key, community ID, auto-scan toggle, display name, max feed items. Built with esbuild (CJS, ES2018, watch + production modes). |
| **Note Scanner** | `warden/integrations/obsidian/note_scanner.py` — `scan_note(content)` parses YAML frontmatter (regex + PyYAML), infers data classification: explicit `data_class:` field wins → tag-based (phi/classified/financial/pii) → keyword scan in body → GENERAL. SecretRedactor integration: `redact(body)` → `.text` (redacted) + `.findings` (kinds). Returns `meta`, `body`, `redacted_body`, `secrets_found`, `data_class`, `word_count`, `has_frontmatter`. |
| **Obsidian REST API — 5 endpoints** | `warden/api/obsidian.py` — FastAPI router at `/obsidian/*`. `POST /scan` → risk_level (ALLOW/LOW/MEDIUM/HIGH/BLOCK), allowed bool, flags list, data_class, secrets_found, word_count, redacted_content, scanned_at. `POST /share` → SEP UECIID (blocks if secrets_found), community_id, display_name, data_class, word_count, shared_at. `GET /feed?community_id&limit` → paginated shared note list from SEP index. `POST /ai-filter` → SecretRedactor + SemanticGuard on free-form AI prompt. `GET /stats` → integration health object. |
| **Test Suite** | `warden/tests/test_obsidian_integration.py` — 25 tests across 6 classes: `TestNoteScanner` (9), `TestScanEndpoint` (6), `TestShareEndpoint` (4), `TestFeedEndpoint` (3), `TestAIFilterEndpoint` (2), `TestStatsEndpoint` (1). All pass. |
| **Plugin Build System** | `obsidian-plugin/esbuild.config.mjs` — esbuild context, obsidian + CodeMirror externals, CJS format, ES2018 target, watch (dev) / minify+exit (prod). `package.json` (TypeScript + obsidian + esbuild devDeps). `tsconfig.json` (ES6 target, ESNext module, inlineSourceMap). `styles.css` — badge colour classes (allow/low/medium/high/block), feed card styles, UECIID monospace, status-bar cursor. `manifest.json` — id `shadow-warden-ai`, minAppVersion `1.4.0`. |
| **Accessibility Widget — WCAG 2.1 AA / Section 508 / EN 301 549 / ADA** | Zero-dependency IIFE (`landing/accessibility-widget.js`, ~420 lines). Auto-detects `prefers-reduced-motion` and `prefers-contrast` on first load. Features: skip-to-content link, text resize (3 levels), high-contrast (dark/light), colour-vision LUT (Normal / Protanopia / Deuteranopia / Tritanopia via SVG `feColorMatrix`), dyslexia font (OpenDyslexic), reduce motion, enhanced focus ring (4px gold), large SVG cursor, line/word spacing, reading guide (follows pointer), ARIA live announcer, focus trap in modal, Escape-to-close, Alt+A global shortcut, `localStorage` persistence, compliance badges. Deployed to every surface: 33 landing HTML pages (`<script defer>`), Astro site (`site/src/components/AccessibilityWidget.astro` + `Layout.astro`), Next.js portal (`portal/src/components/ui/AccessibilityWidget.tsx` `'use client'` + `app/layout.tsx`), Streamlit dashboards (`warden/analytics/accessibility.py` — `inject_accessibility_widget()` called in `dashboard.py`, `2_Settings.py`, `3_Enterprise_Settings.py`, `4_Community.py`, `5_Community_Settings.py`, `6_Secrets_Governance.py`), browser extension (`browser-extension/popup/popup.html`). |
| **Coverage Boost** | `warden/tests/test_coverage_boost.py` — 55 targeted tests covering `topology_guard` (12), `worm_guard` (11), `xai/renderer` (9), `threat_intel/rule_factory` (8), `threat_intel/analyzer` (7), Redis fail-open paths (8). Raises measured coverage from 74.9% → 75.3% (CI gate ≥ 75%). |

---

## What's New in v4.9

| Feature | Description |
|---------|-------------|
| **Secrets Vault Connectors** | `warden/secrets_gov/vault_connector.py` — abstract `VaultConnector` base with 5 implementations: `AWSSecretsManagerConnector`, `AzureKeyVaultConnector`, `HashiCorpVaultConnector`, `GCPSecretManagerConnector`, `EnvVaultConnector`. All return `VaultSecretMeta` (name, vault_id, vault_type, created_at, last_rotated, expires_at, tags) — no plaintext values ever read or stored. Lazy SDK imports: missing boto3/azure-keyvault/hvac/google-cloud-secretmanager raises `RuntimeError` with install instruction. `build_connector(vault_config)` factory. |
| **Secrets Inventory** | `warden/secrets_gov/inventory.py` — SQLite-backed (`SECRETS_DB_PATH` env, default `/tmp/warden_secrets.db`). Tables: `secrets_vaults` (tenant_id, vault_type, display_name, config_enc, created_at) and `secrets_inventory` (secret_id UUID, vault_id FK, name, status, risk_score, created_at, last_rotated, expires_at, tags JSON). `upsert_secrets()` auto-retires secrets removed from vault on next sync. `_compute_risk()` scores 0–100 based on expiry days remaining + rotation age. `get_stats()` returns totals, by_status, by_vault_type, high_risk_count, vaults count. |
| **Secrets Policy Engine** | `warden/secrets_gov/policy.py` — `SecretsPolicy` dataclass (max_age_days=90, rotation_interval_days=30, alert_days_before_expiry=14, auto_retire_expired, require_expiry_date, forbidden_name_patterns, require_tags). `SecretsPolicyEngine.evaluate()` produces `PolicyViolation` list across 7 rules: max_age (high), rotation_interval (high), never_rotated (medium), expired (critical), missing_expiry (medium), forbidden_pattern (medium), missing_tag (low). `audit()` returns compliance_score 0–100, violations_by_severity breakdown, full violation list. Empty inventory scores 100.0. |
| **Lifecycle Manager** | `warden/secrets_gov/lifecycle.py` — `check_and_flag_expiry()` async, flags secrets within alert window. `retire_expired()` auto-retires past-expiry secrets. `rotate()` dispatches to vault connector's `rotate_secret()` and updates `last_rotated`. `get_rotation_schedule()` returns upcoming rotation due dates. `summary()` returns overdue_rotation + due_within_7_days counts. |
| **Secrets REST API — 14 endpoints** | `warden/api/secrets.py` — FastAPI router at `/secrets/*`. Uses `Depends()` DI (not module-level singletons) for per-request DB path from env. Vault endpoints: `GET/POST /vaults`, `DELETE /vaults/{id}`, `POST /vaults/{id}/sync`, `GET /vaults/{id}/health`. Inventory: `GET /inventory` (status/vault_id filters), `GET /inventory/expiring?within_days=30`, `GET /stats`. Lifecycle: `POST /rotate/{secret_id}`, `POST /retire/{secret_id}`, `GET /lifecycle/schedule`. Policy: `GET/PUT /policy`, `GET /policy/audit`. Report: `GET /report` (stats + compliance + lifecycle summary + expiring count + vaults). |
| **Billing Gate** | `warden/billing/feature_gate.py` — `secrets_governance`: True for community_business, pro, enterprise; False for starter/individual. `warden/billing/addons.py` — `secrets_vault` add-on: $12/mo, min_tier individual, unlocks `secrets_governance`. Allows Individual users to purchase vault governance without upgrading to Community Business. |
| **Secrets Governance Dashboard** | `warden/analytics/pages/6_Secrets_Governance.py` — 6-tab Streamlit UI: **Overview** (4 KPI metrics + by_status bar chart + by_vault_type bar chart + lifecycle health), **Inventory** (status filter select + dataframe), **Expiring Soon** (day slider 7–90 + warning count), **Vaults** (vault table + register form + sync trigger), **Policy** (form with all 7 policy fields, saves via PUT), **Audit Report** (run-on-demand compliance score + severity breakdown + violations dataframe). |
| **stdlib conflict fix** | Renamed `warden/secrets/` → `warden/secrets_gov/` to prevent Python's stdlib `secrets` module from being shadowed when `/warden` is in `sys.path`. Affects all imports: `from warden.secrets_gov.*`. |

---

## What's New in v4.8

| Feature | Description |
|---------|-------------|
| **Community Charter — Versioned Governance** | `warden/communities/charter.py` — living governance document for each community. `create_charter()` produces a DRAFT; `publish_charter()` activates it and supersedes the prior ACTIVE version. Member acceptance tracked in `community_charter_accepts`. `validate_charter_compliance(community_id, action, data_class)` gates every cross-community transfer. Fields: transparency (REQUIRED/ENCOURAGED/OPTIONAL), data_minimization (STRICT/STANDARD/RELAXED), accountability (DPO member_id), sustainability (STANDARD/ADVANCED/CERTIFIED), allowed_data_classes, prohibited_actions, auto_block_threshold. Content SHA-256 hash ensures tamper-evidence. |
| **Behavioral Baseline & Anomaly Detection** | `warden/communities/behavioral.py` — Z-score detection over 30-day rolling window. `record_event()` stores events in SQLite `behavioral_events`. `compute_baseline()` calculates mean/stddev/p99. `detect_anomaly()` classifies: NORMAL (<2σ/ALLOW), ELEVATED (≥2σ/ALERT), CRITICAL (≥3σ/BLOCK). Tracked patterns: off_hours_access, bulk_transfer, velocity_spike, data_class_shift, new_peering_burst. `list_recent_anomalies()` returns events with |z|≥2.0 joined against baselines. |
| **Community Intelligence Report** | `warden/communities/intelligence.py` — `generate_report(community_id)` aggregates 4 data sources into `CommunityIntelReport`. Weighted risk score: 40% transfer rejection rate + 35% anomaly score + 25% governance gap. Labels: SAFE (<0.15) / LOW (<0.35) / MEDIUM (<0.55) / HIGH (<0.75) / CRITICAL (≥0.75). Auto-generates recommendations (charter missing, acceptance <80%, rejection >10%, CRITICAL anomalies, revoked > active peerins). |
| **OAuth Agent Discovery** | `warden/communities/oauth_discovery.py` — 14-provider catalog (OpenAI, Anthropic, Google Gemini, GitHub Copilot, Cursor AI, Tabnine, Notion AI, Grammarly, Salesforce Einstein, Microsoft Copilot, Perplexity, Cohere, Mistral, Hugging Face). Scope-based risk escalation: `write:*`/`admin:*` → HIGH; `read:*`/`email` → MEDIUM. `register_oauth_grant()` stores grants with risk verdict in Redis. `get_risk_summary()` aggregates per community. |
| **Community Intel REST API** | `warden/api/community_intel.py` — FastAPI router at `/community-intel/*`. Charter: create, publish, get active, list, accept, pending acceptances, compliance check. Anomalies: recent feed, on-demand detect. OAuth: list grants, register, revoke, catalog. Intelligence: `GET /community-intel/{id}/report` (JSON), `/report/recommendations` (plain list). |
| **Community Dashboard (Page 4)** | `warden/analytics/pages/4_Community.py` — 7-tab Streamlit dashboard: Overview (risk gauge + KPI cards), Transfers (bar charts by data class + top targets), Peerings (policy breakdown + timeline), Charter (active charter display + member acceptance donut), Behavioral (anomaly timeline + baseline table), OAuth (grant risk table + provider breakdown), Intel (full report JSON + recommendations). |
| **Community Settings (Page 5)** | `warden/analytics/pages/5_Community_Settings.py` — dual-mode page toggled via sidebar. **Settings mode** (8 tabs): Profile, Charter (create/publish/accept), Members, Behavioral (live detect + baseline), Shadow AI (policy), File Scanner, OAuth Policy, Retention. **Integration Guide mode** (11 sections): Quick Start, Authentication, SEP Protocol, Charter API, Behavioral Analytics, OAuth Discovery, File Scanner, Sovereign Data Pods, Webhooks, STIX Audit Chain, Environment Reference. |
| **ReDoS Gate Windows Fix** | `warden/brain/evolve.py` — `_validate_regex_safety()` now runs the nested-quantifier heuristic **before** the thread-based degenerate-string timeout. Patterns like `(a+)+$` are caught instantly by heuristic without spawning a thread that deadlocks on Windows. Fixes test suite hang at 63% on Python 3.14/Windows. |
| **Security Hardening — P0/P1 Fixes** | **Fail-closed auth (#11)**: startup raises `RuntimeError` if both `WARDEN_API_KEY` and `WARDEN_API_KEYS_PATH` are unset (`ALLOW_UNAUTHENTICATED=true` required for dev/test). **VAULT_MASTER_KEY validation (#1)**: Fernet key validated at boot. **Shadow ban randomness (#3)**: `_GASLIGHT_POOL` 6→30 entries; `secrets.choice()` replaces deterministic hash-mod. **CPT drift gate (#6)**: `calibrate_from_logs()` rejects shifts >25% from prior. **Evolution ReDoS gate (#2)**: AI-generated regex validated before persistence. |

---

## What's New in v4.6

| Feature | Description |
|---------|-------------|
| **Syndicate Exchange Protocol (SEP)** | `warden/communities/sep.py` — UECIID codec (`SEP-{11 base-62}` from 64-bit Snowflake; lexicographic = chronological). UECIID index (SQLite `sep_ueciid_index`), `search_ueciids()` (prefix + display name LIKE). Causal Transfer Proof (HMAC-SHA256 signed canonical string, `verify_transfer_proof()`). Sovereign Pod Tags (jurisdiction + data_class per entity, blocks non-compliant transfers via `sovereign/jurisdictions.py`). |
| **Inter-Community Peering** | `warden/communities/peering.py` — HMAC handshake token; policies `MIRROR_ONLY`/`REWRAP_ALLOWED`/`FULL_SYNC`; `transfer_entity()` → `TransferRecord` + new UECIID in target community + CTP. Duplicate ACTIVE peering guard. `sep_peerings` + `sep_transfers` SQLite tables. |
| **Knock-and-Verify Invitations** | `warden/communities/knock.py` — one-time Redis tokens (72h TTL). `issue_knock()`, `verify_and_accept_knock()` asserts `invitee_tenant_id == claiming_tenant_id` → `invite_member()`. `revoke_knock()`, `list_pending_knocks()`. |
| **SEP REST API — 18 endpoints** | `/sep/*`: UECIID resolve/search/list/register, pod-tag CRUD, peerings CRUD + accept + transfer + proof-verify, knock issue/accept/revoke/list. |

---

## What's New in v4.5

| Feature | Description |
|---------|-------------|
| **Add-on Monetization** | `warden/billing/addons.py` — `ADDON_CATALOG` (3 SKUs); `grant_addon()`/`revoke_addon()`/`has_addon()` (Redis set + in-memory fallback); `require_addon_or_feature()` FastAPI dep (HTTP 403 = tier too low, HTTP 402 = add-on not purchased). |
| **Pricing Update** | Pro: $49 → $69/mo. Enterprise: $199 → $249/mo. Shadow AI Discovery add-on (+$15/mo, Pro+). XAI Audit add-on (+$9/mo, Individual+). |
| **Feature Gates** | `master_agent_enabled` (Pro+), `shadow_ai_enabled` (Enterprise or add-on), `xai_reports_enabled` (Pro+ or add-on), `sovereign_enabled` (Enterprise only), `pqc_enabled` (Enterprise only). |

---

## What's New in v4.4

| Feature | Description |
|---------|-------------|
| **Sovereign AI Cloud** | `warden/sovereign/` — 8-jurisdiction registry (EU/US/UK/CA/SG/AU/JP/CH); MASQUE_H3/H2/CONNECT_TCP tunnels with TOFU TLS pinning; per-tenant routing policy (BLOCK/DIRECT fallback, data-class overrides); HMAC-SHA256 signed sovereignty attestations (7-year Redis TTL). 16 endpoints at `/sovereign/*`. Enterprise-only gate. |

---

## What's New in v4.3

| Feature | Description |
|---------|-------------|
| **Explainable AI 2.0** | `warden/xai/` — 9-stage pipeline DAG (`build_chain()`); primary cause attribution + counterfactual remediations per non-PASS stage; self-contained HTML report with SVG risk gauge; reportlab PDF (fallback to HTML); `/xai/*` REST API (explain, batch, HTML, PDF, dashboard). |

---

## What's New in v4.2

| Feature | Description |
|---------|-------------|
| **Shadow AI Governance** | `warden/shadow_ai/` — 18-provider AI fingerprint DB; async /24 subnet probe (max 50 concurrent, 3s timeout); DNS telemetry classifier; per-tenant MONITOR/BLOCK_DENYLIST/ALLOWLIST_ONLY policy; Redis findings store (1,000-entry cap). `/shadow-ai/*` REST API. SOVA tool #29 (`scan_shadow_ai`) fully implemented. |

---

## What's New in v4.1

| Feature | Description |
|---------|-------------|
| **Post-Quantum Cryptography** | `warden/crypto/pqc.py` — `HybridSigner` (Ed25519 + ML-DSA-65 / FIPS 204) and `HybridKEM` (X25519 + ML-KEM-768 / FIPS 203) via liboqs-python (fail-open). Hybrid signature = Ed25519 (64B) + ML-DSA-65 (3309B). Hybrid KEM shared secret = HKDF-SHA256(X25519_ss XOR mlkem_ss[:32]). `upgrade_to_hybrid()` for existing community keypairs. Enterprise-only gate. |

---

## What's New in v4.0

| Feature | Description |
|---------|-------------|
| **MasterAgent** | `warden/agent/master.py` — supervisor loop with 4 specialist sub-agents (SOVAOperator, ThreatHunter, ForensicsAgent, ComplianceAgent). HMAC-SHA256 task tokens prevent cross-agent injection. Human-in-the-Loop: `REQUIRES_APPROVAL` actions → Slack webhook → Redis pending (1h TTL) → `POST /agent/approve/{token}`. `run_master_batch()` for 50%-discount scheduled jobs. |
| **SOVA tools #29–30** | `scan_shadow_ai(subnet)` calls `ShadowAIDetector.scan()` directly. `explain_decision(request_id)` returns 9-stage causal chain + plain-English brief. |

---

## What's New in v3.3

| Feature | Description |
|---------|-------------|
| **ScreencastRecorder** | `BrowserSandbox` now supports `record_video=True` — Playwright records the full browser session as a WebM file. `ScreencastRecorder` context manager wraps any browser audit run and ships the video to MinIO Evidence bucket (`screencasts/<session_id>.webm`) on exit via `s3.ship_screencast()`. Fail-open: MinIO unavailable never blocks the caller. |
| **visual_assert_page (SOVA tool #28)** | New SOVA tool: navigates to a URL with headless Chromium, captures a full-page PNG screenshot, and sends it to Claude Vision (claude-opus-4-6) for analysis. Supports a custom `assertion` prompt — e.g. "confirm no error banners". Fail-open when `ANTHROPIC_API_KEY` absent. Screenshot bytes always returned even when vision is skipped. |
| **WardenHealer** | Autonomous self-healing agent (`warden/agent/healer.py`). Runs 4 checks per cycle: (1) circuit breaker state, (2) bypass spike >15%, (3) corpus DEGRADED detection with remediation instructions, (4) canary probe (safe request must always pass). `HealReport` + `HealAction` dataclasses with `summary()` rendering. `sova_corpus_watchdog` now delegates to `WardenHealer` — no LLM overhead on the happy path. |
| **sova_visual_patrol** | New ARQ cron job, nightly 03:00 UTC. Uses `ScreencastRecorder` to bind a browser session to `patrol-<YYYYMMDD-HHmm>`, then calls `visual_assert_page` on configurable endpoints (`/health`, `DASHBOARD_URL`, `PATROL_URLS`). Sends targeted Slack alerts when vision analysis flags issues. Full WebM screencast shipped to MinIO as SOC 2 evidence. 7 SOVA cron jobs total. |
| **Chapter Markers — SWFE ScenarioRunner** | `ScenarioStep.chapter` field groups steps under named sections. `Scenario.add_chapter(name, **kwargs)` opens a new chapter on the first step. `ScenarioResult.summary()` renders `── chapter ──` dividers between groups. `StepResult.chapter` carries the label for programmatic access. Backwards-compatible (empty chapter = no divider). |

---

## Roadmap 2026–2027

### v4.11 — Real-Time Threat Collaboration _(Q3 2026)_

| Feature | Description |
|---------|-------------|
| **Warden Nexus Live Feed** | Federated STIX 2.1 threat-indicator sharing across the Shadow Warden fleet — only SHA-256 fingerprints and Betti topology numbers (β₀/β₁) shared, never payload text or PII. Bayesian consensus gate (Trust_Score ≥ 0.80 requires 3+ independent nodes) prevents network poisoning. Enterprise air-gap mode: `THREAT_FEED_RECEIVE_ONLY=true`. |
| **MITRE ATT&CK Mapping** | Auto-map every BLOCK/HIGH decision to MITRE ATT&CK for LLMs technique IDs. STIX export enriched with `technique_id`, `tactic`, `kill_chain_phase`. Compliance report generator produces ATT&CK coverage heat-map. |
| **SOC 2 Type II Automation** | Scheduled evidence collection from Evidence Vault + ScreencastRecorder + STIX audit chain → ZIP archive with auditor-ready control narratives. `/compliance/soc2/collect` triggers full collection. Auto-emails to designated auditor address. |

---

### v4.12 — AI Model Firewall _(Q4 2026)_

| Feature | Description |
|---------|-------------|
| **Output Semantic Guard** | Mirror of the input pipeline applied to LLM responses before delivery. Catches prompt-injection echoes, hallucinated credentials, and covert data exfiltration in model output. P99 < 5ms using shared MiniLM singleton. |
| **Model Provenance Chain** | Cryptographically signed attestation per LLM call: model ID, version, system-prompt hash, response hash. Stored in Evidence Vault. Enables litigation-grade proof that a specific model version produced a specific output. |
| **Multi-Model Router** | Route requests by data class: PHI → on-prem model only, FINANCIAL → EU-jurisdiction model, GENERAL → cost-optimized cloud. `ModelRouter` honours Sovereign AI Cloud jurisdiction policy and billing tier. |

---

### v4.14 — Enterprise Identity & Access _(Q1 2027)_

| Feature | Description |
|---------|-------------|
| **SCIM 2.0 Provisioning** | Auto-provision/deprovision tenant users from Okta, Azure AD, Google Workspace. SCIM Groups map to community membership and clearance levels. `SCIM_BEARER_TOKEN` env var. |
| **SAML 2.0 SSO** | `warden/auth/saml.py` — SP-initiated SAML flow; `AuthnRequest` signed with tenant Ed25519 key. Attribute mapping: `email` → tenant, `groups` → community roles. Dashboard login via SAML assertion redirect. |
| **Hardware Security Module (HSM)** | PKCS#11 bridge for community keypairs and VAULT_MASTER_KEY on Enterprise tier. Supports YubiHSM 2, AWS CloudHSM, Azure Managed HSM. Ed25519 + ML-DSA-65 signing operations execute inside HSM boundary — private key material never in process memory. |

---

## What's New in v3.2

| Feature | Description |
|---------|-------------|
| **SOVA Autonomous Agent** | Shadow Operations & Vigilance Agent — Claude Opus 4.6 agentic loop with 27 tool handlers covering all Shadow Warden subsystems. Interactive endpoint `POST /agent/sova` supports multi-turn conversations via `session_id`. Six ARQ cron jobs run autonomously: morning brief (08:00), threat sync (every 6h), key rotation check (02:00), SLA report (Monday), upgrade scan (Sunday), corpus watchdog (every 30min). Prompt caching on system prompt cuts repeated-call cost by ~70%. |
| **28 SOVA Tool Suite** | `get_health`, `get_stats`, `get_config`, `update_config`, `list_threats`, `refresh_threat_intel`, `dismiss_threat`, `list_communities`, `get_community`, `rotate_community_key`, `get_rotation_progress`, `list_community_members`, `list_monitors`, `get_monitor_status`, `get_monitor_uptime`, `get_monitor_history`, `get_financial_impact`, `get_cost_saved`, `get_billing_quota`, `generate_proposal`, `list_agents`, `get_agent_activity`, `revoke_agent`, `get_tenant_impact`, `send_slack_alert`, `filter_request`, `get_compliance_art30`, `visual_assert_page`. |
| **Redis Conversation Memory** | `sova:conv:{session_id}` — 6h TTL, 20-turn cap, fail-open when Redis unavailable. Persistent state via `sova:state:{key}` (30d TTL) for rotation timestamps, brief timestamps, etc. |
| **Named Docker Volume** | `warden-models` named volume replaces bind-mount `./warden/models`. ONNX model persists across git operations and full container rebuilds. CI export step now checks model existence first and uses `--name warden-onnx-export` + skip-if-running guard to prevent OOM from duplicate export containers (root cause of 22-container RAM exhaustion). |

---

## What's New in v3.0

| Feature | Description |
|---------|-------------|
| **SaaS Uptime Monitor** | Built-in website/service monitoring. `POST /monitors/` creates HTTP, SSL, DNS, or TCP checks at configurable intervals (10s–1h). Background `probe_scheduler` runs all active monitors as asyncio tasks. Results stored in TimescaleDB hypertable with 1-day chunks, BRIN + composite indexes, automatic columnar compression after 7 days (~90% ratio), 30-day raw retention and 2-year aggregate retention. |
| **TimescaleDB** | Replaced `postgres:16-alpine` with `timescale/timescaledb:latest-pg16` (fully PostgreSQL-compatible). Continuous aggregate `probe_hourly` refreshes every 30 minutes and powers uptime % / avg latency dashboards with no per-query fan-out. |
| **Uptime REST API** | 8 new endpoints under `/monitors/*`: create, list, get, patch, delete, `/status` (latest probe), `/uptime?hours=N` (aggregate), `/history?limit=N` (raw probes). All tenant-scoped via standard `X-API-Key`. |
| **Real-time WebSocket Push** | `/ws/monitor/{id}` streams probe results as they land via Redis Pub/Sub → asyncio.Queue bridge → WebSocket. Compatible with existing Redis instance — no new infrastructure. |
| **SEC-GAP-001 Fixed** | Context field injection bypass closed. `payload.context` string values are now appended to `analysis_text` before all detection stages so ThreatVault, SemanticGuard, ML brain, and PhishGuard scan context content. ATK-005/ATK-009 now correctly return `allowed=false`. |
| **SEC-GAP-002 Fixed** | Social engineering / AI filter bypass detection added to PhishGuard SE-Arbiter. New `_FILTER_BYPASS_PATTERNS` (4 groups): AI filter bypass (`"disable safety filters"`), privileged mode override (`"developer mode"`), AI creator impersonation (`"I am your Anthropic"`), unrestricted mode request (`"no restrictions"`). Weight 0.70 in SE formula — single match pushes se_risk above 0.75 threshold. ATK-006/ATK-011 now correctly blocked. |
| **Idempotency Hardening** | Three gaps fixed: (1) LemonSqueezy webhooks — `webhook_events` dedup table prevents replay of subscription activation/cancellation events. (2) Analytics logger — in-memory `_SEEN_REQUEST_IDS` set (50k cap, O(1)) prevents duplicate NDJSON entries on retry bursts. (3) Evolution Engine — `seen_hashes` persisted into `dynamic_rules.json` so content dedup survives process restarts. |
| **Shadow Warden Fake Engine (SWFE)** | 3-level testing architecture adapted from Avito's fake system. Level 1: `FakeAnthropicClient`, `FakeNvidiaClient`, `FakeS3Storage`, `FakeEvolutionEngine` — full fake layer activated via `unittest.mock.patch`. Level 2: Scenario DSL — `ScenarioRunner` + `ScenarioStep/Scenario` dataclasses + 8 built-in scenarios (ATK-001..006, BEN-001, SLO-001) + YAML loader for QA-authored scenarios. Level 3: `FakeContext` — unified context manager with `X-Simulation-ID` request-level isolation and assertion helpers. 29 SWFE tests. |
| **Formal SLA** | `docs/sla.md` — Pro tier 99.9% monthly uptime / Enterprise 99.95%, P99 < 50ms on `/filter`, incident response P1 = 15min, credit schedule (10%/25%/50%), UptimeRobot config (1-min keyword monitor). |
| **SOC 2 Remediation (4 items)** | (1) Formal SLA documented. (2) UptimeRobot external uptime monitoring configured. (3) Causal Arbiter CPT calibration via MLE from production NDJSON logs (`calibrate_from_logs()`). (4) mlock/VirtualLock for Fernet + HMAC keys in `masking/engine.py` — SOC 2 CC6.7 key material never swaps to disk. |
| **Deploy Pipeline** | Replaced rsync (excluded `.git/`) with `git fetch + git reset --hard` on server — server git log now stays in sync with GitHub. chmod fix via Alpine container runs before git fetch to resolve Docker root-owned `.git/FETCH_HEAD`. |

---

## What's New in v2.9

| Feature | Description |
|---------|-------------|
| **Three-Tier Monetization** | Individual ($5/mo): 10 GB storage, 50 GB/mo bandwidth, 100 MB max file, 90-day retention, hard quota (no overage). Business ($49/mo): 100 GB, 500 GB/mo, 1 GB max file, 1-year retention, overage at $0.10/GB. MCP ($199/mo): 1 TB, 5 TB/mo, 5 GB max file, unlimited retention, overage at $0.04/GB with $40/TB expansion packs. |
| **Storage/Bandwidth Quota Enforcement** | `warden/communities/quota.py` — Redis counters (`warden:quota:{cid}:storage_bytes`, `warden:quota:{cid}:bw:{YYYY-MM}`) with SQLite fallback. `check_entity_size()` (HTTP 413), `check_storage_quota()`, `check_bandwidth_quota()`. `QuotaExceeded` (hard stop) and `OverageRequired` (soft stop, triggers billing) exceptions. Monthly bandwidth counter auto-resets via 31-day Redis TTL. |
| **Overage Billing** | `warden/billing/overage.py` — `resolve_overage()` tries Lemon Squeezy one-time charge → external webhook → log-only (dev). Per-GB pricing from `OVERAGE_PRICES` dict. Business 50 GB pack ($5), MCP 1 TB expansion pack ($40). `get_upgrade_url()` / `get_overage_pack_url()` provide CTA links for HTTP 402 responses. |
| **Referral Growth Mechanics** | Dropbox-style referral: `generate_referral_code()` produces `REF-{8hex}` stored in Redis with 90-day TTL. `apply_referral()` atomically consumes one-time code and awards +2 GB bonus to both referrer and referee via `apply_referral_bonus()`. Bonus tracked separately in `bonus_bytes` counter for auditability. |
| **S3-Backed Encrypted Entity Storage** | `warden/communities/entity_store.py` — S3/MinIO for raw AES-256-GCM ciphertext blobs; PostgreSQL/SQLite for metadata (kid, clearance, cek_wrapped_b64, nonce, sig, s3_key, byte_size). E2EE prevents server-side deduplication — each encrypted entity is unique regardless of content. Key format `communities/{cid}/{eid}.enc` contains no PII. Pre-signed GET URLs for zero-server-bandwidth client downloads. |
| **Retention Reaper** | `expire_entities()` soft-deletes rows past `expires_at` and releases storage quota. S3 lifecycle rules on `communities/{cid}/` prefix enforce retention at the object level (90d Individual, 365d Business, no lifecycle for MCP). `COMMUNITY_S3_BUCKET` env var. |
| **Compliance Upsell Copy** | GDPR Art. 32 "appropriate technical measures" required for personal data. CCPA up to $7,500/intentional violation. WhatsApp Business API sends PII to Meta servers — non-compliant. Pitch: "E2EE Business tunnel for $49/mo vs. €20M GDPR fine." |

---

## What's New in v2.8

| Feature | Description |
|---------|-------------|
| **Business Communities — Cryptographic Identity** | Per-community Ed25519 + X25519 keypair with `kid` versioning (`warden/communities/keypair.py`). Community_ID = UUIDv7 (time-ordered, B-tree-friendly). Member_ID = UUIDv7 scoped under community namespace (XOR + re-assert version/variant bits). Entity_ID = 64-bit Snowflake (41-bit ms timestamp + 10-bit shard + 12-bit sequence). |
| **Security Clearance Levels** | Four-tier content access model: `PUBLIC=0 / INTERNAL=1 / CONFIDENTIAL=2 / RESTRICTED=3`. Each level has an independent 32-byte AES-256-GCM key derived via HKDF-SHA256 from the X25519 private key with `info = community_id:kid:clearance:level`. Envelope encryption: random CEK per entity → wrapped with Clearance Level Key → AES-256-GCM payload. Ed25519 signature over canonical JSON (Non-repudiation). Member clearance downgrade from CONFIDENTIAL/RESTRICTED triggers mandatory Root Key Rollover. |
| **Root Key Rollover** | 4-phase lifecycle: Initiate → ARQ background CEK re-wrap → Multi-Sig confirm → Crypto Shred. ARQ worker re-wraps entity CEK ciphertext (payload bytes never touched). `ROTATION_ONLY` key stays available for re-wrap until 100% done. `crypto_shred()` NULLs private key bytes; tombstone record retained for SOC 2 audit. |
| **Break Glass Emergency Access (MCP only)** | M-of-N Multi-Sig (default 3-of-5) activates temporary key restoration. Auto-shredded after `BREAK_GLASS_TTL_S` (1h default) via `threading.Timer`. Immutable JSONL audit log satisfying SOC 2 CC7.2 and GDPR Art. 30. `PermissionError` for non-MCP tenants. BYOK/HSM path noted for standard-tier shredded keys. |
| **Multi-Sig Bridge Consensus** | SHA-256 `config_hash` is computed at proposal creation time and locked in — all signers sign `b"warden:multisig:v1:" + config_hash_bytes`. Gemini audit fix: prevents condition-substitution where signers are presented with different documents. Single-admin veto via `reject_proposal()`. 24h TTL, duplicate-signer guard, `verify_proposal_hash()` payload integrity check. |
| **Signal Double Ratchet** | HKDF-SHA256 symmetric-key ratchet with Message Keys Cache for out-of-order delivery (Gemini rec). Tier-based DH ratchet interval: individual=1 message (max forward secrecy), business=10, mcp=50 (max throughput). Both peers apply symmetric DH ratchet at the same step boundaries to stay in sync. `RatchetSession.to_dict/from_dict` for Redis state persistence. |
| **Bot_ID — Virtual Members for Integrations** | External systems (Shopify webhook, Zapier, CI) get a scoped JWT with `allowed_ips` claim (Gemini rec). IP whitelist enforced on every request — exact IP or CIDR. JTI stored in Redis; `revoke_bot_token()` invalidates immediately. Short TTL default (1h). Separate `BOT_JWT_SECRET` limits blast radius. |
| **Feature Gating** | `TIER_LIMITS` dict enforces capabilities per tier: Individual ($5) gets no Communities; Business ($49) gets Communities + Multi-Sig + Ratchet; MCP ($199) gets Break Glass + Bot_ID + BYOK. `FeatureGate.require()` / `require_capacity()` raise `PermissionError` in route handlers. `FeatureGateMiddleware` ASGI returns HTTP 403 before routes execute. |
| **REST API `/communities`** | `POST /communities` (Business+ tier), `GET /communities`, `GET /communities/{id}`, `POST /{id}/members` (generates scoped Member_ID), `PATCH /{id}/members/{mid}/clearance` (returns `rotation_required`), `DELETE /{id}/members/{mid}`, `POST /{id}/rotate` (ARQ enqueue), `GET /{id}/rotation` (progress query). |
| **PostgreSQL DDL** | `warden_core.communities`, `community_members`, `community_key_archive` tables added to `create_schema()` with 6 composite indexes. SQLite fallback for dev/test via `COMMUNITY_REGISTRY_PATH` + `COMMUNITY_KEY_ARCHIVE_PATH` env vars. |

---

## What's New in v2.7

| Feature | Description |
|---------|-------------|
| **Warden Syndicates — Zero-Trust Tunnel Network** | Encrypted peer-to-peer document exchange between independent Warden gateways. Three-step X25519 ECDH handshake (`/tunnels/handshake/init` → `/accept` → `/complete`) derives a shared AES-256 session key — never transmitted, only the public halves cross the wire. Safety number (BLAKE2b of both pubkeys) displayed in the Hub UI for out-of-band verification (Signal-style). Kill-switch (`DELETE /tunnels/{id}`) crypto-shreds the Redis key in < 1 ms, instantly revoking all future decryption. TTL Reaper ARQ worker auto-expires stale tunnels. Bandwidth quota enforcement per tunnel link. |
| **Double Shield for Tunnel Documents** | Two-stage pre-flight pipeline runs before any document enters the encrypted tunnel. **Stage 1 (Security):** WormGuard `inspect_for_ingestion()` scans for hidden RAG-poisoning instructions, prompt-injection chains, and AI-worm quine directives — poisoned documents are rejected before encryption. **Stage 2 (Privacy):** PII Masking replaces all entities with `[PERSON_1]` / `[EMAIL_1]` / `[MONEY_1]` tokens; session vault ID is returned so the receiving side can unmask LLM responses. **Stage 3 (Receiving):** Receiving gateway re-runs WormGuard on the decrypted payload — "Trust, but Verify" — and triggers kill-switch if worm is detected. |
| **Warden Syndicate Invitation System** | Cryptographically-signed invite links for onboarding new Syndicate peers. Gatekeeper generates a one-time invite token (HMAC-SHA256 scoped to tenant + expiry); accepting node redeems it to initiate the tunnel handshake. Replay protection via Redis SETNX. |
| **Warden Hub UI** | Management portal page (`/hub`) for Syndicate operators. Lists all tunnel links with status, bandwidth consumed, peer identity, and safety number. One-click kill-switch and invite-link generation. Real-time tunnel health polling. |
| **Threat Intelligence Engine** | Automated ingestion and analysis of external threat feeds (`warden/threat_intel/`). Collector fetches CVE/NVD and AI-specific threat sources on a configurable schedule. Analyzer sends each new item to Claude Haiku for structured OWASP classification, relevance scoring (threshold ≥ 0.65), and detection hint generation. Rule Factory synthesises the hint directly into the live detection pipeline — new regex patterns go through the same `ReviewQueue → RuleLedger` gate used by the Evolution Engine, new semantic examples are vetted and added to the ML corpus. No restart required. |
| **Explainable AI (XAI)** | `warden/xai/explainer.py` converts every filter decision and OutputGuard finding into a plain-English 1–3 sentence summary safe for display to business users or inclusion in PDF reports. Template mode (fast, offline, deterministic) covers all OWASP flag types. Claude Haiku mode (`XAI_USE_CLAUDE=true`) generates richer context-aware explanations; falls back to templates on error. Used by RBAC auditor dashboards and incident detail views. |
| **Agentic Mandate Validator** | AP2-style signed payment-instruction validator for AI agent pipelines (`warden/agentic/mandate.py`). Enforces six sequential security checks: agent active status → invoice hash freshness (anti-replay via one-time consumption) → HMAC-SHA256 signature → amount ≤ invoice price (anti-hallucination) → per-item spend cap → monthly budget cap. Integrates with `/mcp/quote` + `/mcp/mandate/execute` endpoints. GDPR-safe: invoice store holds only SKU, price, expiry, agent ID — no PII. |
| **Wallet Shield — Financial DoS Protection** | Token-budget enforcement per `(tenant_id, user_id)` pair (`warden/wallet_shield.py`). Pre-flight heuristic check (bytes ÷ 4) blocks oversized requests before they reach the upstream LLM. Post-call accounting records actual token counts from API usage fields. Redis sliding-window counters with configurable TTL. Protects SMB clients from LLM10 Financial DoS — a single flood attack can no longer exhaust a tenant's monthly budget overnight. Alert fires at configurable threshold (default 80% consumed). |
| **RBAC for MSP Dashboard** | Three built-in roles: `admin` (full access), `auditor` (read-only compliance — can view raw logs, download PDF reports, see XAI explanations), `viewer` (aggregated charts only). Role resolution: SAML group claim → `DASHBOARD_ROLE` env var. Auditor role designed for SOC 2 Type II evidence collection workflows. |
| **Lemon Squeezy Billing** | Sole payment processor (`warden/lemon_billing.py`). Handles VAT/GST as Merchant of Record — EU/UK compliant out of the box. HMAC-SHA256 webhook verification, subscription lifecycle hooks (`subscription_created/updated/cancelled/expired/payment_failed`), SQLite-backed idempotent event store (`webhook_events` dedup table), customer portal deep-link via `get_portal_url()`. |

## What's New in v2.6

| Feature | Description |
|---------|-------------|
| **Reversible PII Vault (`/ext/filter` + `/ext/unmask`)** | End-to-end PII masking loop for the browser extension. When `/ext/filter` detects PII (email, money, date, person, org), it masks tokens (`[EMAIL_1]`, `[MONEY_1]`, `[PERSON_1]` …) before the prompt reaches the LLM, stores the original values in an ephemeral per-session vault (2-hour TTL), and returns `pii_action="mask_and_send"` + `pii_session_id`. After the LLM replies, the extension calls `/ext/unmask` with the session ID — all `[TYPE_N]` tokens are replaced with the originals. Same entity value always maps to the same token within a session. Fail-open: unknown session IDs return text unchanged. |
| **OIDC Identity Guard** | Hybrid auth dependency (`require_ext_auth`) for the `/ext/*` routes: Bearer JWT → OIDC verification (Google & Microsoft Azure AD); `X-API-Key` header → existing key-based auth; no credentials → dev-mode pass-through. `verify_oidc_token` validates RS256 JWT, resolves tenant from email domain via `OIDC_ALLOWED_DOMAINS` env var (`domain:tenant_id` pairs), force-refreshes JWKS cache on key-ID miss. `resolve_tenant` is case-insensitive and supports runtime domain registration. |
| **Data Policy Engine** | Three-tier traffic-light classification (`GREEN / YELLOW / RED`) applied before the semantic pipeline. RED categories (financial, legal, HR, medical) are blocked from all AI providers. YELLOW categories (internal data) are restricted to local models only. Per-tenant policy overrides via `POLICY_DB_PATH` SQLite store. Blocks return HTTP 403 with `data_class` + `suggestion` detail. |
| **ARQ Async Message Queue** | Decoupled async workers via `arq` (Redis-backed). Geo-block webhook delivery and outbound email notifications run in background `arq-worker` container — the main gateway returns HTTP 200 without waiting for slow external HTTP calls. Dead-letter logging on failure. |
| **CI Test Isolation Hardening** | Fixed three classes of cross-test pollution: (1) `_clear_threat_store` session fixture deletes `blocked_ips` rows from the ThreatStore SQLite DB before each test session — prevents `testclient` IP auto-block accumulation across runs. (2) `AUTO_BLOCK_THRESHOLD=0` env var disables new auto-blocks during the test session. (3) `is_quarantined` patched to `False` in the safe-worm Jaccard test — eliminates Redis quarantine state leakage from the worm-detection test that runs first. |
| **1800 Tests** | Test suite expanded from 1688 to 1800. New coverage: OIDC guard (26 tests), PII vault round-trips and endpoint tests (14 tests), data policy classification, ARQ queue integration, and deploy workflow smoke tests. Coverage gate raised to ≥ 75% (current: ~78%). |

## What's New in v2.5

| Feature | Description |
|---------|-------------|
| **WormGuard — Zero-Click AI Worm Defense** | Three independent detection layers against Morris-II-class self-replicating prompt-injection attacks. **Layer 1** (Anti-Replication Guard): computes bigram Jaccard overlap between untrusted input and LLM output — fires when similarity ≥ 0.65 and a propagation tool (`send_email`, `http_post`, `slack_post` …) is being invoked, catching worms that force the model to copy themselves verbatim. **Layer 2** (RAG Ingestion Firewall): scans documents _before_ vectorisation — detects hidden-instruction text, self-copy quine directives, prompt-delimiter spoofing, and 6 Unicode obfuscation classes (Tag block U+E0000–U+E007F, BiDi override, fullwidth ASCII homoglyphs, HTML comment injection, Markdown invisible sections, soft-hyphen keyword splitting). **Layer 3** (Redis Quarantine): confirmed worm fingerprints (SHA-256) are broadcast via Redis stream to every Warden node; O(1) quarantine hit check short-circuits the full pipeline on repeat payloads. |
| **RAG Evolution Engine (Adaptive L2 Firewall)** | Closed feedback loop that keeps the RAG Ingestion Firewall current against novel obfuscation: blocked documents are anonymised (GDPR) and logged to a JSONL dataset → Nemotron Super 49B or Claude Opus analyses batches and generates new Python regex patterns → patterns are hot-patched into `worm_guard` at runtime with no restart. Rate-gated (4 LLM calls/hour via Redis counter). Works air-gapped without API keys. |
| **ReDoS-Safe Pattern Validation** | AI-generated regexes pass a 3-stage gate before entering production: (1) syntax check via `re.compile()`, (2) false-positive check against 8 diverse legit-document phrases, (3) ReDoS stress test — the pattern runs against a ~105 KB corpus in a `ThreadPoolExecutor` future with a 0.5 s wall-clock timeout. Patterns that don't complete are rejected with a warning. Optional `re2` (Google) fast-path eliminates super-linear patterns at compile time. |
| **TaintTracker** | Session-level taint propagation for agentic pipelines. Tracks four taint levels (`CLEAN → TAINTED → COMPROMISED → CRITICAL`) as the agent ingests untrusted content. Privilege revocation fires automatically when taint crosses the `COMPROMISED` threshold — high-blast-radius tools (`delete_file`, `deploy_code`, `send_email`) are blocked for the remainder of the session. |
| **1688 Tests** | Test suite expanded from 1684 to 1688. `TestValidatePatternReDoS` adds 4 tests covering: timeout rejection via mocked future (avoiding the CPython GIL issue that prevents `concurrent.futures.TimeoutError` from firing during C-level regex matching), false-positive gate ordering, safe pattern acceptance, and wall-clock hang regression guard. |
| **Warden Nexus — Global Threat Intelligence Network** | Federated worm fingerprint sharing across the entire Shadow Warden fleet. When `worm_guard.quarantine_worm()` confirms a worm, it spawns a fire-and-forget daemon thread that submits a **STIX 2.1 Indicator bundle** to the central Nexus feed — containing only the SHA-256 fingerprint, attack class label, and Betti topology numbers (β₀/β₁) as `x_warden_*` extension properties for polymorphic clustering. No payload text or PII ever leaves the node. The sync loop downloads globally-confirmed hashes and injects them into the local **L3 Redis quarantine** for O(1) blocking. **Bayesian consensus gate** (server-side): `Trust_Score = 1 − ∏ᵢ(1 − P(Tᵢ\|H))` — a lone attacker submitting their own SHA-256 cannot reach `Trust_Score ≥ 0.80` without corroboration from 3+ independent high-reputation nodes, preventing network poisoning DoS. **Enterprise air-gap mode**: `THREAT_FEED_RECEIVE_ONLY=true` — consume the global feed without contributing (sold as $10k/yr Intelligence Feed add-on). |

## What's New in v2.4

| Feature | Description |
|---------|-------------|
| **Browser Extension** | MV3 extension for Chrome, Firefox, and Edge. Intercepts every prompt on ChatGPT, Claude.ai, Gemini, and Copilot before it reaches the cloud. RED/YELLOW/GREEN risk zones — hard block, local-AI redirect (Ollama/LM Studio), or pass-through. Content script runs in `world: "MAIN"` so fetch requests appear from the AI site origin; popup/background use the new `/ext/*` routes with wildcard CORS. GPO/MDM support via Windows Registry or Intune/Jamf for managed enterprise deployments. |
| **`/ext/filter` + `/ext/health` routes** | Dedicated browser-extension endpoints on the gateway. `_ExtensionCORSMiddleware` returns `Access-Control-Allow-Origin: *` on all `/ext/*` responses and handles OPTIONS preflight with 204 — required because `chrome-extension://` and `moz-extension://` origins are not in the standard CORS whitelist. |
| **Extension page in portal** | New `/extension/` page in the management portal: install buttons (Chrome/Firefox/Edge), 4-step setup wizard, live API-key display with copy button, behaviour guide, protected-sites list, and GPO deployment link. |
| **CI/CD hardening** | Switched from manual SSH key writing (`printf '%s\n'`) to `webfactory/ssh-agent@v0.9.0` to eliminate `error in libcrypto` failures caused by CRLF line endings or missing final newlines in deploy keys. |

## What's New in v2.3

| Feature | Description |
|---------|-------------|
| **Dollar Impact Calculator** | Multi-layer ROI model quantifying the concrete financial value of deploying Shadow Warden: LLM inference savings (shadow ban), prevented incident costs (IBM Cost of Data Breach 2024 benchmarks with industry multipliers), compliance automation savings (Evidence Vault vs. manual audit), SecOps efficiency gains (automated triage + MTTR reduction), and reputational value. |
| **Live Metrics Integration** | `MetricsReader` reads real production data from logs.json (NDJSON), Redis ERS (shadow-banned entity count), and Prometheus (`warden_shadow_ban_cost_saved_usd_total`). All sources fail-open. |
| **Financial API Endpoints** | Four new REST endpoints: `GET /financial/impact` (full report), `GET /financial/cost-saved` (quick Prometheus read), `GET /financial/roi` (single-tier ROI), `POST /financial/generate-proposal` (sales deck JSON). All require standard API key auth. |
| **Industry Risk Multipliers** | 7 industry profiles (fintech, healthcare, ecommerce, saas, government, education, legal) with per-threat-category IBM-benchmark multipliers (e.g. healthcare PII = 3.5×, fintech compliance = 3.5×). |
| **CLI Impact Tool** | `scripts/impact_analysis.py` — standalone CLI with `--live`, `--industry`, `--requests`, `--cost`, `--export`, `--interactive`, `--json` flags. |

## What's New in v2.2

| Feature | Description |
|---------|-------------|
| **Differentiated Shadow Ban** | Shadow ban now selects response strategy by attack type: `gaslight` (prompt injection — returns subtly wrong output that breaks attacker feedback loop), `delay` (credential stuffing / bot noise — adds real async delay to slow automated tools), `standard` (default). New `_GASLIGHT_POOL` of 6 contradictory responses. |
| **β₁ Integration in Topology Guard** | 1-cycles (repetitive loop patterns) now contribute 8% to the noise score formula. Previously β₁ was computed but unused. Weights rebalanced: `0.33×char_entropy + 0.27×wc_ratio + 0.22×diversity + 0.10×β₀ + 0.08×β₁`. |
| **Adaptive Topological Thresholds** | Content-type detection (code vs. natural language) now adjusts the noise threshold dynamically. Code payloads use threshold 0.65; natural language 0.82. Eliminates false positives on legitimate code submissions. New env vars: `TOPO_NOISE_THRESHOLD_CODE`, `TOPO_NOISE_THRESHOLD_NATURAL`. |
| **Hyperbolic Numerical Stability** | Pre-projection input norm clamping added to `to_poincare_ball()` and `_to_poincare_ball_batch()`. Prevents tanh saturation for unnormalized vectors. `_MAX_INPUT_NORM = 10.0` guards against future callers passing raw (non-L2-normalized) embeddings. |
| **Business Metrics (Dollar Impact)** | Two new Prometheus counters: `warden_shadow_ban_total{strategy, last_flag}` and `warden_shadow_ban_cost_saved_usd_total`. Enables Grafana dashboards showing cumulative LLM inference cost saved by shadow-banning attackers. |
| **Availability SLO Alert** | New Grafana alert fires when success rate < 99.9% over 1 hour. Fulfills SOC 2 Type II CC7.2 / A1.2 continuous monitoring requirements. |
| **Shadow Ban Rate Alert** | New Grafana alert fires when shadow ban rate exceeds 0.2/s (12/min) for 3 minutes — signals active attack campaign. |
| **Compliance Docs** | Three new docs: `docs/security-model.md` (9-layer defense, threat model, OWASP LLM Top 10 coverage), `docs/dpia.md` (GDPR Art. 35 DPIA), `docs/soc2-evidence.md` (SOC 2 Type II evidence guide with auditor-ready collection procedures). |

## What's New in v2.1

| Feature | Description |
|---------|-------------|
| **Data-Gravity Hybrid Hub** | Evidence Vault bundles and analytics logs are persisted to on-prem MinIO (S3-compatible object storage) — not cloud. All security metadata stays inside your infrastructure. Only clean filtered tokens reach the upstream LLM. Background-threaded, fail-open, zero latency impact. |
| **MinIO in Docker Compose** | MinIO and a bucket-init sidecar are now included in `docker-compose.yml`. Enable with `S3_ENABLED=true`. Console at `:9001`. Supports AWS S3, Equinix colocation, or bare-metal via `S3_ENDPOINT`. |
| **`warden/storage/s3.py`** | New S3 storage backend module. `save_bundle(session_id, bundle)` + `ship_log_entry(entry)` — both background-threaded. Lazy boto3 import — no startup cost if disabled. Auto-creates buckets on first connect. |

## What's New in v2.0

| Feature | Description |
|---------|-------------|
| **Topological Gatekeeper (Layer 1)** | TDA pre-filter converts text to a character n-gram point cloud and computes Betti numbers (β₀ connected components, β₁ 1-cycles) to detect bot payloads, random noise, and DoS content in < 2ms — before the obfuscation decoder runs. Uses true persistent homology via `ripser` when installed; algebraic fallback otherwise. |
| **Hyperbolic Semantic Space (Layer 2)** | MiniLM embeddings are projected into the Poincaré ball (hyperbolic geometry, curvature c=1) before similarity scoring. Hyperbolic space separates hierarchically-nested multi-layer attacks ("jailbreak inside roleplay") that appear close in Euclidean cosine space but diverge near the ball boundary. Final score blends cosine (70%) + hyperbolic (30%). |
| **Causal Arbiter (Layer 3)** | Gray-zone requests (ML score in uncertainty band) are resolved by a lightweight Bayesian DAG implementing Pearl's do-calculus. P(HIGH\_RISK \| evidence) is computed from five causal nodes — Entity Risk Score, obfuscation, block history, tool tier, content entropy — with backdoor-path correction for confounded variables. Runs in ~1–5ms CPU, zero LLM calls. |

## What's New in v1.9

| Feature | Description |
|---------|-------------|
| **INJECTION_CHAIN Detection** | New agentic threat pattern fires HIGH when a tool result is blocked for injection and the agent continues issuing further tool calls — catches compromised agents acting on injected instructions from fetched content. |
| **Encrypted PII Vault** | Masking engine vault encrypts all original PII values at rest with a per-process Fernet key. Reverse-lookup map stores HMAC-SHA256 instead of plaintext — no original value ever lives unencrypted in memory. Ephemeral key regenerated on each restart. |
| **Progressive Streaming** | OpenAI proxy buffers first 400 chars for OutputGuard fast-scan, then live-emits subsequent chunks. Eliminates streaming TTFB without sacrificing output safety. Full buffer mode automatically engaged when PII masking session is active. |

## What's New in v1.8

| Feature | Description |
|---------|-------------|
| **Shadow Ban** | Attackers above the critical ERS threshold receive `allowed=true` with a plausible fake response. Real LLM never called. No feedback loop. 100% inference cost saved for flagged entities. |
| **Entity Risk Scoring (ERS)** | Redis sliding-window reputation per `tenant+IP`. Four weighted event counters (block, obfuscation, honeytrap, evolution). Escalates to shadow ban at `score ≥ 0.75`. |
| **Zero-Trust Agent Sandbox** | Every agent registers a capability manifest. Tool calls are authorized before execution. Kill-switch API revokes sessions instantly. |
| **Evidence Vault** | Per-session SHA-256 signed evidence bundles. Sign-last pattern — one byte changed anywhere = verification failure. Built for litigation and SOC 2 management assertions. |
| **Multimodal Guard** | CLIP (image jailbreaks) + Whisper+FFT (audio including ultrasonic steganography). Runs in parallel — minimal latency impact. |
| **ThreatVault 1,300+** | Curated attack signature library grows automatically via the Evolution Engine. Cross-region sync capable. |
| **WardenDoctor** | Production diagnostics & benchmarking CLI. Phase 1 health checks, Phase 2 text benchmark, Phase 3 multimodal benchmark. CI/CD JSON output. |
| **30/30 Integration Suite** | Five-level pre-release test suite (SMOKE → Compliance). All 30 tests passing before every release. |

---

## Architecture

```
POST /filter
  │
  ├─ [0]   Auth & Rate-Limit Gate          per-tenant API keys, 60 req/min Redis window
  ├─ [0.5] Redis Content-Hash Cache        5-min TTL, 0ms ML overhead on hit
  ├─ [1]   Topological Gatekeeper          n-gram point cloud → β₀/β₁ Betti numbers → noise score < 2ms
  ├─ [2]   Obfuscation Decoder             base64/hex/ROT13/Caesar/word-split/UUencode, depth-3 recursive
  ├─ [3]   Secret Redactor                 15 regex patterns + Shannon entropy scan for unknown secrets
  ├─ [4]   Semantic Guard (rules)          compound risk escalation (3+ MEDIUM → HIGH)
  ├─ [5]   Semantic Brain (ML)             MiniLM → Euclidean cosine (70%) + Poincaré ball hyperbolic (30%)
  ├─ [5.5] Causal Arbiter                  gray-zone: Bayesian DAG P(HIGH_RISK|evidence) via do-calculus
  ├─ [6]   Multimodal Guard                CLIP (images) + Whisper+FFT (audio, ultrasonic)
  ├─ [7]   Entity Risk Scoring (ERS)       Redis sliding window → shadow ban at score ≥ 0.75
  └─ [8]   Decision + Event Logger         NDJSON metadata, GDPR-safe, Prometheus metrics
             │
             ├─► EvolutionEngine (async background)    Claude Opus auto-rule synthesis
             └─► Zero-Trust Sandbox (agent calls)      capability manifests + kill-switch
```

Eleven Docker services: `proxy` (80/443), `warden` (8001), `app` (8000), `analytics` (8002), `dashboard` (8501), `postgres` (TimescaleDB), `redis`, `prometheus`, `grafana` (3000), `minio` (9000/9001), `minio-init`.

### Uptime Monitor (v3.0)

```
probe_scheduler (asyncio background task)
  ├─ HTTP probe  — httpx.AsyncClient, status_code < 500
  ├─ SSL probe   — TLS handshake, days until certificate expiry
  ├─ DNS probe   — getaddrinfo() latency
  └─ TCP probe   — asyncio.open_connection() round-trip

Results → TimescaleDB warden_core.probe_results (hypertable)
        → Redis Pub/Sub monitor:{id}:result
        → WebSocket /ws/monitor/{id} (real-time push)
        → Continuous aggregate probe_hourly (1h buckets, 30-min refresh)

REST API /monitors/*  — CRUD + /status + /uptime + /history
```

For the full stage-by-stage breakdown with latency budgets, see [docs/pipeline-anatomy.md](docs/pipeline-anatomy.md).

---

## How to Install

### Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Docker Desktop | 24.x |
| Docker Compose | v2.x |
| RAM | 4 GB (8 GB recommended) |
| Disk | 5 GB free |

### 1. Clone

```bash
git clone https://github.com/zborrman/Shadow-Warden-AI.git
cd Shadow-Warden-AI
```

### 2. Configure

```bash
cp .env.example .env
```

Key variables in `.env`:

```bash
# Required
SECRET_KEY=<random 32-byte hex>
POSTGRES_PASS=<strong password>
WARDEN_API_KEY=<your api key>

# Optional — enables Evolution Engine (Claude Opus auto-rule generation)
ANTHROPIC_API_KEY=sk-ant-...

# Optional — enables HuggingFace model downloads (CLIP, Whisper)
HF_TOKEN=hf_...

# Optional — Slack/PagerDuty alerts on HIGH/BLOCK events
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
PAGERDUTY_ROUTING_KEY=...
```

### 3. Build and start

```bash
docker compose up --build
```

First run downloads PyTorch CPU wheels (~200 MB) and `all-MiniLM-L6-v2` (~80 MB). Both are cached — subsequent starts are fast.

### 4. Verify

```bash
python scripts/warden_doctor.py --url http://localhost:80 --key $WARDEN_API_KEY
```

```
Shadow Warden AI — Production Diagnostics
==========================================
Phase 1 — Health
  Gateway        PASS   (31ms)
  Redis          PASS   (latency 0.4ms)
  Circuit Breaker PASS  (closed)
  Evolution      PASS   (engine active)
  Throughput     PASS   (60 req/min)

Phase 2 — Text Benchmark (n=20)
  Clean requests  PASS   P50=5.3ms  P99=7.2ms
  Attack requests PASS   P50=5.3ms  P99=7.2ms

All checks: 7/7 PASS
```

### 5. First request

```bash
curl -X POST http://localhost:80/filter \
  -H "X-API-Key: $WARDEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello, how are you?"}'
```

```json
{
  "allowed": true,
  "risk_level": "LOW",
  "filtered_content": "Hello, how are you?",
  "secrets_found": [],
  "semantic_flags": [],
  "processing_ms": {"total": 5.3, "ml": 4.1, "rules": 0.8}
}
```

### 6. Stop

```bash
docker compose down        # stop, keep volumes
docker compose down -v     # stop + wipe data
```

---

## Three-Layer Security Architecture (v2.0)

Shadow Warden v2.0 introduces a cascading three-layer security funnel inspired by selective chaining — compute is spent proportional to threat confidence.

### Layer 1 — Topological Gatekeeper

Runs in **< 2ms** before the obfuscation decoder. Converts text to a character n-gram point cloud and computes topological features derived from algebraic topology:

- **β₀ (connected components)** — natural language has few clusters; bot noise has many isolated components
- **β₁ (1-cycles)** — natural language is mostly acyclic; machine-generated payloads have repetitive loop structure

```
text → char trigrams → n-gram frequency map → point cloud
     → persistent homology (ripser) or algebraic fallback
     → noise_score = 0.35×char_entropy + 0.30×(1−word_char_ratio) + 0.25×diversity_noise + 0.10×β₀
     → noise_score ≥ 0.82 → TOPOLOGICAL_NOISE flag (MEDIUM risk)
```

Threshold configurable via `TOPO_NOISE_THRESHOLD`. Install `ripser` for true Vietoris-Rips persistent homology.

### Layer 2 — Hyperbolic Semantic Space

Augments the existing MiniLM cosine similarity with Poincaré ball hyperbolic geometry:

```
MiniLM embedding (384-dim, L2-normalized, Euclidean)
    ↓  expmap_0: tanh(‖v‖/2) · v / (‖v‖/2)
Poincaré ball (D^384, curvature c=1)
    ↓  d(u,v) = arcosh(1 + 2‖u−v‖² / ((1−‖u‖²)(1−‖v‖²)))
hyperbolic_similarity = 1 / (1 + d)
    ↓
final_score = 0.70 × cosine_score + 0.30 × hyperbolic_similarity
```

**Why hyperbolic?** Multi-layer jailbreaks form deep hierarchies. In Euclidean space these appear close to benign requests sharing surface vocabulary. In hyperbolic space, hierarchical depth pushes attacks toward the ball boundary — away from benign clusters. Result: fewer false positives on complex nested attacks.

Configure blend with `HYPERBOLIC_WEIGHT` (default `0.30`, set `0` to disable).

### Layer 3 — Causal Arbiter

Replaces LLM verification for gray-zone requests (ML score in `[UNCERTAINTY_LOWER, threshold)`) with a Bayesian DAG implementing Pearl's do-calculus:

```
P(HIGH_RISK | do(ML=x)) = 0.30·P(rep) + 0.20·P(content) + 0.15·P(persist)
                        + 0.15·P(tool) + 0.10·P(entropy) + 0.10·ml_score
                        − 0.05·P(rep)·P(content)   ← backdoor correction
```

Five causal nodes with conditional probability tables:

| Node | Input | Mechanism |
|------|-------|-----------|
| Reputation | ERS score | S-curve, significant above ERS = 0.35 |
| ContentRisk | Obfuscation detected | 0.82 if obfusc, 0.12 if clean |
| Persistence | Block history | S-curve, rises after 1+ blocks |
| ToolRisk | Tool tier (-1/0/1/2) | 0.10 / 0.15 / 0.55 / 0.92 |
| EntropyRisk | Content entropy | S-curve, significant above 4.5 bits/char |

Backdoor path correction removes the spurious ERS → Obfuscation correlation (both driven by latent attacker sophistication). Result: `CAUSAL_HIGH_RISK` flag at HIGH risk, zero LLM calls, ~1–5ms CPU.

---

## Shadow Ban

Traditional blocking tells attackers exactly where the wall is. They encode, mutate, and retry until something works.

Shadow Warden's answer: **ghost them**.

When an entity's ERS score crosses `0.75` (sustained attack pattern), they receive:

```json
{
  "allowed": true,
  "risk_level": "LOW",
  "filtered_content": "I'd be happy to help with that!",
  "shadow_ban": true
}
```

The real LLM backend is **never called**. The attacker sees success. The feedback loop is broken. 100% of inference cost is saved for that entity.

Minimum 5 requests required before ERS can shadow-ban (`ERS_MIN_REQUESTS=5`) — prevents false positives on first-time callers.

---

## Entity Risk Scoring (ERS)

Redis-backed sliding-window reputation system. Every request outcome feeds four event counters per entity (`tenant_id + IP`):

| Event | Weight | Triggered by |
|-------|--------|-------------|
| `block` | 0.50 | Stage 4/5 BLOCK decision |
| `obfuscation` | 0.25 | Decoded payload detected |
| `honeytrap` | 0.15 | HoneyEngine hit |
| `evolution_trigger` | 0.10 | Near-miss queued for Evolution Engine |

```
score = Σ(weight_i × rate_i)   where rate_i = count_i / total_1h
```

| Level | Score | Action |
|-------|-------|--------|
| `low` | < 0.35 | Pass |
| `medium` | 0.35–0.55 | Flag, monitor |
| `high` | 0.55–0.75 | Extra scrutiny |
| `critical` | ≥ 0.75 | **Shadow Ban** |

Reset a false-positive entity:

```bash
curl -X POST http://localhost:80/ers/reset \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -d "tenant_id=default&ip=<CLIENT_IP>"
```

---

## Dollar Impact Calculator (v2.3)

Shadow Warden quantifies its own financial value in real time — across five cost layers, seven industry profiles, and three-year projections.

### Cost Layers

| Layer | What It Measures |
|-------|-----------------|
| **Inference Savings** | LLM calls avoided because shadow-banned attackers never reach the upstream model |
| **Incident Prevention** | Weighted probability of prevented breaches × IBM Cost of Data Breach 2024 benchmarks |
| **Compliance Automation** | Evidence Vault vs. manual audit hours + GDPR fine risk reduction |
| **SecOps Efficiency** | Automated triage (95% reduction) + MTTR reduction 240h → 48h |
| **Reputational Value** | Customer churn prevention + trust premium LTV uplift |

### Industry Risk Multipliers

| Industry | PII Multiplier | Compliance Multiplier | Notes |
|----------|---------------|----------------------|-------|
| Fintech | 2.2× | 3.5× | GDPR €20M, PCI-DSS |
| Healthcare | 3.5× | 4.0× | HIPAA $100K–$1.9M per violation |
| Government | — | 2.5× | State secrets, critical infrastructure |
| E-Commerce | 1.8× | — | High API abuse rate (12%) |
| Legal | 2.5× | 3.0× | Privilege + confidentiality exposure |

### REST API

```bash
# Full ROI report (live data from logs/Redis/Prometheus)
curl -H "X-API-Key: $WARDEN_API_KEY" \
     "http://localhost:80/financial/impact?industry=fintech&live=true"

# Quick shadow-ban cost saved (reads Prometheus counter directly)
curl -H "X-API-Key: $WARDEN_API_KEY" \
     http://localhost:80/financial/cost-saved

# ROI for a specific pricing tier
curl -H "X-API-Key: $WARDEN_API_KEY" \
     "http://localhost:80/financial/roi?industry=healthcare&tier=professional"

# Generate a customer-facing sales proposal
curl -X POST http://localhost:80/financial/generate-proposal \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"industry": "fintech", "monthly_requests": 5000000,
          "target_tier": "enterprise", "customer_name": "Acme Bank"}'
```

### CLI

```bash
# Estimate from traffic volume (no live data needed)
python scripts/impact_analysis.py --industry fintech --requests 5000000

# Use live data from logs.json + Redis + Prometheus
python scripts/impact_analysis.py --live

# Export JSON report to file
python scripts/impact_analysis.py --industry healthcare --export report.json

# Interactive mode — prompts for all parameters
python scripts/impact_analysis.py --interactive
```

### Sample Report Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║               SHADOW WARDEN AI — DOLLAR IMPACT ANALYSIS                     ║
║                 Industry: FINTECH | 2026-03-26                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─ MONTHLY IMPACT BREAKDOWN ───────────────────────────────────────────────────┐
│  Inference Cost Savings (Shadow Ban)                       $        1,440    │
│  Prevented Incident Costs                                  $      312,000    │
│  Compliance Automation Savings                             $       18,750    │
│  SecOps Efficiency Gains                                   $       45,600    │
│  Reputational Value Protection                             $       41,666    │
│──────────────────────────────────────────────────────────────────────────────│
│  TOTAL MONTHLY IMPACT                                      $      419,456    │
│  TOTAL ANNUAL IMPACT                                       $    5,033,472    │
└──────────────────────────────────────────────────────────────────────────────┘

┌─ ROI BY PRICING TIER ────────────────────────────────────────────────────────┐
│  Tier               Annual Cost    Net Benefit      ROI   Payback            │
│  Startup               $5,000      $5,028,472  100569%    0.0 mo             │
│  Professional         $20,000      $5,013,472   25067%    0.0 mo             │
│  Enterprise           $80,000      $4,953,472    6191%    0.2 mo             │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Zero-Trust Agent Sandbox

Every agent registers an `AgentManifest` declaring its allowed `ToolCapability` list. `SandboxRegistry.authorize_tool_call()` returns a `SandboxDecision` before any tool invocation. Violations are logged and fed into the attestation chain.

```python
from warden.agent_sandbox import AgentManifest, ToolCapability, SandboxRegistry

manifest = AgentManifest(
    agent_id="research-agent",
    capabilities=[ToolCapability.WEB_SEARCH, ToolCapability.READ_FILE],
)
registry = SandboxRegistry()
registry.register(manifest)

decision = registry.authorize_tool_call("research-agent", "web_search", {"query": "..."})
# decision.allowed = True

decision = registry.authorize_tool_call("research-agent", "exec_shell", {"cmd": "rm -rf /"})
# decision.allowed = False — not in manifest
```

**Kill-switch API** — revoke a session instantly:

```bash
curl -X DELETE http://localhost:80/agents/sessions/{session_id} \
     -H "X-API-Key: $WARDEN_API_KEY"
```

---

## Evidence Vault

Every agent session generates a cryptographically signed evidence bundle suitable for SOC 2 audits, regulatory investigations, and litigation.

```bash
# Export evidence bundle for a session
curl -s http://localhost:80/compliance/evidence/<SESSION_ID> \
     -H "X-API-Key: $WARDEN_API_KEY" > evidence_$(date +%s).json

# Verify bundle integrity
curl -X POST http://localhost:80/compliance/evidence/verify \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "Content-Type: application/json" \
     -d @evidence_$(date +%s).json
```

SHA-256 sign-last pattern: the bundle hash covers the entire session record. One byte changed anywhere = verification fails. The live compliance score `Cs` drops from `1.0` the moment any log entry is tampered with.

---

## Multimodal Guard

Shadow Warden scans images and audio for embedded attack payloads — not just text.

**Image (CLIP):** Zero-shot classification compares image patch embeddings against jailbreak phrase embeddings. Catches text embedded in images and adversarial visual prompts.

**Audio (FFT + Whisper):**
1. FFT peak detection — flags ultrasonic energy (> 20 kHz) that may carry steganographic commands inaudible to humans
2. Whisper transcription — transcript is fed back through the full text pipeline

```bash
# Scan an image
curl -X POST http://localhost:80/filter/multimodal \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -F "image=@suspect.png" \
     -F 'payload={"content": "describe this image"}'
```

Both guards run in parallel (`asyncio.gather`) — combined overhead is < 200ms P99.

---

## WardenDoctor

Production diagnostics and benchmarking CLI. Run before every deployment and after any incident.

```bash
python scripts/warden_doctor.py --url http://localhost:80 --key $WARDEN_API_KEY
```

Three phases:

| Phase | Checks |
|-------|--------|
| Health | Gateway liveness, Redis latency, circuit breaker state, Evolution Engine, throughput |
| Text Benchmark | Clean / attack / obfuscated-B64 requests. P50/P99 against SLO thresholds |
| Multimodal Benchmark | Synthetic PNG + WAV. P99 < 800ms threshold |

Thresholds: text P99 < 150ms = PASS, < 500ms = WARN, ≥ 500ms = FAIL.

```bash
# CI/CD usage — exits 1 if any check fails
python scripts/warden_doctor.py --url http://staging:80 --key $KEY --json > doctor_report.json
```

For troubleshooting procedures, see [docs/sop.md](docs/sop.md).

---

## NVIDIA Integration

Shadow Warden AI integrates with NVIDIA's AI security stack at two independent layers, aligned with the [*How Autonomous AI Agents Become Secure by Design*](https://developer.nvidia.com/blog/how-autonomous-ai-agents-become-secure-by-design-with-nvidia-openshield/) OpenShield framework — **defense before inference** and **self-improving threat intelligence**.

### Layer 1 — NVIDIA NIM as a Secure LLM Backend

Every request routed through Shadow Warden is filtered *before* it reaches the model. NVIDIA NIM endpoints are first-class citizens in the multi-provider proxy:

```
POST /v1/chat/completions
  model: "nim/nvidia/llama-3.1-nemotron-ultra-253b-v1"
```

Shadow Warden's full 9-stage pipeline (topological gatekeeper → obfuscation decoder → secret redactor → semantic guard → causal arbiter → ERS → output guard) executes on every request **before** the token is forwarded to NIM — making every NIM deployment secure by design without touching the model or its hosting infrastructure.

```
Client → Shadow Warden (filter) → NVIDIA NIM → Shadow Warden (OutputGuard) → Client
```

**What this gives you:**
- Jailbreak, prompt-injection, and indirect-injection attempts blocked before NIM sees them
- PII/secrets stripped before they enter the NVIDIA inference infrastructure
- OutputGuard scans NIM responses for policy violations, competitor mentions, and price manipulation before they reach users
- Zero changes to your existing NIM deployment

### Layer 2 — Nemotron Super 49B as the Evolution Engine Brain

Shadow Warden's Evolution Engine autonomously synthesises new defense rules from observed attack patterns. By default it uses Claude Opus; with `NVIDIA_API_KEY` set it switches to **Nemotron Super 49B via NIM** — NVIDIA's most capable reasoning model:

```bash
EVOLUTION_ENGINE=nemotron   # force Nemotron
EVOLUTION_ENGINE=auto        # Nemotron if NVIDIA_API_KEY is set, else Claude (default)
EVOLUTION_ENGINE=claude      # force Claude
```

Nemotron's **thinking mode** (`<think>…</think>` reasoning trace) is captured and optionally stored in the Evidence Vault (`NEMOTRON_STORE_THINKING=true`) — providing an auditable chain-of-thought for every new defense rule.

**What this gives you:**
- New attack signatures synthesised automatically from blocked requests — no human analyst required
- Reasoning traces stored in the tamper-evident Evidence Vault for SOC 2 / litigation review
- Nemotron's 49B parameter reasoning applied to the specific domain of adversarial AI attack patterns

### Alignment with NVIDIA OpenShield

NVIDIA OpenShield defines four security primitives for autonomous agents: **Input Validation**, **Output Inspection**, **Agent Authorization**, and **Runtime Monitoring**. Shadow Warden implements all four:

| OpenShield Primitive | Shadow Warden Implementation |
|---|---|
| Input Validation | 9-stage filter pipeline (topo → semantic → causal arbiter) |
| Output Inspection | OutputGuard v2 — 10 risk types across business + security layers |
| Agent Authorization | Zero-Trust Agent Sandbox — capability manifests + kill-switch API |
| Runtime Monitoring | Prometheus metrics, ERS sliding-window reputation, Evidence Vault audit trail |

---

## Multi-Provider Proxy

Shadow Warden proxies `/v1/chat/completions` with filter-before-forward. Provider is auto-detected from the model name:

| Model prefix / format | Routes to |
|---|---|
| `gpt-*`, `o1-*`, `o3-*` | OpenAI |
| `azure/<deployment>` | Azure OpenAI Service |
| `bedrock/<model-id>` | Amazon Bedrock (Converse / ConverseStream API) |
| `vertex/<model-name>` | Google Cloud Vertex AI |
| `gemini-*` | Google Gemini |
| `nim/<org>/<model>` | NVIDIA NIM |
| `sonar-*`, `llama-*`, `pplx-*`, `r1-*`, `mixtral` | Perplexity |

**Streaming** (`"stream": true`) is fully supported for all providers. Progressive scan: the first 400 chars are buffered for an OutputGuard fast-scan, then subsequent chunks are live-emitted with zero added latency. Full buffering is automatically engaged when a PII masking session (`X-Mask-Session-Id`) is active. Configure the scan buffer size with `STREAMING_FAST_SCAN_BUFFER` (default `400`, set `0` to force full-buffer mode).

---

## OutputGuard v2

OutputGuard scans LLM *responses* before they reach users. Ten risk types across two layers:

### Business-layer

| Risk | Trigger example | OWASP |
|------|----------------|-------|
| Price manipulation | "80% off today!" / "Get it for free" | LLM09 |
| Unauthorized commitments | "I guarantee delivery by Friday" | LLM09 |
| Competitor mentions | "Check Amazon for better prices" | Brand risk |
| Policy violations | "Lifetime warranty included" | LLM09 |

### Safety + data protection

| Risk | Trigger example | OWASP |
|------|----------------|-------|
| Hallucinated URLs | Any `http://` link in LLM output | LLM09 |
| Hallucinated statistics | "Studies show 92% of users prefer…" | LLM09 |
| PII leakage | Credit cards, SSNs, email addresses | LLM02 |
| Toxic content | Threats, hate speech, severe profanity | LLM01 |
| System prompt echo | "My instructions say I should not…" | LLM07 |
| Sensitive data exposure | API keys, passwords, bearer tokens | LLM02 |

---

## Configuration Reference

All tunable parameters are documented in `.env.example`. Critical values:

| Env var | Default | Effect |
|---------|---------|--------|
| `WARDEN_API_KEY` | _(blank = disabled)_ | Gateway authentication |
| `SEMANTIC_THRESHOLD` | `0.72` | MiniLM cosine similarity cutoff |
| `UNCERTAINTY_LOWER_THRESHOLD` | `0.55` | ML uncertain band floor |
| `RATE_LIMIT_PER_MINUTE` | `60` | Requests per IP per minute |
| `ERS_SHADOW_BAN_THRESHOLD` | `0.75` | ERS score to trigger shadow ban |
| `ERS_MIN_REQUESTS` | `5` | Minimum requests before ERS escalates |
| `WARDEN_FAIL_STRATEGY` | `open` | `closed` = block on timeout (financial/regulated) |
| `REDIS_URL` | `redis://redis:6379` | Set `memory://` for tests |
| `ANTHROPIC_API_KEY` | _(blank = air-gapped)_ | Disables Evolution Engine if empty |
| `HF_TOKEN` | _(blank)_ | HuggingFace auth for CLIP/Whisper download |
| `DYNAMIC_RULES_PATH` | `/warden/data/dynamic_rules.json` | Evolved rules corpus |
| `GDPR_LOG_RETENTION_DAYS` | `30` | Auto-purge log entries after N days |
| `STREAMING_FAST_SCAN_BUFFER` | `400` | Chars buffered for OutputGuard fast-scan before live-emit begins. Set `0` to force full-buffer mode. |
| `TOPO_NOISE_THRESHOLD` | `0.82` | Topological noise score threshold for TOPOLOGICAL_NOISE flag (0–1). |
| `TOPO_MIN_LEN` | `20` | Minimum text length for topological analysis (shorter inputs pass through). |
| `HYPERBOLIC_WEIGHT` | `0.30` | Weight of hyperbolic similarity in final ML score blend (0 = cosine only). |
| `CAUSAL_RISK_THRESHOLD` | `0.65` | P(HIGH\_RISK) threshold for Causal Arbiter to escalate gray-zone requests. |
| `S3_ENABLED` | `false` | Master switch for on-prem S3 object storage (MinIO). |
| `S3_ENDPOINT` | `http://minio:9000` | MinIO or S3-compatible endpoint. Leave empty for AWS S3. |
| `S3_BUCKET_EVIDENCE` | `warden-evidence` | Bucket for Evidence Vault bundles. |
| `S3_BUCKET_LOGS` | `warden-logs` | Bucket for GDPR-safe analytics log entries. |

Live-tunable without restart via `POST /api/config/update`:

```bash
curl -X POST http://localhost:80/api/config/update \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"semantic_threshold": 0.78, "uncertainty_lower_threshold": 0.60}'
```

---

## GDPR Compliance

### What is logged (metadata only)

```json
{
  "ts": "2026-01-15T14:32:01Z",
  "request_id": "a1b2c3d4-...",
  "tenant_id": "acme-corp",
  "allowed": false,
  "risk_level": "HIGH",
  "flags": ["prompt_injection", "obfuscation"],
  "secrets_found": ["openai_api_key"],
  "payload_tokens": 83,
  "processing_ms": {"total": 5.8, "ml": 4.2, "rules": 0.9},
  "attack_cost_usd": 0.0
}
```

### What is never logged

| Data | Status |
|------|--------|
| Request content / prompts | Never stored |
| Redacted secret values | Never stored |
| Email addresses, phone numbers | Never stored |
| IP addresses | Pseudonymised (SHA-256 GDPR entity key) |

### Purge (GDPR Article 5(1)(e))

```bash
curl -X POST http://localhost:80/gdpr/purge \
     -H "X-API-Key: $WARDEN_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"before\": \"$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')\"}"
```

Automate with cron — see [docs/sop.md](docs/sop.md) for the recommended cron entry.

### Article 30

- **Controller:** Your organisation · **Processor:** Shadow Warden AI (self-hosted)
- **Purpose:** Security monitoring · **Legal basis:** Legitimate interests (Art. 6(1)(f))
- **Retention:** Configurable, default 30 days · **Transfers:** None

---

## Security Model

### Detection layers

1. **TopologicalGatekeeper** — n-gram point cloud → Betti numbers (β₀, β₁) → noise_score. Catches random noise, DoS payloads, binary garbage in < 2ms before any ML runs.
2. **ObfuscationDecoder** — Decodes Base64, hex, ROT13, Caesar variants, word-splitting, UUencode, Unicode homoglyphs. Multi-layer recursive up to depth 3.
3. **SecretRedactor** — 15+ regex patterns (API keys, credit cards with Luhn validation, JWTs, SSH keys) + Shannon entropy scan for unknown secret formats.
4. **SemanticGuard** — Regex rule engine with compound escalation (3+ MEDIUM → HIGH).
5. **HyperbolicBrain** — `all-MiniLM-L6-v2` projected into Poincaré ball. Final score = 70% cosine + 30% hyperbolic similarity. Better precision on hierarchically nested attacks. Adversarial suffix stripping.
6. **CausalArbiter** — Bayesian DAG for gray-zone requests. Computes P(HIGH\_RISK | evidence) via do-calculus. Zero LLM calls. Resolves uncertainty in ~1–5ms.
7. **MultimodalGuard** — CLIP (image patch embeddings) + Whisper+FFT (audio transcription + ultrasonic detection).
8. **Entity Risk Scoring** — Redis sliding-window reputation with shadow ban at critical threshold.
9. **ToolCallGuard** — Inspects tool calls and results in agentic pipelines. Blocks injection, SSRF, OS command abuse.
10. **AgentMonitor** — Session-level threat patterns: INJECTION_CHAIN, EXFIL_CHAIN, PRIVILEGE_ESCALATION, EVASION_ATTEMPT, ROGUE_AGENT, TOOL_VELOCITY, RAPID_BLOCK. Cryptographic attestation chain per session.
11. **EvolutionEngine** — Claude Opus generates new detection rules from live HIGH/BLOCK attacks. Hot-reloaded without restart.
12. **Evidence Vault** — SHA-256 attestation chains per session. Tamper-evident, litigation-ready.
13. **Encrypted PII Vault** — Masking engine stores original PII values Fernet-encrypted. Reverse map uses HMAC-SHA256 keys. No plaintext PII ever in memory.
14. **Data-Gravity Hybrid Hub** — Evidence Vault bundles and analytics logs persisted to on-prem MinIO (S3-compatible). All security metadata stays inside your infrastructure; zero egress cost.

### Risk levels

| Level | Meaning | Default action | Strict mode |
|-------|---------|---------------|-------------|
| `LOW` | Clean | Allowed | Allowed |
| `MEDIUM` | Suspicious | Allowed | Blocked |
| `HIGH` | Likely attack | Blocked | Blocked |
| `BLOCK` | Confirmed attack | Blocked | Blocked |

---

## Full OWASP LLM Top 10 Coverage

```
OWASP LLM Top 10 (2025)
  │
  ├─ LLM01  Prompt Injection              → PromptShield (6 labeled patterns) + SemanticBrain
  │                                          + CausalArbiter (gray-zone do-calculus)
  │                                          + ObfuscationDecoder (depth-3 recursive decode)
  │
  ├─ LLM02  Sensitive Information Disclosure
  │         ├─ Input side                 → SecretRedactor (15+ patterns, Shannon entropy scan)
  │         │                               + Encrypted PII Vault (Fernet at-rest, HMAC reverse map)
  │         └─ Output side                → OutputGuard v2 (PII leakage + sensitive data exposure)
  │
  ├─ LLM03  Supply Chain Vulnerabilities  → Evidence Vault (SHA-256 attestation chain per session)
  │                                          + Data-Gravity Hybrid Hub (MinIO on-prem, zero egress)
  │
  ├─ LLM04  Data and Model Poisoning      → EvolutionEngine poison guard (dedup + adversarial
  │                                          corpus validation before rule hot-reload)
  │                                          + SemanticGuard compound escalation
  │
  ├─ LLM05  Improper Output Handling      → OutputGuard v2 (business layer: price manipulation,
  │                                          unauthorized commitments, competitor mentions,
  │                                          policy violations + security layer: hallucinated URLs,
  │                                          hallucinated stats, toxic content, system prompt echo)
  │
  ├─ LLM06  Excessive Agency              → Zero-Trust Agent Sandbox (capability manifests,
  │                                          authorize_tool_call(), session kill-switch API)
  │                                          + AgentMonitor (TOOL_VELOCITY, PRIVILEGE_ESCALATION,
  │                                          ROGUE_AGENT, INJECTION_CHAIN, EVASION_ATTEMPT)
  │
  ├─ LLM07  System Prompt Leakage         → OutputGuard v2 (system prompt echo detector)
  │                                          + SecretRedactor strips secrets before any LLM call
  │
  ├─ LLM08  Vector and Embedding Weaknesses
  │                                       → HyperbolicBrain (Poincaré ball projection separates
  │                                          hierarchically nested adversarial embeddings that
  │                                          appear close in Euclidean cosine space)
  │                                          + TopologicalGatekeeper (β₀/β₁ Betti numbers catch
  │                                          adversarial n-gram distributions < 2ms)
  │
  ├─ LLM09  Misinformation                → OutputGuard v2 (hallucinated URLs, hallucinated stats,
  │                                          price manipulation, unauthorized commitments)
  │
  └─ LLM10  Unbounded Consumption         → Auth & Rate-Limit Gate (60 req/min per tenant,
                                             Redis sliding window)
                                             + Entity Risk Scoring (shadow ban at ERS ≥ 0.75,
                                             progressive penalty: gaslight → delay → ban)
                                             + Redis Content-Hash Cache (5-min TTL,
                                             0ms ML overhead on repeated payloads)
```

---

## Service Level Objectives

Measured production values on 4 vCPU / 4 GB RAM (Ubuntu 22.04, CPU-only):

| Metric | Target | Measured |
|--------|--------|----------|
| P50 latency (`/filter`, text) | < 20 ms | **5.3 ms** |
| P99 latency (`/filter`, text) | < 150 ms | **7.2 ms** |
| P99 latency (multimodal) | < 800 ms | — |
| Pre-release integration suite | 30/30 | **30/30** |
| Test coverage | ≥ 75% | **86%** |
| Uptime | 99.9% | — |

---

## Development

### Run locally

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[dev]"
pip install -r warden/requirements.txt

# Core
export WARDEN_API_KEY="" REDIS_URL="memory://" LOGS_PATH="/tmp/warden_test.json"

# v2.8 Communities (SQLite dev paths — no S3/PostgreSQL needed locally)
export COMMUNITY_REGISTRY_PATH="/tmp/warden_community_registry.db"
export COMMUNITY_KEY_ARCHIVE_PATH="/tmp/warden_community_key_archive.db"
export BREAK_GLASS_AUDIT_PATH="/tmp/warden_break_glass_audit.jsonl"
export VAULT_MASTER_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

# v2.9 Monetization (SQLite fallback, S3 optional)
export QUOTA_DB_PATH="/tmp/warden_quota.db"
export ENTITY_DB_PATH="/tmp/warden_entity_store.db"
export COMMUNITY_S3_BUCKET="warden-communities"  # set S3_ENDPOINT for MinIO

uvicorn warden.main:app --reload --port 8001
```

### Tests

```bash
# Standard suite
pytest warden/tests/ -v -m "not adversarial and not slow"

# Pre-release integration suite (30 tests, 5 levels)
pytest warden/tests/pre_release_final_test.py -v

# Coverage gate (≥75%)
pytest warden/tests/ -m "not adversarial" --cov=warden --cov-fail-under=75

# Lint
ruff check warden/ analytics/ --ignore E501
mypy warden/ --ignore-missing-imports --no-strict-optional
```

### Project structure

```
shadow-warden-ai/
├── docker-compose.yml
├── pyproject.toml
├── .env.example
├── CONTRIBUTING.md                    # Contribution guidelines + non-negotiables
├── .github/workflows/ci.yml           # Test matrix (3.11/3.12) + lint + Docker smoke
│
├── docs/
│   ├── pipeline-anatomy.md            # Stage-by-stage breakdown + latency budget
│   ├── sop.md                         # Security & Operations Advisory (Blue Team)
│   └── deployment-guide.md            # Infrastructure + production hardening
│
├── scripts/
│   └── warden_doctor.py               # Production diagnostics & benchmarking CLI
│
├── warden/
│   ├── main.py                        # FastAPI gateway — all endpoints + lifespan MOTD
│   ├── brain/
│   │   ├── semantic.py                # MiniLM ML detector (ThreadPoolExecutor, lru_cache)
│   │   ├── evolve.py                  # Evolution Engine (Claude Opus, corpus poisoning protection)
│   │   └── dataset.py                 # Corpus management utilities
│   ├── obfuscation.py                 # Obfuscation decoder pre-filter
│   ├── secret_redactor.py             # PII/secret redactor (15+ patterns)
│   ├── semantic_guard.py              # Rule engine + compound risk escalation
│   ├── entity_risk.py                 # ERS — Redis sliding window + shadow ban
│   ├── agent_sandbox.py               # Zero-trust capability manifest + authorize_tool_call
│   ├── agent_monitor.py               # Session-level attestation chain
│   ├── tool_guard.py                  # Tool call + result inspection
│   ├── image_guard.py                 # CLIP zero-shot image scanning
│   ├── audio_guard.py                 # Whisper + FFT ultrasonic detection
│   ├── compliance/
│   │   └── bundler.py                 # EvidenceBundler — SHA-256 sign-last bundles
│   ├── circuit_breaker.py             # Circuit breaker (Redis-backed, auto-heal)
│   ├── auth_guard.py                  # Per-tenant API key auth (SHA-256 hash lookup)
│   ├── cache.py                       # Redis content-hash cache (5-min TTL, fail-open)
│   ├── alerting.py                    # Slack + PagerDuty alerts on HIGH/BLOCK
│   ├── metrics.py                     # Prometheus metrics (warden_* namespace)
│   ├── webhook_dispatch.py            # Outbound webhook delivery
│   ├── analytics/
│   │   ├── logger.py                  # GDPR-safe NDJSON logger + purge helpers
│   │   └── siem.py                    # Splunk HEC + Elastic ECS SIEM integration
│   └── tests/
│       ├── pre_release_final_test.py  # 30-test integration suite (L1–L5)
│       └── ...                        # Unit tests (~86% coverage)
│
└── grafana/
    ├── prometheus.yml
    └── dashboards/warden_overview.json
```


### Planned

- [ ] Kubernetes Helm chart (EKS / GKE / AKS)
- [ ] Browser extension — real-time protection for ChatGPT, Claude.ai, Copilot
- [x] Threat intelligence sharing (STIX 2.1 / Warden Nexus federated feed) ✓ v2.5
- [ ] SOC 2 Type II certification audit
- [ ] SaaS hosted option (no Docker, single API key)

---

## Documentation

| Doc | Audience |
|-----|----------|
| [docs/pipeline-anatomy.md](docs/pipeline-anatomy.md) | Security architects, platform engineers |
| [docs/sop.md](docs/sop.md) | Blue Team, Security Operations, DevOps |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributors |
| `.env.example` | Everyone — all env vars with descriptions |

---

## License

Proprietary — Shadow Warden AI. All rights reserved.
