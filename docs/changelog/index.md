# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [4.11] — 2026-05-04

### Added
- **Phase 3 — Documentation**: MkDocs Material site with Mermaid diagrams, ADRs, API reference, and guides for every module
- **Phase 2 — Cyber Security Hub**: `GET /security/posture|cve-feed|pentest|compliance`, `POST /security/cve-scan`; `GET /soc/health|healer|metrics`; `POST /soc/heal`
- **`scan_cves` ARQ cron**: OSV batch API every 6h → `data/cve_report.json`; Slack alert on new CRITICALs; GREEN/YELLOW/RED badge
- **Interactive Security Dashboard** (`7_Cyber_Security.py`): 5-tab Streamlit page — Posture, CVE Feed, SOC Live (gauge), Pentest, Compliance
- **Phase 1 — Business Community**: `POST /community/posts|from-obsidian`, `GET /community/feed`, comments, members; NIM moderation ARQ job
- **SOVA Community Integration** (tools #32–#37): `get_community_feed`, `get_community_post`, `moderate_community_post`, `list_community_posts_members`, `community_moderation_report`, `post_community_announcement`
- **`sova_community_watchdog` cron**: every hour at :20 — auto-blocks WARN ≥ 0.85; Slack alert on BLOCK verdicts
- **`sova_morning_brief`** updated to include Business Community health digest

### Changed
- `sova_morning_brief` now calls `community_moderation_report` and includes NIM verdict breakdown in daily Slack digest
- `warden/workers/settings.py` extended with `moderate_post`, `scan_cves`, `sova_community_watchdog` functions and cron entries

### Previous — [4.11 SOVA Intelligence Upgrades] — 2026-05-03

#### Added
- **`visual_diff` tool (#31)**: `BrowserSandbox.capture_screenshot_b64()` + Claude Vision comparison; verdicts IDENTICAL/MINOR_DIFF/REGRESSION/CRITICAL_REGRESSION
- **WardenHealer**: SQLite metric time series (`bypass_metrics`, `incident_recipes`); `_linear_trend()` OLS; `_check_trend_prediction()` WARN at predicted bypass > 15%; `_llm_classify_incident()` Claude Haiku + recipe cache
- **`_PatrolWeights`**: Redis-backed per-URL decay/boost weights for visual patrol; critical_coverage_pct reporting
- **`ScenarioStep.smart_retry`**: retries with XAI causal-chain failure enrichment

---

## [4.10] — 2026-05-01

### Added
- **Obsidian Business Community Integration**: `scan_note()`, `/obsidian/*` REST API (5 endpoints), TypeScript Obsidian plugin with 5 commands, auto-scan on modify
- Community posts can originate from Obsidian notes (`source='obsidian'`); secrets/CLASSIFIED blocked before sharing

---

## [4.9] — 2026-04-30

### Added
- **Secrets Governance**: vault connectors (AWS SM/Azure KV/HashiCorp/GCP SM/env), SQLite inventory, per-tenant policy engine, lifecycle manager, 14 REST endpoints at `/secrets/*`, 6-tab Streamlit dashboard

---

## [4.8] — 2026-04-29

### Added
- **Community Governance**: charter lifecycle, Z-score behavioural anomaly detection, risk scoring, OAuth discovery (14 providers), 7-tab Streamlit community dashboard

---

## [4.7] — 2026-04-25

### Security (P0/P1 fixes)
- Fail-closed auth: startup `RuntimeError` if `WARDEN_API_KEY` unset without `ALLOW_UNAUTHENTICATED=true`
- `VAULT_MASTER_KEY` validated as Fernet key at boot
- `_GASLIGHT_POOL` expanded 6→30 entries; `secrets.choice()` replaces deterministic hash
- CPT drift gate: rejects calibration updates shifting any parameter > 25%
- Evolution Engine regex gate: compile + timeout + nested-quantifier heuristic

### Added
- **Causal Transfer Guard**, **Sovereign Data Pods**, **STIX 2.1 Audit Chain**
- **Caddy v2.8** replaces nginx (QUIC/HTTP3, hostname routing, HSTS)
- **MasterAgent batch API**: `client.beta.messages.batches` for 50% token discount

---

## [4.6] — 2026-04-20

### Added
- **SEP (Syndicate Exchange Protocol)**: UECIID codec, inter-community peering, Knock-and-Verify invitations, 24 REST endpoints at `/sep/*`

---

## [4.5] — 2026-04-15

### Changed
- Pro $49 → $69/mo · Enterprise $199 → $249/mo
- `master_agent_enabled` included in Pro (not sold as add-on)

### Added
- Add-on SKUs: `shadow_ai_discovery` $15/mo · `xai_audit` $9/mo
- Feature gates: `master_agent_enabled`, `shadow_ai_enabled`, `xai_reports_enabled`, `sovereign_enabled`

---

## [4.4] — 2026-04-10

### Added
- **Sovereign AI Cloud**: 8-jurisdiction registry, MASQUE tunnel lifecycle, per-tenant routing policy, HMAC-signed attestations (7yr TTL), 16 REST endpoints at `/sovereign/*`

---

## [4.3] — 2026-04-05

### Added
- **Explainable AI 2.0**: 9-stage pipeline DAG, primary cause attribution, counterfactuals, HTML + PDF reports, `/xai/*` REST API

---

## [4.2] — 2026-04-01

### Added
- **Shadow AI Governance**: 18-provider fingerprint DB, async subnet probe, MONITOR/BLOCK_DENYLIST/ALLOWLIST_ONLY modes, `/shadow-ai/*` REST API

---

## [4.1] — 2026-03-25

### Added
- **Post-Quantum Cryptography**: HybridSigner (Ed25519 + ML-DSA-65), HybridKEM (X25519 + ML-KEM-768), Enterprise-only gate, liboqs fail-open

---

## [4.0] — 2026-03-20

### Added
- **MasterAgent**: 4 sub-agents (SOVAOperator, ThreatHunter, ForensicsAgent, ComplianceAgent), HMAC task tokens, human-in-the-loop approval gate

---

## [3.3] — 2026-03-10

### Added
- **Playwright Browser Automation**: `BrowserSandbox` with video recording, `ScreencastRecorder` → MinIO
- **WardenHealer**: 4 checks, Slack alerts, LLM-free on happy path
- `sova_visual_patrol` nightly cron
