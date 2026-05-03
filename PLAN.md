# PLAN.md — Shadow Warden AI Product Roadmap

**Version 4.10 · Last updated 2026-05**

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
| Q2.6 | Agent Action Whitelist REST API (warden/api/action_whitelist.py) | ☐ Open |
| Q3.7 | SMB Billing Tier + Add-on gates | ✅ |
| Q3.8 | Shadow AI Dashboard for SMB | ☐ Open |
| Q4.10 | Knock-and-Verify invitation flow | ✅ |
| Q4.11 | STIX 2.1 Tamper-Evident Audit Chain | ✅ |
| Q4.12 | Claude Design System Dashboard SPA | ✅ |

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

### Block G — Secrets Governance v4.9 (✅ Complete)
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

### Block H — Obsidian Business Community Integration v4.11 (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| H-01 | `warden/integrations/obsidian/__init__.py` — package init | ✅ |
| H-02 | `warden/integrations/obsidian/note_scanner.py` — scan_note(), data classification, SecretRedactor | ✅ |
| H-03 | `warden/api/obsidian.py` — 5 endpoints: /scan, /share (SEP UECIID), /feed, /ai-filter, /stats | ✅ |
| H-04 | `/obsidian` router mounted in main.py (try/except ImportError) | ✅ |
| H-05 | `obsidian-plugin/main.ts` — TypeScript plugin: ribbon, status bar, 5 commands, auto-scan | ✅ |
| H-06 | `obsidian-plugin/manifest.json` — id shadow-warden-ai, minAppVersion 1.4.0 | ✅ |
| H-07 | `obsidian-plugin/styles.css` — badge colours, feed cards, UECIID monospace | ✅ |
| H-08 | TypeScript build toolchain (package.json + tsconfig.json + esbuild.config.mjs) | ✅ |
| H-09 | 25 tests in test_obsidian_integration.py (6 classes) | ✅ |

---

### Block I — Platform Polish v4.11 (✅ Complete)
| ID | Feature | Status |
|----|---------|--------|
| I-01 | Accessibility widget — ♿ international symbol icon | ✅ |
| I-02 | Accessibility widget — click bug fixed (!btnEl.contains(e.target)) | ✅ |
| I-03 | Accessibility widget — loaded only on index.html (removed from 27 other pages) | ✅ |
| I-04 | Enterprise Integration Guide — updated to v4.11 (pillars, Obsidian, Settings link) | ✅ |
| I-05 | Enterprise Settings — updated to v4.11 (Secrets Gov, Obsidian, Accessibility panels) | ✅ |
| I-06 | Settings pages (Astro + landing/settings.html) — NVIDIA/NeMo settings tab | ✅ |

---

## Tier Feature Matrix

| Feature | Starter | Individual | Community Business $19 | Pro $69 | Enterprise $249 |
|---------|---------|-----------|------------------------|---------|----------------|
| /filter gateway | ✅ | ✅ | ✅ | ✅ | ✅ |
| Offline Mode | ✅ | ✅ | ✅ | ✅ | ✅ |
| Evolution Engine | ✅ | ✅ | ✅ | ✅ | ✅ |
| SOVA Agent | ✅ | ✅ | ✅ | ✅ | ✅ |
| Uptime Monitor | ✅ | ✅ | ✅ | ✅ | ✅ |
| API Key Rotation | ✅ | ✅ | ✅ | ✅ | ✅ |
| Email Guard | — | — | ✅ | ✅ | ✅ |
| File Scanner (DOCX/XLSX) | — | — | ✅ | ✅ | ✅ |
| Obsidian Integration | — | — | ✅ | ✅ | ✅ |
| Communities (3×10 members) | — | — | ✅ | ✅ | ✅ |
| 180-day retention | — | — | ✅ | ✅ | ✅ |
| Financial Impact Calculator | — | ✅ | ✅ | ✅ | ✅ |
| Secrets Governance | — | add-on $12 | ✅ | ✅ | ✅ |
| XAI Reports | — | add-on $9 | add-on $9 | ✅ | ✅ |
| MasterAgent SOC | — | — | — | ✅ | ✅ |
| Shadow AI Governance | — | — | — | add-on $15 | ✅ |
| Sovereign AI Cloud | — | — | — | — | ✅ |
| Post-Quantum Crypto | — | — | — | — | ✅ |
| SEP Community Exchange | — | — | — | — | ✅ |
| SMB Compliance Report | — | — | ✅ | ✅ | ✅ |

---

## Open Items (Q2–Q3 2026)

| Priority | Item | Owner |
|----------|------|-------|
| HIGH | Agent Action Whitelist REST API (Q2.6) | Backend |
| HIGH | FraudScore API backend (POST /fraud-score/evaluate) | Backend |
| HIGH | Coverage gate — restore ≥75% (post v4.9/4.10 additions) | QA |
| MED | Shadow AI Dashboard for SMB (Q3.8) | Frontend |
| MED | Obsidian feed persistence (SQLite sep_obsidian_feed) | Backend |
| MED | Secrets Vault add-on Lemon Squeezy webhook handler | Backend |
| MED | mutmut pass ≤20 surviving mutants (CI enforcement) | QA |
| MED | landing/index.html footer — update v4.7.0 → v4.11 | Frontend |
| LOW | Obsidian plugin TypeScript CI step | DevOps |
| LOW | Hadolint GitHub Actions step | DevOps |
| LOW | docker scout / Trivy in CI | DevOps |
| LOW | NVIDIA NeMo GeometricThreatBridge production wiring | Backend |
| LOW | Kubernetes Helm chart | DevOps |
| LOW | docs/dpia.md + docs/soc2-evidence.md update to v4.11 | Docs |

---

## Coverage Gate

Current: ~74% (gate: ≥75%)

Recent additions in v4.9 (48 tests) and v4.11 (25 tests) added new coverage
but also introduced uncovered lines in some modules. Target is to restore to
76%+ before next version bump.

Omitted from coverage: dashboard, auth UI, SIEM, LangChain callback, browser sandbox, OpenAI proxy.

---

*PLAN.md — Shadow Warden AI product roadmap v4.11 · 2026-05*
