# PlAN.md — Shadow Warden AI Product Roadmap

**Version 4.7 · Last updated 2026-04**

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
| Q2.5 | Agent Action Whitelist (warden/agentic/action_whitelist.py) | ✅ |
| Q2.6 | Agent Action Whitelist REST API (warden/api/action_whitelist.py) | ☐ |
| Q3.7 | SMB Billing Tier + Add-on gates | ✅ |
| Q3.8 | Shadow AI Dashboard for SMB | ☐ |
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

## Tier Feature Matrix

| Feature | Starter | Individual | Pro $69 | Enterprise $249 |
|---------|---------|-----------|---------|----------------|
| /filter gateway | ✅ | ✅ | ✅ | ✅ |
| Offline Mode | ✅ | ✅ | ✅ | ✅ |
| Email Guard | ✅ | ✅ | ✅ | ✅ |
| File Scanner (DOCX/XLSX) | ✅ | ✅ | ✅ | ✅ |
| SOVA Agent | ✅ | ✅ | ✅ | ✅ |
| EvolutionEngine | ✅ | ✅ | ✅ | ✅ |
| Uptime Monitor | ✅ | ✅ | ✅ | ✅ |
| Financial Impact Calculator | — | ✅ | ✅ | ✅ |
| XAI Reports | — | add-on $9 | ✅ | ✅ |
| MasterAgent SOC | — | — | ✅ | ✅ |
| Shadow AI Governance | — | — | add-on $15 | ✅ |
| Sovereign AI Cloud | — | — | — | ✅ |
| Post-Quantum Crypto | — | — | — | ✅ |
| SEP Community Exchange | — | — | — | ✅ |
| SMB Compliance Report | ✅ | ✅ | ✅ | ✅ |
| API Key Rotation | ✅ | ✅ | ✅ | ✅ |

---

## Open Items (Q2 2026)

| Priority | Item | Owner |
|----------|------|-------|
| HIGH | Agent Action Whitelist REST API (Q2.6) | Backend |
| HIGH | FraudScore API backend (POST /fraud-score/evaluate) | Backend |
| MED | Shadow AI Dashboard for SMB (Q3.8 — non-Streamlit) | Frontend |
| MED | mutmut pass ≤20 surviving mutants (CI enforcement) | QA |
| LOW | Hadolint GitHub Actions step | DevOps |
| LOW | docker scout / Trivy in CI | DevOps |

---

## Coverage Gate

Current: **76.31%** (gate: ≥75%)

Omitted from coverage: dashboard, auth UI, SIEM, LangChain callback, browser sandbox, OpenAI proxy.

---

*PlAN.md — Shadow Warden AI product roadmap v4.7 · 2026-04*
