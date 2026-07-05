# Shadow Warden AI — Final Development Lists (v7.6)

Definitive, code-grounded development inventory across the three product pillars.
Every entry maps to shipped modules in `warden/`. Status legend: **✅ Shipped** ·
**🔧 Hardening** (shipped, ongoing quality work) · **📋 Planned**.

---

## 1. Business Community

Self-sovereign, GDPR-compliant communities that share threat intelligence, run
governed AI procurement, and transfer entities across jurisdictions with a
tamper-evident audit chain.

### 1.1 SEP — Sovereign Entity Protocol
- ✅ UECIID codec — Snowflake → base-62 `SEP-{11}`, lexicographic = chronological (`communities/sep.py`, `communities/id_generator.py`)
- ✅ Sovereign Pod Tags — per-entity data residency; PHI EU→US blocked (`communities/sep.py`)
- ✅ Causal Transfer Proof — HMAC-SHA256 + optional ML-DSA-65 PQC signature (`communities/sep.py`)
- ✅ Causal Transfer Guard — pre-transfer exfiltration block (P≥0.70, <20 ms) (`communities/transfer_guard.py`)
- ✅ Sovereign Data Pods — per-jurisdiction MinIO routing, Fernet-encrypted keys (`communities/data_pod.py`)
- ✅ STIX 2.1 tamper-evident audit chain — SHA-256 prev-hash, JSONL export (`communities/stix_audit.py`)
- ✅ REST surface — 24 endpoints `/sep/*` (`api/sep.py`)

### 1.2 Peering & Membership
- ✅ Inter-community peering — MIRROR_ONLY / REWRAP_ALLOWED / FULL_SYNC, HMAC handshake (`communities/peering.py`)
- ✅ Knock-and-Verify invitations — Redis tokens, 72 h TTL, one-time use (`communities/knock.py`)
- ✅ Membership + roles — Owner / Admin / Member, join-request flow (`communities/membership.py`)
- ✅ Community keypairs — classical + hybrid PQC upgrade (`communities/keypair.py`, `communities/rotation.py`, `communities/key_archive.py`)
- ✅ Multisig + break-glass + clearance (`communities/multisig.py`, `communities/break_glass.py`, `communities/clearance.py`)
- ✅ Federation + model sharing (`communities/federation.py`, `communities/model_share.py`)
- ✅ Charter / factory / registry / router (`communities/charter.py`, `community_factory.py`, `registry.py`, `router.py`)

### 1.3 SMB Governance Suite (single-wizard provisioning — IN-25)
- ✅ AI Vendor Governance Register + DPA tracking (`vendor_gov/registry.py`, `api/vendor_gov.py`)
- ✅ AI Cost Allocation — per-dept/vendor spend (`financial/cost_allocation.py`, `api/cost_allocation.py`)
- ✅ AI Budget Dashboard — caps, threshold alerts, approvals (`financial/budget.py`, `api/budget.py`)
- ✅ AI Incident Register — STIX-linked severity journal (`communities/incident_register.py`, `api/incident_register.py`)
- ✅ Supplier AI Risk Assessment — 5-criteria composite (`communities/supplier_risk.py`, `api/supplier_risk.py`)
- ✅ Shared Prompt Library — UECIID provenance + injection screening (`communities/prompt_library.py`, `api/prompt_library.py`)
- ✅ Employee AI Training Records — HMAC attestation (`communities/training_records.py`, `api/training_records.py`)
- ✅ Suite provisioner (`integrations/smb_suite.py`, `api/smb_suite.py`)

### 1.4 Community Intelligence & Analytics
- ✅ Threat intelligence + reputation + behavioral analytics (`communities/intelligence.py`, `reputation.py`, `behavioral.py`)
- ✅ Business Intelligence — 8 analytics functions, SQLite cache, OLS predictions, benchmarking (`business_intelligence/`)
- ✅ Community compliance / data / evolution surfaces (`communities/community_compliance.py`, `community_data.py`, `community_evolution.py`)
- ✅ WebSocket live metrics + notifications (`communities/notifications.py`, `api/community_notifications.py`)

### 1.5 Agentic Commerce (CM-40)
- ✅ Procurement protocols — UCP / AP2 / MCP (`business_community/agentic_commerce/ucp.py`, `ap2.py`, `mcp_bridge.py`)
- ✅ Multi-agent auction orchestrator + connectors (`agentic_commerce/multi_agent/`)
- ✅ Commerce Budget Guardian — Settings-Hub limits × Semantic-Layer MTD spend (`agentic_commerce/semantic_budget.py`)
- ✅ FIDO2 passkeys + Sepolia Web3 mandate contract (`auth/fido.py`, `blockchain/`)

### 1.6 Surfaces
- ✅ Astro 7-page Community SPA (`site/src/pages/community/*.astro`)
- ✅ SOC Dashboard Community Hub — list + 6-tab detail + live WS (`dashboard/src/app/(soc)/community/`)
- ✅ Streamlit Community Hub — 7 tabs (`analytics/pages/22_Community_Hub.py`)

**📋 Next:** cross-community federated model-averaging governance vote; per-pod cost SLA dashboards.

---

## 2. Agentic Marketplace

A machine-to-machine marketplace where buyer/seller/brand agents negotiate,
transact via x402 nanopayments, and settle through escrow — under a trust graph,
anti-Sybil, and MAESTRO collusion detection.

### 2.1 Agents
- ✅ Buyer / Seller / Brand agents (`marketplace/buyer_agent.py`, `seller_agent.py`, `brand_agent.py`, `agent.py`)
- ✅ Auto-responder + autonomy controls (`marketplace/auto_responder.py`, `autonomy.py`)
- ✅ Agent memory + key rotation (`marketplace/memory.py`, `agent_key_rotation.py`)

### 2.2 Trading Core
- ✅ Listings + negotiation engine (`marketplace/listing.py`, `negotiation.py`, `api_listings.py`, `api_negotiations.py`)
- ✅ Escrow + clearing (Decimal math, dual-write) (`marketplace/escrow.py`, `clearing.py`, `api_escrow.py`)
- ✅ Credits + tokenizer + model router (`marketplace/credits.py`, `tokenizer.py`, `model_router.py`)
- ✅ Vector search / semantic discovery (`marketplace/vector_search.py`)
- ✅ Analytics (`marketplace/analytics.py`)

### 2.3 Trust, Safety & Payments
- ✅ Trust graph + reputation (`marketplace/trust_graph.py`, `reputation.py`)
- ✅ Sybil guard + KYA (Know-Your-Agent) (`marketplace/sybil_guard.py`, `kya.py`, `api/kya.py`)
- ✅ x402 payment gate — nanopayments, replay protection (`marketplace/x402_gate.py`)
- ✅ Injection guard + rate limiting (`marketplace/injection_guard.py`, `rate_limit.py`)
- ✅ MAESTRO — tacit/vertical collusion detection, Pearson ≥0.80 (`marketplace/maestro.py`, `api_maestro.py`)
- ✅ Data lifecycle + governance (`marketplace/data_lifecycle.py`, `governance.py`, `api_governance.py`)
- ✅ Importer for external rule/asset ingest (`marketplace/importer.py`)

### 2.4 Protocols
- ✅ A2A — Agent-to-Agent card + HMAC call tokens (`protocols/a2a/`, `staff/a2a.py`)
- ✅ ACP — multi-agent auction, shared cart, refund intents (`protocols/acp/`, `api/acp.py`)
- ✅ Paid MCP Gateway — x402-gated filter/explain/mask/scan tools (`mcp/gateway.py`)
- ✅ Zero-Trust Billing Audit Chain — SHA-256 chain, Turso-backed (`billing/audit_chain.py`, `api/billing_audit.py`)

### 2.5 Surfaces
- ✅ Unified `/agentic` page (Community + Marketplace + Agentic) (`site/src/pages/agentic.astro`)
- ✅ REST surface — assets / agents / listings / negotiations / escrow / governance / maestro (`marketplace/api*.py`)

**📋 Next:** migrate self-prefixed marketplace routers onto Starlette 1.x pattern (unpin FastAPI); cross-marketplace liquidity bridging.

---

## 3. Cyber Security — Core Detection Engine

The 9-stage `/filter` pipeline plus the agentic SOC that operates and self-heals
it. GDPR-hard: content is never logged, only metadata.

### 3.1 The 9-Stage Pipeline (`POST /filter`)
- ✅ Stage 1 — Topological Gatekeeper: n-gram point cloud → β₀/β₁ Betti numbers, <2 ms (`topology_guard.py`)
- ✅ Stage 1b — Obfuscation Decoder: base64/hex/ROT13/Caesar/word-split/UUencode/homoglyphs, depth-3 (`obfuscation.py`)
- ✅ Stage 1c — Secret Redactor: 15 regex + Shannon entropy scan (`secret_redactor.py`)
- ✅ Stage 2 — Semantic Guard (rules): compound risk escalation (`semantic_guard.py`)
- ✅ Stage 2b — Brain Semantic Guard (ML): MiniLM + Poincaré hyperbolic blend (`brain/semantic.py`, `brain/hyperbolic.py`)
- ✅ Stage 3 — Causal Arbiter: Bayesian DAG, Pearl do-calculus, backdoor correction (`causal_arbiter.py`)
- ✅ Stage 3b — PhishGuard + SE-Arbiter: URL phishing + social engineering (`phishing_guard.py`)
- ✅ Stage 4 — ERS + Shadow Ban: Redis sliding window, differentiated gaslight/delay/standard (`shadow_ban.py`)
- ✅ Decision + Evolution Engine: Claude Opus auto-rule generation, hot-reload (`brain/evolve.py`)

### 3.2 Brain / ML Ops
- ✅ ONNX runner + FAISS index + dataset tooling (`brain/onnx_runner.py`, `faiss_index.py`, `dataset.py`)
- ✅ Data-poisoning guard (CPT drift gate, 25% cap) (`brain/poison.py`)
- ✅ Federated + online learning (`brain/federated.py`, `online_learner.py`)
- ✅ Threat feed + Nemotron evolution (`brain/threat_feed.py`, `evolve_nemotron.py`, `nemotron_client.py`)
- ✅ Intel Ops (OSV CVE + ArXiv) → Auto-Evolution Bridge (`intel_ops.py`, `intel_bridge.py`)

### 3.3 Agentic SOC
- ✅ SOVA agent — Claude Opus loop, 30+ tools, 7 ARQ cron jobs, Redis memory (`agent/sova.py`, `tools.py`, `scheduler.py`, `memory.py`)
- ✅ MasterAgent — 4 sub-agents, HMAC task tokens, human-in-the-loop approval (`agent/master.py`)
- ✅ WardenHealer — anomaly detection, OLS trend, Haiku triage, SQLite recipe cache (`agent/healer.py`)
- ✅ Digital Staff — boundary registry, velocity guard, A2A, unit-economics tracker (`staff/`)
- ✅ XAI — 9-stage causal chain, HTML/PDF report, counterfactuals (`xai/chain.py`, `renderer.py`, `explainer.py`, `api/xai.py`)

### 3.4 Agent & Protocol Runtime Security
- ✅ Agent monitor — INJECTION_CHAIN + 6 patterns, cryptographic attestation (`agent_monitor.py`)
- ✅ Prompt shield + tool guard + taint tracker + session guard (`prompt_shield.py`, `tool_guard.py`, `taint_tracker.py`, `session_guard.py`)
- ✅ Output sanitizer / output guard (`output_sanitizer.py`, `output_guard.py`)
- ✅ Agent sandbox (Playwright headless) (`agent_sandbox.py`, `tools/browser.py`)
- ✅ Honeytokens + global blocklist + wallet shield (`honey.py`, `global_blocklist.py`, `wallet_shield.py`)

### 3.5 Privacy, Crypto & Multimodal
- ✅ Masking engine — Fernet vault, HMAC-SHA256 reverse map, no plaintext (`masking/engine.py`)
- ✅ Post-Quantum Crypto — Hybrid Ed25519+ML-DSA-65, X25519+ML-KEM-768 (`crypto/pqc.py`)
- ✅ HSM connector + memory protection (`crypto/hsm.py`, `memory_protection.py`)
- ✅ Multimodal — image/audio guard + redactor + OCR (`multimodal_guard.py`, `image_*.py`, `audio_*.py`, `ocr.py`)
- ✅ Shadow AI Discovery — 18 providers, subnet probe + DNS, per-tenant policy (`shadow_ai/`)

### 3.6 Sovereign & Compliance
- ✅ 8-jurisdiction routing, MASQUE tunnels, attestation (`sovereign/`)
- ✅ Real-time compliance posture — GDPR/SOC2/ISO27001/HIPAA, WebSocket push (`compliance/`, `api/compliance_report.py`)
- ✅ ISO 27001:2022 full 93-control mapping (`analytics/pages/18_ISO27001.py`)
- ✅ Secrets Governance — vault connectors, inventory, policy, lifecycle (`secrets_gov/`)

### 3.7 Platform Hardening (v7.5–v7.6, ongoing)
- ✅ Application Factory — `register_router_safe` isolates sub-routers from the pipeline (`app_factory.py`)
- ✅ Route-inventory guard — clean-subprocess, env-tolerant OpenAPI diff (`tests/test_route_inventory.py`)
- ✅ Adversarial ratchet — full-pipeline blocking baseline (`tests/test_adversarial_ratchet.py`)
- ✅ Dependency lockfile — `constraints.txt` + CI pip-freeze snapshot
- 🔧 Fail-open inventory — 308 sites catalogued, 244 flagged for review (`docs/fail-open-inventory.md`)
- 🔧 Silent-except logging — 34 critical handlers instrumented; ~176 non-critical remaining

**📋 Next:** finish fail-open review queue (244 sites); migrate remaining multi-router blocks in `main.py`; Starlette 1.x migration to drop the FastAPI pin.
