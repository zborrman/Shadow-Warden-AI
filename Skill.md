# Shadow Warden AI — Skill Reference

**Version 4.14 · Proprietary · All rights reserved**

This document catalogues every capability Shadow Warden AI exposes to developers,
operators, and integrators. Each section defines the skill, its configuration
surface, its observable outputs, and integration patterns.

---

## Table of Contents

1.  Skill Taxonomy
2.  Skill 1 — Secret Redaction
3.  Skill 2 — Semantic Threat Analysis
4.  Skill 3 — Risk Decision Engine
5.  Skill 4 — Autonomous Rule Evolution
6.  Skill 5 — Topological Gatekeeper (TDA)
7.  Skill 6 — HyperbolicBrain
8.  Skill 7 — Causal Arbiter
9.  Skill 8 — Browser Security Sandbox
10. Skill 9 — SOVA Autonomous Agent (30 tools)
11. Skill 10 — MasterAgent (Multi-Agent SOC)
12. Skill 11 — Shadow AI Discovery
13. Skill 12 — Explainable AI (XAI)
14. Skill 13 — Sovereign AI Cloud
15. Skill 14 — Post-Quantum Cryptography (PQC)
16. Skill 15 — Syndicate Exchange Protocol (SEP)
17. Skill 16 — GDPR-Safe Analytics
18. Skill 17 — Uptime Monitor
19. Skill 18 — File Scanner (SMB)
20. Skill 19 — Email Guard (SMB)
21. Skill 20 — Secrets Rotation Monitor
22. Skill 21 — Agent Action Whitelist
23. Skill 22 — SMB Compliance Report
24. Skill 23 — Secrets Governance
25. Skill 24 — Obsidian Community Integration
26. Skill 25 — OTel Distributed Tracing
27. Skill 26 — SOC Next.js Dashboard
28. Skill 27 — Public API Documentation (Redoc)
29. Skill 28 — Load Profiling + Flamegraph
30. Skill 29 — SLO Burn-Rate Alerting
31. Integration Recipes
32. Configuration Quick-Reference

---

## 1. Skill Taxonomy

Shadow Warden AI is composed of 29 discrete, independently configurable skills.
Skills 1–3 execute synchronously in the `/filter` pipeline. Skills 4–24 are
background, agentic, or on-demand capabilities.

```
POST /filter pipeline (sync):
  Skill 1  · Secret Redaction          < 5 ms
  Skill 5  · Topological Gatekeeper    < 2 ms
  Skill 2  · Semantic Threat Analysis  5–120 ms
  Skill 6  · HyperbolicBrain           5–60 ms (warm)
  Skill 7  · Causal Arbiter            1–5 ms
  Skill 3  · Risk Decision Engine      < 1 ms

Background / On-demand:
  Skill 4  · Autonomous Rule Evolution    (async, background)
  Skill 8  · Browser Security Sandbox     (on-demand)
  Skill 9  · SOVA Autonomous Agent        (on-demand / ARQ cron)
  Skill 10 · MasterAgent                  (on-demand)
  Skill 11 · Shadow AI Discovery          (on-demand / ARQ)
  Skill 12 · Explainable AI              (on-demand)
  Skill 13 · Sovereign AI Cloud          (routing, on-demand)
  Skill 14 · Post-Quantum Cryptography   (crypto primitive)
  Skill 15 · SEP                         (on-demand)
  Skill 16 · GDPR-Safe Analytics         (fire-and-forget)
  Skill 17 · Uptime Monitor              (background probes)
  Skill 23 · Secrets Governance          (background + on-demand)
  Skill 24 · Obsidian Integration        (on-demand / plugin)
  Skill 25 · OTel Distributed Tracing   (background, per-request)
  Skill 26 · SOC Dashboard              (SPA, on-demand)
```

| # | Skill | Latency | Offline | Tier |
|---|-------|---------|---------|------|
| 1 | Secret Redaction | < 5 ms | ✅ | All |
| 2 | Semantic Threat Analysis | 5–120 ms | ✅ | All |
| 3 | Risk Decision Engine | < 1 ms | ✅ | All |
| 4 | Autonomous Rule Evolution | Background | ⚠️ API key | All |
| 5 | Topological Gatekeeper | < 2 ms | ✅ | All |
| 6 | HyperbolicBrain | 5–60 ms | ✅ | All |
| 7 | Causal Arbiter | 1–5 ms | ✅ | All |
| 8 | Browser Security Sandbox | On-demand | ✅ | Pro+ |
| 9 | SOVA Agent | On-demand | ⚠️ API key | Pro+ |
| 10 | MasterAgent | On-demand | ⚠️ API key | Pro ($69) |
| 11 | Shadow AI Discovery | On-demand | ✅ | Enterprise or +$15/mo add-on |
| 12 | Explainable AI | On-demand | ✅ | Pro+ or +$9/mo add-on |
| 13 | Sovereign AI Cloud | Routing | ✅ | Enterprise ($249) |
| 14 | Post-Quantum Cryptography | Crypto primitive | ✅* | Enterprise ($249) |
| 15 | SEP | On-demand | ✅ | Pro+ |
| 16 | GDPR-Safe Analytics | < 1 ms | ✅ | All |
| 17 | Uptime Monitor | Background | ✅ | All |
| 18 | File Scanner | On-demand | ✅ | Community Business+ |
| 19 | Email Guard | On-demand | ✅ | Community Business+ |
| 20 | Secrets Rotation Monitor | Background | ✅ | All |
| 21 | Agent Action Whitelist | Per-request | ✅ | All |
| 22 | SMB Compliance Report | On-demand | ✅ | Community Business+ |
| 23 | Secrets Governance | Background + On-demand | ✅ | Community Business+ or +$12/mo add-on |
| 24 | Obsidian Integration | On-demand / plugin | ✅ | Community Business+ |
| 25 | OTel Distributed Tracing | Per-request background | ✅ | All (opt-in) |
| 26 | SOC Dashboard | SPA on-demand | ✅ | Pro+ |
| 27 | Public API Documentation | Static Redoc | ✅ | All (public) |
| 28 | Load Profiling + Flamegraph | On-demand (script) | ✅ | Ops |
| 29 | SLO Burn-Rate Alerting | Grafana provisioned | ✅ | All |

*PQC requires liboqs-python system package; classical fallback if unavailable.

---

## 2. Skill 1 — Secret Redaction

**File:** `warden/secret_redactor.py`

Scans raw text for credentials, PII, and sensitive tokens using 15 compiled
regex patterns + a Shannon entropy scan for unknown high-entropy secrets.
Every match is replaced with `[REDACTED:<kind>]` before any other processing.

### Secret Types (R-01 through R-15)

OpenAI key, Anthropic key, HuggingFace token, AWS access key, GitHub token,
Stripe key, GCP API key, Bearer token, PEM private key, URL credentials,
credit card (Luhn-validated), US SSN, IBAN, email, RFC-1918 IPv4 (strict mode).

Shannon entropy scan: flags tokens ≥ 32 chars with ≥ 4.5 bits/char that
don't match any named pattern.

### Configuration

| Env Var | Effect |
|---------|--------|
| `STRICT_MODE=true` | Enables stricter variants + private IPv4 (R-15) |

### Integration

```python
result = warden_filter(content)
if result["secrets_found"]:
    audit_log(result["secrets_found"])   # log types only — never values
forward_to_model(result["filtered_content"])
```

---

## 3. Skill 2 — Semantic Threat Analysis

**File:** `warden/semantic_guard.py`

Two-layer rule engine evaluating the **redacted** text:

1. **Rule Engine** — 10 named rules (S-01→S-10). Compound escalation: 3×
   MEDIUM → HIGH. Hardcoded BLOCK for CBRN (S-03), self-harm (S-04), CSAM (S-05).

2. **PhishGuard + SE-Arbiter** — URL phishing detection + 4 social-engineering
   pattern groups (SEC-GAP-002). Single match → se_risk ≥ 0.75 → HIGH.

### Flag Types

| Flag | Triggered by |
|------|-------------|
| `prompt_injection` | Jailbreak / DAN / override language |
| `harmful_content` | Violence, abuse (non-CBRN) |
| `weapon_synthesis` | CBRN — always BLOCK |
| `self_harm` | Detailed methods — always BLOCK |
| `csam` | Child sexual content — always BLOCK |
| `exfiltration_probing` | System-prompt extraction attempts |
| `obfuscation` | Residual encoding after Stage 2 decode |
| `policy_violation` | Explicit guideline-violation requests |
| `explicit_content` | Adult content |
| `pii_detected` | PII combos not caught by Stage 3 |

---

## 4. Skill 3 — Risk Decision Engine

**File:** `warden/main.py` (pipeline orchestration)

Aggregates verdicts from all 9 pipeline stages. Highest risk level wins.
Emits structured `FilterResponse` with `allowed`, `risk_level`, `semantic_flags`,
`secrets_found`, `processing_ms`.

```json
{
  "allowed": false,
  "risk_level": "HIGH",
  "semantic_flags": [{"flag": "prompt_injection", "score": 0.89}],
  "secrets_found": [{"kind": "openai_api_key", "start": 42, "end": 93}],
  "processing_ms": 18.4
}
```

---

## 5. Skill 4 — Autonomous Rule Evolution

**File:** `warden/brain/evolve.py`

Sends a structured summary of every HIGH/BLOCK event to **Claude Opus 4.6**
(no raw content — GDPR-safe). Claude generates new detection examples or regex
patterns. Rules are hot-loaded into the running corpus without restart.

**Intel Bridge** (`INTEL_OPS_ENABLED=true`): fetches recent ArXiv LLM-attack
papers → `synthesize_from_intel()` → auto-evolves corpus from published research.

| Config | Default |
|--------|---------|
| `ANTHROPIC_API_KEY` | Required (air-gap mode: Evolution skipped, detection still works) |
| `INTEL_BRIDGE_INTERVAL_HRS` | `6` |

---

## 6. Skill 5 — Topological Gatekeeper (TDA)

**File:** `warden/topology_guard.py`

Converts text to a character n-gram point cloud and computes Betti numbers
(β₀ connected components, β₁ 1-cycles) using persistent homology. Runs in
< 2 ms on CPU — the fastest gate in the pipeline.

Detects bot payloads, random-noise flooding, and DoS content before the
obfuscation decoder runs.

| Config | Default |
|--------|---------|
| `TOPO_NOISE_THRESHOLD_CODE` | `0.65` |
| `TOPO_NOISE_THRESHOLD_NATURAL` | `0.82` |

Uses `ripser` for true persistent homology when installed; algebraic
fallback otherwise.

---

## 7. Skill 6 — HyperbolicBrain

**Files:** `warden/brain/semantic.py`, `warden/brain/hyperbolic.py`

`sentence-transformers/all-MiniLM-L6-v2` (80 MB, CPU-only) encodes input
text, then projects embeddings into the **Poincaré ball** (curvature c=1).
Final score blends **70% cosine + 30% hyperbolic distance**.

Hyperbolic geometry separates hierarchically-nested multi-layer attacks
(jailbreak inside roleplay) that appear close in Euclidean cosine space.

| Config | Default |
|--------|---------|
| `SEMANTIC_THRESHOLD` | `0.72` |
| `MODEL_CACHE_DIR` | `/warden/models` (Docker) / `MODEL_CACHE_DIR` env |

Latency: 3–8 s cold start; 5–20 ms warm; 20–60 ms with 500+ corpus examples.

---

## 8. Skill 7 — Causal Arbiter

**File:** `warden/causal_arbiter.py`

Gray-zone resolution via a Bayesian DAG implementing Pearl's do-calculus
with backdoor-path correction for 5 causal nodes. Runs in ~1–5 ms — zero LLM calls.

Nodes: `ml_score`, `ers_score`, `obfuscation_detected`, `block_history`,
`tool_tier`, `content_entropy`, `se_risk`.

Output: `CausalResult.risk_probability`. If ≥ `CAUSAL_THRESHOLD` → HIGH.

| Config | Default |
|--------|---------|
| `CAUSAL_THRESHOLD` | `0.65` |

---

## 9. Skill 8 — Browser Security Sandbox

**File:** `warden/tools/browser.py`

Playwright headless Chromium sandbox (`BrowserSandbox`) for navigating,
screenshotting, and asserting page state.

- `record_video=True` — WebM session recording shipped to MinIO Evidence Vault
  via `ScreencastRecorder` + `s3.ship_screencast(session_id, video_path)`
- `BrowserSandbox.__aexit__` closes page before context to finalise WebM

**SOVA tool #28 — `visual_assert_page`:**
Takes a full-page PNG, sends to Claude Vision (claude-opus-4-6) with an
`assertion` prompt. In-process — no HTTP round-trip. Requires `ANTHROPIC_API_KEY`.

| Config | Effect |
|--------|--------|
| `PATROL_URLS` | Comma-separated extra URLs for `sova_visual_patrol` |

---

## 10. Skill 9 — SOVA Autonomous Agent

**File:** `warden/agent/sova.py`

Claude Opus 4.6 agentic loop (≤10 iterations). Prompt caching on system
prompt cuts repeated-call cost by ~70%. Redis conversation memory
(`sova:conv:{session_id}`, 6h TTL, 20-turn cap).

**30 SOVA tools:**

| # | Tool | Description |
|---|------|-------------|
| 1–5 | Health, stats, config CRUD | Gateway introspection |
| 6–10 | Threat intel (list, refresh, dismiss) | CVE + ArXiv intel |
| 11–16 | Communities (list, get, rotate key, members) | Community management |
| 17–21 | Monitors (list, status, uptime, history) | SaaS uptime checks |
| 22–26 | Financial (impact, cost-saved, ROI, proposal) | Dollar impact |
| 27 | `filter_request` | Test a payload through `/filter` |
| 28 | `visual_assert_page` | BrowserSandbox + Claude Vision |
| 29 | `scan_shadow_ai` | `ShadowAIDetector.scan()` — real /24 subnet probe |
| 30 | `explain_decision` | 9-stage causal chain + XAI brief |

**7 ARQ cron jobs:**

| Job | Schedule | Action |
|-----|----------|--------|
| `sova_morning_brief` | 08:00 UTC daily | Health + threat summary → Slack |
| `sova_threat_sync` | Every 6h | CVE + ArXiv refresh |
| `sova_rotation_check` | 02:00 UTC daily | Community key rotation audit |
| `sova_sla_report` | Monday 09:00 UTC | P99 + availability report |
| `sova_upgrade_scan` | Sunday 10:00 UTC | Dependency CVE sweep |
| `sova_corpus_watchdog` | Every 30 min | Delegates to WardenHealer (LLM-free) |
| `sova_visual_patrol` | 03:00 UTC daily | ScreencastRecorder + Claude Vision patrol |

**WardenHealer** (`warden/agent/healer.py`): LLM-free autonomous anomaly
detection — circuit breaker state, bypass spike >15%, corpus DEGRADED,
canary probe. Direct `httpx` calls only — no SOVA loop invoked.

**Endpoints:**
```
POST   /agent/sova              query (agentic loop)
DELETE /agent/sova/{sid}        clear session
POST   /agent/sova/task/{job}   trigger scheduled job manually
```

---

## 11. Skill 10 — MasterAgent (Multi-Agent SOC)

**File:** `warden/agent/master.py`

Supervisor agent that decomposes a complex SOC task into parallel sub-agent
workstreams, then synthesises results. Uses `client.beta.messages.batches`
for decompose + synthesis (50% input token discount on scheduled jobs).

**Sub-agents (each has a restricted tool subset — principle of least privilege):**

| Sub-agent | Specialisation |
|-----------|---------------|
| `SOVAOperator` | Gateway health, quota management, key rotation |
| `ThreatHunter` | CVE triage, ArXiv intel, adversarial analysis |
| `ForensicsAgent` | Evidence Vault reconstruction, GDPR Art.30, visual patrol |
| `ComplianceAgent` | SLA monitoring, SOC 2 control mapping, ROI proposals |

**Security controls:**
- Every delegated task carries HMAC-SHA256 token `(sub_agent:task_hash:ts:sig)`
- `REQUIRES_APPROVAL` actions → Slack webhook → Redis pending (1h TTL) →
  `POST /agent/approve/{token}?action=approve|reject`
- `auto_approve=True` skips gate for scheduled jobs

**Token budget:** `_SUB_AGENT_MAX_ITER=5`, `_SUB_AGENT_TOKEN_BUDGET=8192` early-halt.

**Endpoints:**
```
POST  /agent/master               run decompose → sub-agents → synthesis
POST  /agent/approve/{token}      approve or reject pending action
GET   /agent/approve/{token}      check approval status
```

**Tier gate:** `master_agent_enabled` — Pro ($69/mo) and above.

---

## 12. Skill 11 — Shadow AI Discovery

**Files:** `warden/shadow_ai/discovery.py`, `warden/shadow_ai/policy.py`

Discovers unauthorised AI tool usage in the corporate network.

**Subnet probe** (`ShadowAIDetector.scan()`):
- Async /24 probe (max 256 hosts, max 50 concurrent, 3s timeout)
- HTTP fingerprinting against 18 AI provider signatures
- Optional scapy ARP pre-probe (`SHADOW_AI_USE_SCAPY=true`) — 60–80% faster
- Redis findings store: `shadow_ai:findings:{tenant_id}` (1,000-entry cap)

**DNS telemetry** (`classify_dns_event()`):
- Real-time domain classification against 18 provider signature DB
- Async UDP syslog sink (`warden/shadow_ai/syslog_sink.py`) —
  parses dnsmasq/BIND9/Zeek lines, port `SHADOW_AI_SYSLOG_PORT` (default 5514)

**18 providers fingerprinted:** OpenAI, Anthropic, Google Gemini, Ollama,
Gradio, HuggingFace, Cohere, Mistral, Together.ai, Replicate, Perplexity,
Stability AI, RunPod, Modal, Banana.dev, LMStudio, Jan.ai, GPT4All.

**Governance policy modes:**

| Mode | Behaviour |
|------|-----------|
| `MONITOR` | Report only — no enforcement |
| `BLOCK_DENYLIST` | Block requests matching denylist providers |
| `ALLOWLIST_ONLY` | Flag any provider not on allowlist |

**Tier gate:** Enterprise ($249/mo) or Shadow AI Discovery add-on (+$15/mo, Pro+).

**Endpoints:**
```
POST  /shadow-ai/scan          subnet probe
POST  /shadow-ai/dns-event     real-time DNS event classification
GET   /shadow-ai/findings      Redis findings list
GET   /shadow-ai/report        governance summary
GET   /shadow-ai/providers     18-provider signature DB
GET|PUT /shadow-ai/policy      get/set governance mode
```

---

## 13. Skill 12 — Explainable AI (XAI)

**Files:** `warden/xai/chain.py`, `warden/xai/renderer.py`

Builds a 9-stage pipeline graph (`CausalChain`) from a filter log entry and
renders it as an HTML or PDF report.

**`build_chain(log_entry)`** produces:
- 9 stage nodes with `verdict` (PASS/FLAG/BLOCK/SKIP), `score`, `color`, `weight`
- Primary cause: first BLOCK node → else highest-weight FLAG node
- `Counterfactual` per non-PASS stage: plain-English remediation action

**`render_html(chain)`** — self-contained, print-ready HTML with:
- SVG risk gauge (0–1 score dial)
- Collapsible stage cards (verdict color-coded)
- Counterfactual remediation section

**`render_pdf(chain)`** — uses reportlab if installed; falls back to HTML.
`X-Report-Format: pdf|html` response header signals which was returned.

**Dashboard** (`GET /xai/dashboard`): reads full log, calls `build_chain()` per
record. Outputs stage hit rates, top causes, flag distribution.

**Tier gate:** Pro+ or XAI Audit add-on (+$9/mo, Individual+).

**Endpoints:**
```
GET  /xai/explain/{id}         CausalChain JSON
POST /xai/explain/batch        batch chain build
GET  /xai/report/{id}          HTML report
GET  /xai/report/{id}/pdf      PDF report
GET  /xai/dashboard            aggregate stats
```

---

## 14. Skill 13 — Sovereign AI Cloud

**Files:** `warden/sovereign/` package

Routes AI inference through jurisdictionally-compliant MASQUE tunnels.
Enforces data residency per entity data class.

**8 Jurisdictions:** EU, US, UK, CA, SG (APAC), AU, JP, CH

**Tunnel protocols:** MASQUE_H3 (RFC 9297), H2, CONNECT_TCP.

**TOFU TLS pinning:** `tls_fingerprint` stored on first connection; mismatch
→ tunnel OFFLINE.

**Tunnel lifecycle:** PENDING → ACTIVE → DEGRADED (≥2 failures) → OFFLINE (≥5 failures).

**Transfer rules matrix (key examples):**

| Data class | Blocked destinations |
|---|---|
| CLASSIFIED | All cross-border transfers |
| PHI | Only EU/US/UK/CA/CH allowed |
| PII/FINANCIAL/GENERAL | All jurisdictions with adequacy check |

**Adequacy partners:** EU↔UK, EU↔CA, EU↔JP, EU↔CH.

**Sovereignty attestation:** HMAC-SHA256 signed `SovereigntyAttestation`
stored in Redis (7-year TTL, 10,000-per-tenant cap).

**Tier gate:** Enterprise ($249/mo) — `sovereign_enabled`.

**16 endpoints at `/sovereign/*`:** jurisdictions, compliance check, policy CRUD,
tunnels CRUD + probe, route decision, attest issue/retrieve/verify/list, report.

---

## 15. Skill 14 — Post-Quantum Cryptography (PQC)

**File:** `warden/crypto/pqc.py`

Hybrid classical + post-quantum cryptographic primitives using `liboqs-python`.
All PQC code paths raise `PQCUnavailableError` if liboqs not installed —
classical Ed25519/X25519 still work.

**HybridSigner (FIPS 204):**
- Combines Ed25519 (64B) + ML-DSA-65 (3309B) = 3373-byte hybrid signature
- `hybrid_sign(data)` / `hybrid_verify(data, sig)`
- `hybrid_verify()` falls back to Ed25519-only if liboqs unavailable

**HybridKEM (FIPS 203):**
- X25519 + ML-KEM-768; ciphertext = ephem_pub (32B) + ML-KEM ct (1088B)
- Shared secret = HKDF-SHA256(X25519_ss XOR mlkem_ss[:32])
- XOR-then-HKDF: if one algorithm is broken, the other provides full security

**Community keypair integration:**
- `generate_community_keypair(pqc=True)` → kid gets `-hybrid` suffix
- `upgrade_to_hybrid(kp)` upgrades existing classical keypair
- `CommunityKeypair.is_hybrid` checks `kid.endswith("-hybrid") and mldsa_pub_b64 is not None`

**CTP PQC signing:**
- `sign_transfer_proof(community_keypair=kp)` signs canonical CTP bytes with ML-DSA-65
- `pqc_signature` field: base64-encoded ML-DSA-65 result
- Both HMAC-SHA256 and ML-DSA-65 must pass `verify_transfer_proof()`

**Tier gate:** Enterprise ($249/mo) — `pqc_enabled`.

**Endpoints:**
```
POST /communities/{id}/upgrade-pqc   upgrade keypair to hybrid PQC
```

---

## 16. Skill 15 — Syndicate Exchange Protocol (SEP)

**Files:** `warden/communities/sep.py`, `warden/communities/peering.py`,
`warden/communities/knock.py`, `warden/communities/transfer_guard.py`,
`warden/communities/data_pod.py`, `warden/communities/stix_audit.py`

End-to-end framework for inter-community document exchange with causal safety,
PQC signing, and tamper-evident audit trail.

### UECIID — Unique Encrypted Content Identifier

Format: `SEP-{11 base-62 chars}` encoding a 64-bit Snowflake integer.
Alphabet: `0-9A-Za-z` (case-sensitive). Lexicographic order = chronological order.

### Causal Transfer Proof (CTP)

HMAC-SHA256 over canonical fields:
```
transfer_id | source_community_id | target_community_id |
entity_ueciid | initiator_mid | issued_at | purpose
```
Optional ML-DSA-65 hybrid signature (`pqc_signature`) when `is_hybrid=True`.

### Transfer Guard

Bayesian DAG gates every `transfer_entity()`. Maps SEP context to
CausalArbiter evidence. Blocks exfiltration P≥0.70 in <20ms.
REJECTED transfers still written to DB + STIX chain.

### Sovereign Data Pods

Per-jurisdiction MinIO routing. Fernet-encrypted MinIO secret keys.
Resolution: jurisdiction → data_class → primary → first ACTIVE pod.
`probe_pod()` checks MinIO health endpoint.

### STIX 2.1 Audit Chain

Blockchain-style SHA-256 prev_hash chain of STIX 2.1 bundles.
4 objects per bundle: identity (source) + identity (target) +
relationship (`x-sep-proof` extension: risk_score, pqc_signature, data_class) +
note (CTP canonical). Genesis: `prev_hash = "0"×64`.
`verify_chain()` re-hashes all bundles. `export_chain_jsonl()` → SIEM JSONL.

### Knock-and-Verify Invitations

One-time Redis tokens (72h TTL). `issue_knock()`, `verify_and_accept_knock()`
asserts `invitee_tenant_id == claiming_tenant_id` → `invite_member()`.

**24 endpoints at `/sep/*`:**
UECIID resolve/search/list/register, pod-tag CRUD, peerings CRUD + accept +
transfer + proof-verify, knock issue/accept/revoke/list, pods CRUD + probe,
audit-chain list/verify/export.

---

## 17. Skill 16 — GDPR-Safe Analytics

**File:** `warden/analytics/logger.py`

Fire-and-forget NDJSON logger. Content is **never** logged — only metadata:
request type, content length, timing, risk level, flag types.

GDPR helpers: `purge_before(timestamp)`, `read_by_request_id(id)`.
Atomic writes via `tempfile.mkstemp()` + `os.replace()` — corruption-safe.

MinIO background ship: `warden-logs/logs/<date>/<request_id>.json` (fail-open).

---

## 18. Skill 17 — Uptime Monitor

**Files:** `warden/api/monitor.py`, `warden/workers/probe_worker.py`

Built-in SaaS monitoring for HTTP, SSL, DNS, and TCP checks.

- TimescaleDB hypertable with 1-day chunks, BRIN + composite indexes
- Continuous aggregate `probe_hourly` (30-min refresh) for uptime % + avg latency
- 90% columnar compression after 7 days; 30-day raw retention; 2-year aggregate retention
- Real-time WebSocket push: `/ws/monitor/{id}` via Redis Pub/Sub → asyncio.Queue

**8 endpoints at `/monitors/*`:** create, list, get, patch, delete,
`/status`, `/uptime?hours=N`, `/history?limit=N`.

---

## 19. Skill 18 — File Scanner (SMB)

**File:** `warden/api/file_scan.py`

Pre-upload file scanner for AI tools. Supports text, JSON, PDF, Python, JS/TS,
HTML, CSV, YAML, `.env`, SQL, docx, xlsx/xls (10 MB max).

**Extraction pipeline:**
- `.docx` — python-docx: paragraphs + table cells
- `.xlsx`/`.xls` — openpyxl: all sheets, all cell values
- `.pdf` — pdfminer → pypdf → raw decode (cascading fallback)
- Other — UTF-8 → latin-1 decode

**Detection layers:**
1. `SecretRedactor` — 15 PII/secret patterns + entropy scan
2. `SemanticGuard` — injection detection on first 5,000 chars
3. `ObfuscationDecoder` — base64/hex/ROT13 multi-layer (depth ≥2 → CRITICAL)
4. HTML injection — `<!--` comments, CSS-hidden elements, poisoned `<meta>` tags (Q4.12)

**Risk levels:** `SAFE` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`

**Endpoints:**
```
POST  /filter/file                  scan file (multipart/form-data)
GET   /filter/file/supported-types  list accepted extensions + size limit
```

---

## 20. Skill 19 — Email Guard (SMB)

**File:** `warden/api/email_guard.py`

Scans inbound email (subject + body + headers) for social engineering, phishing
links, and prompt-injection payloads hidden in email bodies.

**Detection:**
- 5 social-engineering subject patterns (urgency, authority spoofing, invoice fraud)
- 6 body injection patterns (AI persona override, instruction smuggling)
- Phishing URL classifier (defanged URLs, typosquatting, data URI abuse)
- `SecretRedactor` on body → `SemanticGuard` analysis

**Input:** `EmailScanRequest(subject, body, from_address, raw_headers, tenant_id)`
**Output:** `EmailScanResponse(safe, risk_level, findings, sanitized_body, processing_ms)`

**Endpoint:**
```
POST  /scan/email
```

---

## 21. Skill 20 — Secrets Rotation Monitor

**File:** `warden/api/rotation.py`

Tracks the age of 8 critical API secrets by SHA-256 digest prefix in Redis
(`warden:key_age:{digest}`). Fires Slack alerts automatically when keys approach
or pass the rotation policy window.

**Tracked secrets:** `WARDEN_API_KEY`, `ANTHROPIC_API_KEY`, `NVIDIA_API_KEY`,
`VAULT_MASTER_KEY`, `COMMUNITY_VAULT_KEY`, `SOVEREIGN_ATTEST_KEY`,
`SLACK_WEBHOOK_URL`, `PAGERDUTY_ROUTING_KEY`.

**Status:** `OK` (< 75 days) → `WARNING` (≥75 days) → `EXPIRED` (≥90 days).

| Config | Default |
|--------|---------|
| `KEY_ROTATION_WARNING_DAYS` | `75` |
| `KEY_ROTATION_MAX_DAYS` | `90` |
| `ADMIN_KEY` | Required for all endpoints |

**Endpoints:**
```
GET   /admin/rotation/status        age + status of all tracked secrets
POST  /admin/rotation/record        reset age clock for a label
POST  /admin/rotation/rotate-alert  manual Slack rotation reminder
```

---

## 22. Skill 21 — Agent Action Whitelist

**File:** `warden/agentic/action_whitelist.py`

Per-agent CRUD permission enforcement using glob-style endpoint patterns and
per-second rate limiting. Hot-path gate called before every agentic tool invocation.

**Rule fields:** `http_method` (`*` or specific verb), `endpoint_glob` (fnmatch),
`max_rps` (0 = unlimited).

**`check_action(agent_id, method, endpoint)` logic:**
1. No rules defined → allow (open policy, log warning)
2. Any rule matches (method + glob) → allow, enforce `max_rps`
3. No rule matches → deny

**Rate limiting:** 1-second sliding window in `agent_action_rate` SQLite table.
Thread-safe via shared `threading.Lock` with `AgentRegistry`.

**Storage:** `agent_action_whitelist` + `agent_action_rate` tables in `AgentRegistry` SQLite DB.

---

## 23. Skill 22 — SMB Compliance Report

**File:** `warden/api/compliance_report.py`

Generates GDPR Art.30 + FZ-152 compliance records for the Community Business tier.
Aggregates analytics logs over a configurable period (1–365 days).

**Report contents:**
- Processing KPIs: total requests, blocked, PII hits, anonymisation rate, avg latency
- GDPR Art.5(1)(a–f), Art.30, Art.35 checklist — all 8 items
- FZ-152 Art.18 (data localisation), Art.19 (cross-border transfer), Art.21 (Roskomnadzor)
- Top 10 detected flag categories
- Data minimisation statement (GDPR Art.5(1)(c))

**PDF:** reportlab if installed; HTML fallback with `X-Report-Format: html` header.

| Config | Default |
|--------|---------|
| `ORG_NAME` | `"Your Organisation"` |
| `TENANT_ID` | `"default"` |
| `DATA_RESIDENCY_JURISDICTION` | `"EU"` |
| `RETENTION_DAYS` | `"180"` |

**Endpoints:**
```
GET  /compliance/smb-report        JSON summary
GET  /compliance/smb-report/html   print-ready HTML
GET  /compliance/smb-report/pdf    PDF (reportlab) or HTML fallback
```

---

## 24. Skill 23 — Secrets Governance

**Files:** `warden/secrets_gov/vault_connector.py`, `warden/secrets_gov/inventory.py`,
`warden/secrets_gov/policy.py`, `warden/secrets_gov/lifecycle.py`,
`warden/api/secrets.py`

End-to-end secrets lifecycle management across multi-cloud vault connectors.
All operations are **metadata-only** — no plaintext secret values are ever
returned through the API.

### Vault Connectors

| Connector | Backend | Auth |
|-----------|---------|------|
| `AwsSecretsManager` | AWS Secrets Manager | IAM role / access key |
| `AzureKeyVault` | Azure Key Vault | Service principal / managed identity |
| `HashiCorpVault` | HashiCorp Vault | Token / AppRole |
| `GcpSecretManager` | GCP Secret Manager | Service account JSON |
| `EnvConnector` | Environment variables | N/A — local dev only |

All connectors implement `sync_metadata()` → populates inventory.

### Inventory

SQLite-backed `SecretsInventory` in `SEP_DB_PATH`. Fields per entry:
`label`, `vault_id`, `secret_path`, `data_class`, `rotation_age_days`,
`exposure`, `status` (ACTIVE/RETIRED), `expires_at`, `risk_score`.

`sync()` auto-retires expired entries and recalculates risk scores.

### Lifecycle Manager

- Expiry alerts at `expiry_warning_days` (default 14) before `expires_at`
- `schedule_rotation(label, target_date)` → persists to Redis + sends Slack reminder
- `lifecycle_summary()` → counts by status + upcoming rotations in 30d window

### Policy Engine

Per-tenant governance: 7 violation rules (V-01→V-07), compliance score (0–100).
Score < `min_compliance_score` (default 60) blocks new vault registrations.

**Tier gate:** Community Business+ or `secrets_vault` add-on (+$12/mo, Individual+).

**14 endpoints at `/secrets/*`:**
```
POST|GET|DELETE  /secrets/vaults/{id}       vault CRUD
POST             /secrets/vaults/{id}/sync  trigger metadata sync
GET              /secrets/vaults/{id}/health vault health check
GET              /secrets/inventory         list all entries
GET              /secrets/inventory/expiring entries expiring within N days
GET              /secrets/inventory/stats   count by status/risk tier
POST             /secrets/inventory/{id}/rotate  schedule rotation
POST             /secrets/inventory/{id}/retire  mark as RETIRED
GET              /secrets/lifecycle/schedule     upcoming rotations (30d)
GET|PUT          /secrets/policy             get/update governance policy
POST             /secrets/policy/audit       run violation scan
GET              /secrets/report             full governance report (JSON/PDF)
```

**Streamlit dashboard:** `warden/analytics/pages/6_Secrets_Governance.py` —
6 tabs: Overview, Vaults, Inventory, Lifecycle, Policy, Report.

---

## 25. Skill 24 — Obsidian Community Integration

**Files:** `warden/integrations/obsidian/note_scanner.py`, `warden/api/obsidian.py`,
`obsidian-plugin/main.ts`

Brings Shadow Warden AI security directly into Obsidian vaults. Notes are
scanned for secrets and classified before sharing to Business Communities via SEP.

### Note Scanner

`scan_note(content, frontmatter)` performs:
1. YAML frontmatter parse (regex + PyYAML fallback)
2. Data class inference: explicit field → tags → keywords → GENERAL
3. `SecretRedactor` scan — secrets replaced with `[REDACTED:<kind>]`
4. Word count + classification metadata returned (body never stored)

**Output:**
```json
{
  "data_class": "PHI",
  "secrets_found": 0,
  "word_count": 342,
  "tags": ["health", "patient"],
  "redacted_body": "Patient: [REDACTED:email] ..."
}
```

### API Endpoints (5)

```
POST  /obsidian/scan        scan note content — returns data_class, secrets_found
POST  /obsidian/share       register note as SEP entity → returns UECIID
GET   /obsidian/feed        shared notes feed for this tenant (max 20)
POST  /obsidian/ai-filter   pre-share AI enrichment (SecretRedactor → LLM)
GET   /obsidian/stats       vault scan statistics for this tenant
```

`/obsidian/share` blocks if `secrets_found > 0` or `data_class == CLASSIFIED`.
UECIID format: `SEP-{11 base-62 chars}`.

### Obsidian Plugin (`obsidian-plugin/main.ts`)

TypeScript plugin built on the Obsidian Plugin API (minAppVersion `1.4.0`).

**5 commands:**
| Command | Action |
|---------|--------|
| Scan current note | POST /obsidian/scan → ScanResultModal |
| Share current note | POST /obsidian/share → ShareResultModal (shows UECIID) |
| Scan entire vault | Iterates all `.md` files → aggregate stats |
| View community feed | GET /obsidian/feed → FeedModal |
| Ping Warden | GET /health → status check |

**Auto-scan:** fires on `vault.on('modify')` with 800ms debounce. Status bar
shows last scan result (✅ / ⚠️ / 🔴). Ribbon icon toggles settings tab.

**Tier gate:** Community Business+ (included — no add-on required).

---

## 26. Skill 25 — OTel Distributed Tracing

**Files:** `warden/telemetry.py`, all 9 pipeline stage modules

Exports OpenTelemetry spans for every filter request — one root span per
`POST /filter` call, with child spans per pipeline stage. Enables per-layer
latency breakdown in Jaeger and root-cause pinpointing on latency regressions.

### Architecture

```
POST /filter → root span "warden.filter"
  ├── topology         span (warden.stage=topology)
  ├── obfuscation      span (warden.stage=obfuscation)
  ├── secrets          span (warden.stage=secrets)
  ├── semantic_rules   span (warden.stage=semantic_rules)
  ├── brain            span (warden.stage=brain)
  ├── causal           span (warden.stage=causal)
  ├── phish            span (warden.stage=phish)
  ├── ers              span (warden.stage=ers)
  └── decision         span (warden.stage=decision)
```

Spans flow: warden → OTel Collector → Jaeger (OTLP gRPC port 4317).

### Configuration

| Env Var | Default | Effect |
|---------|---------|--------|
| `OTEL_ENABLED` | `false` | Enable/disable all tracing |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4317` | Collector gRPC endpoint |
| `OTEL_SERVICE_NAME` | `shadow-warden` | Service label in Jaeger |

### Activation on production

```bash
# Add to /opt/shadow-warden/.env
OTEL_ENABLED=true
# Restart warden service
docker compose restart warden
# Open Jaeger UI at http://91.98.234.160:16686
```

### GDPR compliance

Span attributes **never** contain raw content, decoded text, or PII.
Only metadata: stage name, risk level, latency ms, score floats, secret count.
See Rule.md §21 for the complete allowed/prohibited attribute list.

**Tier gate:** All tiers. Activated via `OTEL_ENABLED=true` env var.

---

## 27. Skill 26 — SOC Next.js Dashboard

**Files:** `dashboard/` — Next.js 14.2 App Router SPA

Real-time Security Operations Center dashboard. Connects to the warden API
and analytics service to display live threat data, filter test results, and
platform observability (Grafana + Jaeger iframes).

### Pages

| Route | Page | Data source |
|-------|------|-------------|
| `/overview` | KPI cards + 24h area chart + verdict pie + ROI | `/analytics/stats` |
| `/events` | Paginated event table with verdict filter + search | `/analytics/events` |
| `/events/[id]` | 9-stage pipeline timeline + scores | `/analytics/event/{id}` |
| `/threats` | Bar chart + radar chart + 14-day trend | `/analytics/threats` |
| `/sandbox` | Live filter test harness | `POST /filter` |
| `/platform/metrics` | Grafana iframe panels | Grafana embed |
| `/platform/traces` | Jaeger search iframe | Jaeger embed |

### Tech stack

- Next.js 14.2 App Router, TypeScript
- TanStack Query v5 — polling every 30s, stale-while-revalidate
- Recharts — AreaChart, BarChart, PieChart, RadarChart
- Tailwind CSS dark theme (custom `surface.*` + `accent.*` palette)
- lucide-react icons

### Deployment

```bash
# Build image
docker build -t shadow-warden-dashboard ./dashboard

# Run (prod)
docker run -d --name warden-dashboard \
  --network shadow-warden_warden-net \
  --network-alias dashboard \
  -p 3002:3002 \
  -e NEXT_PUBLIC_API_URL=https://api.shadow-warden-ai.com \
  shadow-warden-dashboard

# Caddy routes dash.shadow-warden-ai.com → dashboard:3002
```

**Tier gate:** Pro+ (requires auth gate — Block L-03).

---

## 27. Skill 27 — Public API Documentation (Redoc)

**File:** `docs/redoc.html` · **Endpoint:** `GET /openapi-public.json`

Serves the complete OpenAPI 3.1 schema at `/openapi-public.json` with no authentication required. The Caddy reverse proxy mounts `docs/redoc.html` as `/srv/docs/index.html` and serves it under `docs.shadow-warden-ai.com`. The Redoc SPA fetches the schema from `https://api.shadow-warden-ai.com/openapi-public.json` cross-origin (CORS allowed for `docs.shadow-warden-ai.com`).

**Contrast with `/openapi.json`:** Protected by HTTP Basic auth when `DOCS_PASSWORD` is set. `/openapi-public.json` is always public — no password, no token — making it suitable for developer portal embedding.

**Configuration:**
```
# No extra env vars required — endpoint is always active.
# DOCS_PASSWORD protects /docs and /openapi.json only; does not affect /openapi-public.json.
```

**Tier gate:** All (public, no auth).

---

## 28. Skill 28 — Load Profiling + Flamegraph

**File:** `scripts/profile_under_load.sh`

Simultaneously runs a k6 load test and py-spy CPU profiler against the live warden process, producing an SVG flamegraph, a Speedscope JSON, and k6 NDJSON metrics. Results are optionally uploaded to MinIO for long-term SOC evidence retention.

**Workflow:**
1. Resolves warden process PID from Docker (`shadow-warden-warden-1` or `warden-warden`) or local `pgrep`.
2. Launches two py-spy recorders in background: SVG flamegraph + Speedscope JSON at `PYSPY_RATE` Hz (default 100).
3. Runs `k6/load_test.js` with `--env SCENARIO=<scenario>` (all / baseline / ramp / spike / soak).
4. Stops py-spy and uploads all artifacts to MinIO `warden-evidence/profiles/<timestamp>/` via `mc`.

**Usage:**
```bash
WARDEN_URL=https://api.shadow-warden-ai.com \
WARDEN_API_KEY=your-key \
SCENARIO=baseline \
./scripts/profile_under_load.sh
```

**MinIO setup (one-time):**
```bash
mc alias set warden http://localhost:9000 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD
```

**Tier gate:** Ops (server-side tool, no tier gate).

---

## 29. Skill 29 — SLO Burn-Rate Alerting

**File:** `grafana/provisioning/alerting/warden_alerts.yml` (rules `warden-burn-fast`, `warden-burn-slow`)

Google SRE-style multi-window burn-rate alerts for the 99.9% SLO (error budget = 0.1%/month = 43.8 min). Two rules using the AND-gate multi-window pattern to eliminate false positives from transient spikes:

| Rule | Windows | Threshold | Meaning | Action |
|------|---------|-----------|---------|--------|
| Fast burn (critical) | 1h + 5min | 14.4× SLO rate | 2% of monthly budget/hour | Page immediately |
| Slow burn (warning) | 6h + 30min | 6× SLO rate | 5% of monthly budget/6h | File ticket |

**Formula:** `burn_rate = actual_error_rate / slo_error_rate` where `slo_error_rate = 0.001` (99.9% SLO).

**Multi-window AND gate:** Both the long window (detects sustained burn) and short window (confirms it's not just a stale Prometheus datapoint) must exceed threshold before the alert fires. This is the standard Google SRE approach from "Implementing SLOs" (Chapter 5).

**Labels:** `severity: critical|warning`, `category: slo_burn`, `window: fast|slow`.

**Tier gate:** All (Grafana provisioned, no billing gate).

---

## 31. Integration Recipes

### Filter a prompt before forwarding to an LLM

```python
import httpx

resp = httpx.post("https://api.shadow-warden-ai.com/filter",
    headers={"X-API-Key": "YOUR_KEY"},
    json={"content": user_prompt, "tenant_id": "t-001"})

result = resp.json()
if not result["allowed"]:
    return {"error": "Request blocked", "reason": result["risk_level"]}

forward_to_model(result["filtered_content"])
```

### LangChain callback

```python
from warden.integrations.langchain_callback import WardenCallback

llm = ChatOpenAI(callbacks=[WardenCallback(api_key="YOUR_KEY", tenant_id="t-001")])
```

### Ask SOVA a question

```python
resp = httpx.post("/agent/sova",
    headers={"X-API-Key": "..."},
    json={"query": "What is the current ERS top-10 threat list?", "session_id": "my-session"})
print(resp.json()["response"])
```

### Get an XAI explanation

```python
resp = httpx.get(f"/xai/explain/{request_id}", headers={"X-API-Key": "..."})
chain = resp.json()
print(f"Primary cause: {chain['primary_cause']['stage']}")
print(f"Remediation: {chain['counterfactuals'][0]['action']}")
```

### Scan an Obsidian note before sharing

```python
resp = httpx.post("/obsidian/scan",
    headers={"X-API-Key": "...", "X-Tenant-ID": "t-001"},
    json={"content": note_body, "frontmatter": {"tags": ["health"]}})

result = resp.json()
if result["secrets_found"] == 0:
    share = httpx.post("/obsidian/share", ...)
    print(f"UECIID: {share.json()['ueciid']}")
```

### Check secrets governance compliance

```python
resp = httpx.post("/secrets/policy/audit",
    headers={"X-API-Key": "...", "X-Tenant-ID": "t-001"})
audit = resp.json()
print(f"Compliance score: {audit['compliance_score']}/100")
print(f"Violations: {audit['violations']}")
```

---

## 29. Configuration Quick-Reference

| Env Var | Default | Skill |
|---------|---------|-------|
| `ANTHROPIC_API_KEY` | — | 4, 9, 10 (optional — fail-open) |
| `SEMANTIC_THRESHOLD` | `0.72` | 6 |
| `CAUSAL_THRESHOLD` | `0.65` | 7 |
| `TRANSFER_RISK_THRESHOLD` | `0.70` | 15 (Transfer Guard) |
| `STRICT_MODE` | `false` | 1, 3 |
| `REDIS_URL` | `memory://` | 9, 10, 11, 15, 17 |
| `SEP_DB_PATH` | `/tmp/warden_sep.db` | 15, 23, 24 |
| `COMMUNITY_VAULT_KEY` | — | 15 (Data Pods encryption) |
| `SHADOW_AI_USE_SCAPY` | `false` | 11 |
| `SHADOW_AI_SYSLOG_ENABLED` | `false` | 11 |
| `SHADOW_AI_SYSLOG_PORT` | `5514` | 11 |
| `INTEL_OPS_ENABLED` | `false` | 4 (ArXiv Intel Bridge) |
| `INTEL_BRIDGE_INTERVAL_HRS` | `6` | 4 |
| `PATROL_URLS` | — | 9 (visual patrol) |
| `ADMIN_KEY` | — | Add-on grant/revoke |
| `SOVEREIGN_ATTEST_KEY` | — | 13 |
| `WARDEN_API_KEY` | — | All (main auth) |
| `MODEL_CACHE_DIR` | `/warden/models` | 6 |
| `TOPO_NOISE_THRESHOLD_CODE` | `0.65` | 5 |
| `TOPO_NOISE_THRESHOLD_NATURAL` | `0.82` | 5 |
| `OBSIDIAN_WARDEN_URL` | `https://api.shadow-warden-ai.com` | 24 (plugin setting) |
| `OBSIDIAN_COMMUNITY_ID` | — | 24 (plugin setting) |
