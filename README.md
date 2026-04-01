# Shadow Warden AI

**The AI Security Gateway for the US/EU Marketplace**

Shadow Warden AI is a self-contained, GDPR-compliant security layer that sits in front of every AI request in your application. It blocks jailbreak attempts, strips secrets and PII, shadow-bans attackers, enforces agentic safety guardrails, and self-improves — all without sending sensitive data to third parties.

**Version:** 2.4 · **License:** Proprietary · **Language:** Python 3.11+

---

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

Eleven Docker services: `proxy` (80/443), `warden` (8001), `app` (8000), `analytics` (8002), `dashboard` (8501), `postgres`, `redis`, `prometheus`, `grafana` (3000), `minio` (9000/9001), `minio-init`.

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

export WARDEN_API_KEY="" REDIS_URL="memory://" LOGS_PATH="/tmp/warden_test.json"
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

---

## Roadmap

### v2.1 (current)

- **Data-Gravity Hybrid Hub** — MinIO on-prem S3 storage for Evidence Vault + analytics logs. Data sovereignty: security metadata stays inside your infrastructure.
- `warden/storage/s3.py` — S3 backend with lazy boto3 import, background threads, auto-bucket creation, fail-open.
- `minio` + `minio-init` services added to `docker-compose.yml`. Enable with `S3_ENABLED=true`.

### v2.0

- **Topological Gatekeeper** — TDA pre-filter using n-gram point cloud + Betti numbers (β₀, β₁). Catches noise/bot/DoS in < 2ms before any ML. Ripser optional for true persistent homology.
- **Hyperbolic Semantic Space** — MiniLM projected into Poincaré ball. Cosine (70%) + hyperbolic (30%) blend. Better precision on hierarchically nested attacks.
- **Causal Arbiter** — Bayesian DAG with Pearl's do-calculus resolves ML gray zone. Five causal nodes + backdoor correction. Zero LLM calls, ~1–5ms CPU.

### v1.9

- INJECTION_CHAIN pattern — detects compromised agents acting on injected instructions after a blocked tool result
- Encrypted PII vault — Fernet + HMAC-SHA256, no original PII value ever unencrypted in memory
- Progressive streaming — 400-char fast-scan buffer then live-emit; eliminates streaming TTFB

### v1.8

- Entity Risk Scoring (ERS) — Redis sliding-window reputation, shadow ban at critical threshold
- Shadow Ban — fake `allowed=true` responses, real LLM never called, no adversarial feedback
- Zero-Trust Agent Sandbox — capability manifests, `authorize_tool_call()`, kill-switch API
- Evidence Vault — SHA-256 sign-last bundles, live compliance score `Cs`, SOC 2 / litigation ready
- Multimodal Guard — CLIP (image) + Whisper+FFT (audio, ultrasonic steganography)
- ThreatVault 1,300+ — upgraded signature library with Evolution Engine auto-growth
- WardenDoctor — production diagnostics CLI with P50/P99 benchmarks and CI/CD JSON output
- 30/30 pre-release integration suite (SMOKE → Compliance)
- Log rotation — Docker json-file driver, 10MB / 3 files per service
- Startup MOTD — live system status on every `docker compose up`

### v1.0

- NVIDIA NIM routing — `nim/<org>/<model>` prefix
- Full multi-cloud provider catalogue
- Backend contact form (`/api/contact`)

### v0.9

- Cryptographic audit trail (SHA-256 hash chain, SQLite + WAL)
- SOC 2 Type II controls (CC6.1, CC6.7, CC7.2)

### v0.8

- PromptShield — indirect injection detection (OWASP LLM01/02), six labeled attack types

### v0.7

- Google Cloud Vertex AI provider
- Amazon Bedrock streaming (binary AWS EventStream → SSE)
- `/v1/embeddings` proxy

### v0.6

- ToolCallGuard + AgentMonitor
- WalletShield (token budget enforcement)
- Reversible PII masking
- Amazon Bedrock + Azure OpenAI routing

### v0.5

- OutputGuard v2 (10 risk types, per-tenant config)
- SSE streaming in `/v1/chat/completions`
- Real-time WebSocket event feed

### v0.4

- Obfuscation decoder pre-filter
- Per-tenant API keys (SHA-256 hash lookup)
- Batch filter endpoint
- Redis content-hash cache

### Planned

- [ ] Kubernetes Helm chart (EKS / GKE / AKS)
- [ ] Browser extension — real-time protection for ChatGPT, Claude.ai, Copilot
- [ ] Threat intelligence sharing (STIX/TAXII feed export)
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
