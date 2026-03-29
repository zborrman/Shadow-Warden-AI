# NVIDIA Nemotron Super — Integration Plan
## Shadow Warden AI · v2.4 target

**Model:** `Llama-3.3-Nemotron-Super-49B-v1`
**Access:** NVIDIA NIM Cloud API + optional self-hosted NIM container
**API compatibility:** OpenAI-compatible (`/v1/chat/completions`)
**Special capability:** Native "thinking mode" (`"thinking": {"type": "enabled"}`)

---

## 1. Strategic Rationale

| Problem today | How Nemotron solves it |
|---|---|
| Evolution Engine uses Claude Opus (external API → data leaves perimeter) | Nemotron via NIM self-hosted = zero egress, full GDPR compliance |
| CausalArbiter is a static Bayesian DAG — can't reason about novel attack patterns | Nemotron thinking mode = chain-of-thought causal inference |
| Threat Intel module generates simple regex rules | Nemotron produces richer detection logic with semantic context |
| Red Team Cert needs a target LLM for lab challenges | Nemotron as the "victim LLM" — controllable, no API cost per student |
| Air-gapped deployment breaks Evolution Loop | Nemotron NIM container = fully air-gapped self-improving warden |

**Core thesis:** Nemotron Super becomes Shadow Warden's on-premise AI brain — replacing external API dependency with a self-hosted 49B reasoning model that never touches the internet.

---

## 2. Integration Architecture

```
POST /filter
    ↓
TopologicalGatekeeper  (< 2ms, unchanged)
    ↓
ObfuscationDecoder     (unchanged)
    ↓
SecretRedactor         (unchanged)
    ↓
SemanticGuard          (unchanged)
    ↓
HyperbolicBrain        (MiniLM, unchanged)
    ↓
CausalArbiter          (Bayesian DAG, fast path — unchanged)
    ↓ [MEDIUM confidence only — gray zone]
NemotronArbiter ★ NEW  (thinking mode, < 150ms async budget)
    ↓
ERS / Shadow Ban       (unchanged)
    ↓
Decision

Background:
    HIGH/BLOCK → NemotronEvolutionEngine ★ NEW (replaces Claude Opus)
                      ↓ add_examples() hot-reload
               _brain_guard corpus
```

**Key design constraint:** Nemotron sits on the **async gray-zone path only** — it never adds latency to the P99 fast path. The Bayesian CausalArbiter remains the primary < 5ms path; Nemotron is invoked only when confidence is in the 0.45–0.65 range.

---

## 3. Four Integration Layers

### Layer 1 — NemotronEvolutionEngine (replaces Claude Opus)
**File:** `warden/brain/evolve_nemotron.py` (new) + factory in `evolve.py`

**What changes:**
- Same interface as `EvolutionEngine`: `async def process_attack(content, flags, risk_level)`
- Uses NIM OpenAI-compatible endpoint instead of `anthropic.AsyncAnthropic()`
- Enables Nemotron thinking mode for deeper rule synthesis
- Config: `EVOLUTION_ENGINE=nemotron|claude|auto`
  - `auto` = use nemotron if `NVIDIA_API_KEY` is set, else fall back to claude

**Why this is better than Claude Opus:**
- Self-hosted: zero data egress → fully GDPR-compliant without any API call
- Nemotron's thinking mode produces structured reasoning traces stored in audit log
- 49B model at NIM inference speed is cheaper per-token than Opus at scale
- Air-gapped customers can run the full Evolution Loop offline

**Prompt engineering delta:** Nemotron uses the same system prompt structure but benefits from an explicit `<thinking>` budget. Add `budget_tokens: 4096` for rule generation tasks.

---

### Layer 2 — NemotronArbiter (gray-zone deep reasoning)
**File:** `warden/brain/nemotron_arbiter.py` (new)

**What changes:**
- Called by `CausalArbiter` when `0.45 ≤ P(HIGH_RISK) ≤ 0.65`
- Receives: sanitized content (post-SecretRedactor), current flags, Bayesian score
- Returns: `NemotronVerdict(risk_level, confidence, reasoning_summary, escalate_to_block)`
- Async with a 150ms timeout — on timeout returns `None` (CausalArbiter decision stands)

**Thinking mode usage:**
```python
extra_body = {
    "thinking": {"type": "enabled", "budget_tokens": 2048}
}
# Response includes a <think>...</think> block stored to audit trail
# Only the final verdict is used for the filter decision
```

**Audit trail integration:**
- `reasoning_summary` (not full thinking trace) stored in `filter_audit.nemotron_reasoning` column
- Full thinking trace: optional, stored to Evidence Vault (S3) if `NEMOTRON_STORE_THINKING=true`

---

### Layer 3 — Threat Intelligence Enrichment
**File:** `warden/threat_intel/nemotron_analyzer.py` (new)

**What changes:**
- Current flow: raw RSS/CVE feed → simple regex rule generation
- New flow: raw feed → Nemotron analysis → structured `ThreatRule` with:
  - Attack pattern description
  - 3–5 semantic examples for `_brain_guard` corpus
  - Regex pattern (if applicable)
  - OWASP LLM category mapping
  - Confidence score
  - Reasoning trace (stored in `threat_intel_items.analysis_reasoning`)

**Why thinking mode matters here:** Threat intelligence articles often require reading between the lines — Nemotron's chain-of-thought can extract attack patterns from prose descriptions that simple NLP misses.

---

### Layer 4 — Red Team Cert Lab Target
**File:** `warden/labs/nemotron_target.py` (new) + NIM Docker service

**What changes:**
- Self-hosted NIM container runs Nemotron as the "victim LLM" in lab challenges
- Lab students attack Nemotron endpoints via the cert lab environment
- Shadow Warden sits in front of Nemotron — students see if their attacks get blocked
- Scoreboard: each successful jailbreak = lab points; Shadow Warden detection rate tracked

**Docker service:**
```yaml
# docker-compose.yml addition
nemotron-nim:
  image: nvcr.io/nim/meta/llama-3.3-nemotron-super-49b-instruct:latest
  runtime: nvidia
  environment:
    NGC_API_KEY: ${NVIDIA_NGC_KEY}
  ports: ["8010:8000"]
  deploy:
    resources:
      reservations:
        devices: [{driver: nvidia, count: all, capabilities: [gpu]}]
  profiles: ["labs", "full"]   # opt-in only — requires GPU
```

*Note: The GPU service is `profiles: labs` — it does NOT start with the default `docker-compose up`. CPU-only deployments are unaffected.*

---

## 4. New Environment Variables

```env
# ── Nemotron / NVIDIA NIM ─────────────────────────────────────────────────────

# Master switch: nemotron | claude | auto (default: auto)
EVOLUTION_ENGINE=auto

# NVIDIA NIM Cloud API key (https://build.nvidia.com)
# If set → NemotronEvolutionEngine used when EVOLUTION_ENGINE=auto or nemotron
NVIDIA_API_KEY=nvapi-...

# NIM endpoint — cloud default, or self-hosted NIM container URL
NIM_BASE_URL=https://integrate.api.nvidia.com/v1

# Nemotron model name
NEMOTRON_MODEL=meta/llama-3.3-nemotron-super-49b-instruct

# Thinking mode token budget (Evolution Engine)
NEMOTRON_THINKING_BUDGET=4096

# Gray-zone arbiter: invoke Nemotron when CausalArbiter confidence is in this window
NEMOTRON_ARBITER_MIN=0.45
NEMOTRON_ARBITER_MAX=0.65
NEMOTRON_ARBITER_TIMEOUT_MS=150

# Store full thinking traces to Evidence Vault (S3) — default false (privacy)
NEMOTRON_STORE_THINKING=false

# Self-hosted NIM container (labs profile only)
NEMOTRON_NIM_LOCAL_URL=http://nemotron-nim:8000/v1
NVIDIA_NGC_KEY=                # required for NIM container pull
```

---

## 5. New Files

| File | Lines | Purpose |
|------|-------|---------|
| `warden/brain/nemotron_client.py` | ~80 | Async OpenAI-compat client, thinking mode, retry |
| `warden/brain/evolve_nemotron.py` | ~200 | `NemotronEvolutionEngine` — drop-in replacement for `EvolutionEngine` |
| `warden/brain/nemotron_arbiter.py` | ~150 | Gray-zone deep reasoning arbiter |
| `warden/threat_intel/nemotron_analyzer.py` | ~180 | Feed enrichment with thinking mode |
| `warden/labs/nemotron_target.py` | ~120 | Red Team Cert lab — Nemotron as attack target |
| `warden/tests/test_nemotron_client.py` | ~60 | Unit tests (mocked NIM responses) |

## 6. Modified Files

| File | Change |
|------|--------|
| `warden/brain/evolve.py` | Factory: `build_evolution_engine()` returns Nemotron or Claude based on env |
| `warden/causal_arbiter.py` | Hook: call `NemotronArbiter` in gray-zone path |
| `warden/main.py` | Wire NemotronArbiter in lifespan; Prometheus counter `NEMOTRON_ARBITER_INVOCATIONS` |
| `warden/metrics.py` | New metrics: `nemotron_arbiter_total`, `nemotron_arbiter_latency_ms`, `nemotron_evolution_total` |
| `data/init.sql` | Add `nemotron_reasoning TEXT` column to `filter_audit` |
| `docker-compose.yml` | Add `nemotron-nim` service under `profiles: [labs]` |
| `.env.example` | All new env vars |
| `warden/requirements.txt` | `openai>=1.30.0` already present — no new deps needed (NIM is OpenAI-compat) |
| `CLAUDE.md` | Update architecture diagram, key files table |

---

## 7. Implementation Phases

### Phase 1 — NIM Cloud API (1–2 days)
**Goal:** NemotronEvolutionEngine working against NVIDIA NIM cloud.

1. `warden/brain/nemotron_client.py` — async wrapper around `openai.AsyncOpenAI(base_url=NIM_BASE_URL)`
2. `warden/brain/evolve_nemotron.py` — port `EvolutionEngine` logic, replace `anthropic` calls with NIM client, add thinking mode
3. Factory in `evolve.py`: `build_evolution_engine()` checks `EVOLUTION_ENGINE` env + key availability
4. Tests: mock NIM responses, assert same `DynamicRule` output schema
5. Set `NVIDIA_API_KEY` on server → `EVOLUTION_ENGINE=auto` picks Nemotron

**Deliverable:** Evolution Loop runs on Nemotron cloud. Claude Opus still available as fallback.

---

### Phase 2 — NemotronArbiter (2–3 days)
**Goal:** Gray-zone requests get a second opinion from Nemotron's thinking mode.

1. `warden/brain/nemotron_arbiter.py`:
   - Accepts sanitized content + CausalArbiter score
   - Constructs a focused prompt: "Analyze this for LLM attack intent. Think step by step."
   - Parses `<think>` block for reasoning summary
   - Returns structured `NemotronVerdict`
2. Integrate in `causal_arbiter.py`: `if NEMOTRON_ARBITER_MIN ≤ score ≤ NEMOTRON_ARBITER_MAX → await arbiter`
3. Add `nemotron_reasoning` column to `filter_audit` (migration script)
4. Prometheus metrics + Grafana panel: "Nemotron arbiter invocations / overrides"
5. Tests: mock gray-zone scenarios, verify verdict integration

**Deliverable:** Every ambiguous request gets Nemotron's chain-of-thought analysis. Stored in audit log.

---

### Phase 3 — Threat Intel Enrichment (1–2 days)
**Goal:** Richer detection rules from threat feed analysis.

1. `warden/threat_intel/nemotron_analyzer.py` — replaces/augments existing rule generation
2. Prompt: structured JSON extraction from raw article text using thinking mode
3. Output: `ThreatAnalysis(attack_pattern, semantic_examples[], regex_pattern, owasp_category, confidence)`
4. Store `analysis_reasoning` in `threat_intel_items` table (migration)
5. Tests: fixture articles, assert structured output

**Deliverable:** Threat intel rules include semantic examples for `_brain_guard` — not just regexes.

---

### Phase 4 — Self-Hosted NIM + Red Team Labs (3–5 days, GPU required)
**Goal:** Full air-gapped deployment + Nemotron as Red Team Cert lab target.

1. Add `nemotron-nim` to `docker-compose.yml` under `profiles: [labs]`
2. `warden/labs/nemotron_target.py` — FastAPI router `/labs/chat` proxying to local NIM
3. Scoreboard service: track jailbreak attempts, detection rate, leaderboard
4. Update `NIM_BASE_URL` to `http://nemotron-nim:8000/v1` → entire stack air-gapped
5. Deployment guide update: §24 Self-Hosted Nemotron NIM

**Deliverable:** One command (`docker compose --profile labs up`) spins up the full cert lab environment including Nemotron.

---

## 8. Performance Budget

| Component | Latency target | Path type |
|-----------|---------------|-----------|
| CausalArbiter (Bayesian DAG) | < 5ms | Synchronous, always runs |
| NemotronArbiter (gray-zone) | < 150ms timeout | Async, gray-zone only (~8% of traffic) |
| NemotronEvolutionEngine | < 30s | Background task, never blocks response |
| Threat Intel Analysis | < 60s | Scheduled background job |

**P99 impact:** Near zero. NemotronArbiter runs async after the Bayesian decision. If it times out, the CausalArbiter verdict stands. The 150ms budget gives Nemotron enough time for `budget_tokens: 2048` thinking.

---

## 9. GDPR / Security Controls

| Concern | Control |
|---------|---------|
| Data sent to NVIDIA cloud API | Same GDPR anonymization as Claude: `_ANON_PATTERNS` strips UUIDs, IPs, emails before any NIM call |
| Self-hosted NIM = zero egress | Phase 4 NIM container: no data leaves perimeter at all |
| Thinking traces contain sensitive analysis | `NEMOTRON_STORE_THINKING=false` by default; if enabled, stored in Evidence Vault (S3), not in DB |
| Model access control | `NVIDIA_API_KEY` in secrets, never logged |
| NIM container image integrity | Pull from `nvcr.io` with NGC API key; SHA-256 digest pinned in compose file |

---

## 10. Metrics & Observability

New Prometheus counters added to `warden/metrics.py`:

```python
NEMOTRON_ARBITER_TOTAL = Counter(
    "warden_nemotron_arbiter_total",
    "Nemotron arbiter invocations",
    ["outcome"],           # agree | override_block | override_allow | timeout
)
NEMOTRON_ARBITER_LATENCY = Histogram(
    "warden_nemotron_arbiter_latency_ms",
    "Nemotron arbiter response latency",
    buckets=[20, 50, 100, 150, 200, 500],
)
NEMOTRON_EVOLUTION_TOTAL = Counter(
    "warden_nemotron_evolution_total",
    "Nemotron evolution engine invocations",
    ["engine"],            # nemotron | claude | skipped
)
```

New Grafana panels:
- **Nemotron Override Rate** — `nemotron_arbiter_total{outcome="override_block"}` / total filter requests
- **Arbiter Latency P99** — histogram panel
- **Evolution Engine source** — pie: nemotron vs claude vs skipped

---

## 11. Cost Analysis

### NIM Cloud API (Phase 1–3)
| Scenario | Volume | Est. cost/month |
|----------|--------|-----------------|
| Evolution Engine (5% of blocked = ~500 calls/day) | ~15K calls/mo | ~$18/mo |
| Nemotron Arbiter (8% of traffic = ~800 calls/day) | ~24K calls/mo | ~$29/mo |
| Threat Intel Enrichment (100 articles/day) | ~3K calls/mo | ~$4/mo |
| **Total cloud NIM** | — | **~$51/mo** |

vs. Claude Opus 4.6: ~$0.075/K input tokens × same volume ≈ **$180–240/mo**

### Self-Hosted NIM (Phase 4)
- Hardware: 1× A100 80GB or 2× A6000 48GB (rental: ~$2.50/hr on Lambda Labs)
- Monthly (always-on): ~$1,800/mo
- Monthly (on-demand for labs only, 8h/day): ~$600/mo
- Break-even vs cloud: at ~35K requests/day

**Recommendation:** Use NIM Cloud API for production (cost-effective). Self-hosted NIM only for Red Team Cert lab (burst usage during active cohort weeks).

---

## 12. Competitive Positioning

With Nemotron integration, Shadow Warden can market:

> **"The only AI security gateway powered by on-premise NVIDIA Nemotron 49B reasoning — zero data egress, chain-of-thought threat analysis, fully air-gapped."**

- vs. competitors using only regex/embeddings → Shadow Warden has **reasoning-native detection**
- vs. cloud-only AI security tools → Shadow Warden is **100% self-hostable, GDPR Art. 35 compliant**
- For enterprise/defense customers → the **air-gapped NIM deployment** is a major differentiator
- For Red Team Cert → Nemotron as a **real 49B target model** makes labs production-realistic

---

## Summary: Priority Order

| Priority | Phase | Effort | Impact |
|----------|-------|--------|--------|
| 🔴 P0 | Phase 1: NIM Cloud API + NemotronEvolutionEngine | 2 days | Replace Claude Opus dependency, reduce API cost 70% |
| 🔴 P0 | Phase 2: NemotronArbiter gray-zone | 3 days | Measurably improve F1 on ambiguous inputs |
| 🟡 P1 | Phase 3: Threat Intel Enrichment | 2 days | Richer detection rules from feeds |
| 🟢 P2 | Phase 4: Self-hosted NIM + Red Team Labs | 5 days | Air-gapped enterprise sales + cert lab |
