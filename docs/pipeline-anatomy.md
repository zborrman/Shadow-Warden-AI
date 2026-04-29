# Shadow Warden AI — Pipeline Anatomy

> **Audience:** Security architects, platform engineers, and contributors who need to understand the internal request lifecycle.
> **Version:** v4.8

---

## Overview

Every request that enters Shadow Warden passes through a layered, fail-fast defense pipeline before a decision (`allowed` / `blocked` / `shadow_ban`) is returned to the caller.  The stages are sequential by default; each stage can short-circuit and return a final decision without invoking later stages.

```
POST /filter
  │
  ├─ [0] Auth & Rate-Limit Gate         warden/auth_guard.py + slowapi
  ├─ [1] Redis Content-Hash Cache       warden/cache.py
  ├─ [2] Obfuscation Decoder            warden/obfuscation.py
  ├─ [3] Secret Redactor                warden/secret_redactor.py
  ├─ [4] Semantic Guard (rules)         warden/semantic_guard.py
  ├─ [5] Semantic Brain (ML)            warden/brain/semantic.py
  ├─ [6] Multimodal Guard               warden/image_guard.py + audio_guard.py
  ├─ [7] Entity Risk Scoring (ERS)      warden/entity_risk.py
  └─ [8] Decision + Event Logger        warden/analytics/logger.py
             │
             ├─► EvolutionEngine (async background)    warden/brain/evolve.py
             └─► Zero-Trust Sandbox (agent calls)      warden/agent_sandbox.py
```

---

## Stage-by-Stage Breakdown

### Stage 0 — Auth & Rate-Limit Gate

| Component | File | Key behaviour |
|-----------|------|---------------|
| `AuthGuard` | `auth_guard.py` | Per-tenant API keys (JSON file or SHA-256 hash lookup). Constant-time compare to prevent timing attacks. **Fail-closed**: startup raises `RuntimeError` if `WARDEN_API_KEY` and `WARDEN_API_KEYS_PATH` are both blank, unless `ALLOW_UNAUTHENTICATED=true` (dev only). |
| `slowapi` limiter | `main.py` | Default 60 req/min per IP, Redis-backed sliding window. Returns `429` on breach. Configurable via `RATE_LIMIT_PER_MINUTE`. |

`AuthResult` carries `tenant_id`, `entity_key` (GDPR pseudonym), and pre-computed ERS score for downstream stages.

---

### Stage 1 — Redis Content-Hash Cache

**File:** `warden/cache.py`

Incoming content is SHA-256 hashed.  If the hash exists in Redis (TTL 5 min), the cached `FilterResponse` is returned immediately — the full ML pipeline is skipped.  On any Redis failure, the stage is bypassed (fail-open).

```
cache hit  → return cached decision (0 ms ML overhead)
cache miss → continue to Stage 2, write result on exit
```

---

### Stage 2 — Obfuscation Decoder

**File:** `warden/obfuscation.py`

Attackers frequently encode payloads to bypass keyword-based filters.  This stage normalises the text before any analysis:

| Encoding | Detection method | Example attack |
|----------|-----------------|----------------|
| Base64 | `re.match` + `b64decode` round-trip | `SWdub3JlIGFsbC4uLg==` |
| Hex | `0x`-prefixed or pure hex strings | `49676e6f726520616c6c...` |
| ROT13 | Always-valid decode + semantic check | `Vtaber nyy cerivbhf...` |
| Unicode homoglyphs | Unicode category scan (`Lo`, `Ll` substitutes) | `Іgnorе аll рreviоus...` |

If any encoding is detected, the decoded form is used for all subsequent stages and the `obfuscation` flag is set in the response.

---

### Stage 3 — Secret Redactor

**File:** `warden/secret_redactor.py`

Fifteen regex patterns covering:

- OpenAI, Anthropic, HuggingFace API keys
- AWS access/secret keys, GCP service-account JSON fragments
- Generic bearer tokens, private SSH keys, JWT fragments
- Credit card numbers (Luhn-validated), IPv4 CIDR blocks, email addresses

Matched spans are replaced with `[REDACTED:<type>]`.  Redacted content is written to `filtered_content`; the original is never logged (GDPR hard requirement).

---

### Stage 4 — Semantic Guard (Rule Engine)

**File:** `warden/semantic_guard.py`

A deterministic, zero-latency rule engine that assigns risk signals:

- **BLOCK:** single pattern match against a known-critical pattern (e.g., `system prompt extraction`, `DAN/jailbreak` phrases)
- **HIGH:** direct match of one high-severity rule
- **MEDIUM:** one mid-severity signal
- **Compound escalation:** 3+ MEDIUM signals → escalated to HIGH automatically

Emits `flags` list (e.g., `["prompt_injection", "role_override"]`) for downstream correlation and SIEM export.

---

### Stage 5 — Semantic Brain (ML)

**File:** `warden/brain/semantic.py`

All-MiniLM-L6-v2 sentence embeddings compared against a corpus of known-malicious examples using cosine similarity.  A score above `SEMANTIC_THRESHOLD` (default `0.72`) triggers a `HIGH` or `BLOCK` decision.

Implementation details:

- Loaded once at startup via `@lru_cache(maxsize=1)` singleton
- Async-safe: inference runs in a `ThreadPoolExecutor` via `check_async()` — the event loop is never blocked
- Hot-reloadable: `add_examples(examples)` extends the corpus at runtime (used by the Evolution Engine)
- CPU-only: `--index-url https://download.pytorch.org/whl/cpu` prevents accidental CUDA pulls

---

### Stage 6 — Multimodal Guard

**Files:** `warden/image_guard.py`, `warden/audio_guard.py`

**Image (CLIP):** Submitted images are scanned for embedded jailbreak text using OpenAI CLIP zero-shot classification.  Jailbreak phrases are compared against image patch embeddings.  On HuggingFace auth failure, the stage fails open with a warning.

**Audio (FFT + Whisper):** WAV/MP3 audio is analysed in two passes:
1. FFT peak detection — flags ultrasonic energy (>20 kHz) that may carry steganographic commands inaudible to humans
2. Whisper transcription — the transcript is fed back through Stages 3–5

Both guards run in parallel (`asyncio.gather`) to minimise latency impact.

---

### Stage 7 — Entity Risk Scoring (ERS)

**File:** `warden/entity_risk.py`

Redis-backed sliding-window reputation system.  Every request outcome feeds four event counters per entity (GDPR pseudonym of `tenant_id + IP`):

| Event | Weight | Triggered by |
|-------|--------|-------------|
| `block` | 0.50 | Stage 4/5 BLOCK decision |
| `obfuscation` | 0.25 | Stage 2 decoded payload |
| `honeytrap` | 0.15 | HoneyEngine hit |
| `evolution_trigger` | 0.10 | Stage 5 near-miss → Evolution Engine queued |

```
score = Σ(weight_i × rate_i)   where rate_i = count_i / total_1h
```

Thresholds:

| Level | Score | Action |
|-------|-------|--------|
| `low` | < 0.35 | Pass |
| `medium` | 0.35–0.55 | Flag, monitor |
| `high` | 0.55–0.75 | Extra scrutiny |
| `critical` | ≥ 0.75 | **Shadow Ban** activated |

**Shadow Ban:** The entity receives `allowed=True` with a plausible fake response.  The real LLM backend is never called.  The attacker sees no signal that they have been detected.  This saves 100% of inference cost for that entity and denies adversarial feedback loops.

Minimum 5 requests required before ERS can elevate a score (`MIN_REQUESTS=5`), preventing false positives on first-time callers.

---

### Stage 8 — Decision & Event Logger

**File:** `warden/analytics/logger.py`

Final decision assembly and NDJSON append to `logs.json`.  Only metadata is persisted — **payload content is never logged** (GDPR Article 5(1)(c) data minimisation).

Logged fields per event: `ts`, `request_id`, `tenant_id`, `risk_level`, `allowed`, `flags`, `secrets_found` (types only), `payload_tokens`, `processing_ms` (per-stage breakdown), `attack_cost_usd`.

---

## Background Systems

### Evolution Engine

**File:** `warden/brain/evolve.py`

When a `HIGH` or `BLOCK` decision is reached, the payload hash is queued for async analysis by Claude Opus.  The model is prompted to synthesise a compact, generalisable rule from the attack pattern.  The new rule is vetted (dedup, growth cap at 500 rules, semantic poison-check) and hot-reloaded into the ML corpus via `add_examples()` — no restart required.

Corpus poisoning protections:
- Growth cap: max 500 auto-generated rules
- Dedup cap: max 10,000 examples in the similarity corpus
- Example vetting: Claude is instructed to produce defensive rules, not to echo attack content

### Zero-Trust Agent Sandbox

**Files:** `warden/agent_sandbox.py`, `warden/agent_monitor.py`, `warden/tool_guard.py`

Every agent registers an `AgentManifest` declaring its allowed `ToolCapability` list.  `SandboxRegistry.authorize_tool_call()` returns a `SandboxDecision` before any tool invocation.  Violations are logged, and the `AgentMonitor` maintains an attestation chain (SHA-256 rolling hash) over the session event stream.

Sessions can be revoked via `DELETE /agents/sessions/{id}`.  Post-session, an `EvidenceBundler` generates a cryptographically signed evidence bundle suitable for SOC 2 audit or litigation.

---

## Latency Budget

| Stage | Typical latency | Notes |
|-------|----------------|-------|
| Auth + rate-limit | < 1 ms | Constant-time key lookup |
| Cache hit | < 2 ms | Redis round-trip |
| Obfuscation decoder | < 1 ms | Pure Python regex |
| Secret redactor | 1–3 ms | 15 compiled regex patterns |
| Semantic Guard (rules) | 1–2 ms | Deterministic |
| Semantic Brain (ML) | 8–25 ms | MiniLM, CPU inference |
| Multimodal (image/audio) | 50–200 ms | Only on multimodal endpoints |
| ERS lookup | 1–3 ms | Redis pipeline |
| Logger | < 1 ms | Async NDJSON append |
| **Total (text, cache miss)** | **~15–35 ms** | p95 target |

Per-stage timings are returned in every `FilterResponse.processing_ms` dict for live observability.

---

## Configuration Reference

All tunable parameters are documented in `.env.example`.  Critical values:

| Env var | Default | Effect |
|---------|---------|--------|
| `SEMANTIC_THRESHOLD` | `0.72` | MiniLM cosine similarity cutoff |
| `RATE_LIMIT_PER_MINUTE` | `60` | Requests per IP per minute |
| `UNCERTAINTY_LOWER_THRESHOLD` | `0.55` | ERS medium-risk floor |
| `DYNAMIC_RULES_PATH` | `/warden/data/dynamic_rules.json` | Evolved rules corpus |
| `MODEL_CACHE_DIR` | `/warden/models` | MiniLM weights location |
| `REDIS_URL` | `redis://redis:6379` | Set `memory://` for tests |
| `ANTHROPIC_API_KEY` | *(empty = air-gapped mode)* | Disables Evolution Engine |
