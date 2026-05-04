# Filter Pipeline

The 9-layer filter pipeline processes every request in under 10ms (P99 < 50ms SLA).

---

## Layers

### Layer 1 — TopologicalGatekeeper

**File:** `warden/topology_guard.py`

Converts the text into an n-gram point cloud and computes Betti numbers
(β₀ = connected components, β₁ = loops) using persistent homology.
Jailbreak prompts tend to have anomalous topology — high β₁ relative to β₀.

- **Threshold:** configurable `TOPOLOGY_BETA1_MAX`
- **Speed:** < 2ms (pure numpy, no external deps)
- **Fallback:** if `ripser` unavailable, uses simplified distance matrix

### Layer 2 — ObfuscationDecoder

**File:** `warden/obfuscation.py`

Recursive depth-3 decoder for:
- Base64 padding permutations
- Hex (`\x41`, `%41`, `&#x41;`)
- ROT13 / Caesar cipher (all 25 shifts)
- Unicode homoglyphs (а→a, 0→o, etc.)
- Word-split obfuscation ("i g n o r e p r e v i o u s")
- UUencode

### Layer 3 — SecretRedactor

**File:** `warden/secret_redactor.py`

Strips 15 PII/secret regex patterns:
AWS keys · OpenAI keys · GitHub tokens · Stripe keys · credit cards ·
SSNs · email addresses · IP addresses · JWTs · private key headers ·
bearer tokens · phone numbers · and more.

Also runs a Shannon entropy scan — any token with entropy > 4.5 bits/char
and length > 20 is flagged as a potential unknown secret.

### Layer 4 — SemanticGuard (rules)

**File:** `warden/semantic_guard.py`

Rule-based semantic analyser with compound risk escalation:
3+ MEDIUM findings → escalate to HIGH. Maintains a dynamic ruleset that
the EvolutionEngine hot-reloads after each Claude Opus improvement cycle.

### Layer 5 — BrainSemanticGuard (ML)

**File:** `warden/brain/semantic.py`

MiniLM all-MiniLM-L6-v2 cosine similarity against a corpus of known
jailbreak examples. Blends with hyperbolic distance (Poincaré ball
projection) at 70% cosine + 30% hyperbolic.

- **Threshold:** `SEMANTIC_THRESHOLD` (default `0.72`)
- **Adversarial suffix stripping:** removes `[\n!#.]` suffixes before scoring
- **Model loading:** `@lru_cache(maxsize=1)` singleton, pre-warmed in `lifespan()`

### Layer 6 — CausalArbiter

**File:** `warden/causal_arbiter.py`

5-node Bayesian DAG using Pearl do-calculus with backdoor correction.
For gray-zone inputs, computes P(HIGH_RISK | evidence) from:
ERS score · ML score · obfuscation score · semantic rule score · SE risk.

CPT drift gate: rejects calibration updates that shift any parameter
> 25% from the prior (prevents slow-burn data poisoning).

### Layer 7 — ERS (Entity Risk Score)

**File:** `warden/main.py` (inline)

Redis sliding window per session. Shadow ban at score ≥ 0.75 with three
differentiated strategies:

| Strategy | Trigger | Behavior |
|----------|---------|----------|
| Gaslight | Prompt injection | Returns plausible-sounding fake response |
| Delay | Bot / credential stuffing | Progressive response delay (1–10s) |
| Standard | General abuse | Generic refusal |

`_pick_response()` uses `secrets.choice()` — not deterministic — to prevent fingerprinting.

---

## Processing Budget

| Layer | Budget | Notes |
|-------|--------|-------|
| Topology | 2ms | Pure numpy |
| Obfuscation | 1ms | Regex + lookup tables |
| Secrets | 1ms | Pre-compiled patterns |
| SemanticGuard | 0.5ms | Dict lookup + compound logic |
| BrainSemanticGuard | 3–5ms | MiniLM ONNX (CPU) |
| CausalArbiter | 0.5ms | Matrix multiply |
| ERS | 0.5ms | Redis GET/SET |
| **Total P99** | **< 50ms** | Per SLA |
