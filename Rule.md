# Shadow Warden AI — Rules Reference

> **Version 5.6 · Proprietary · All rights reserved**
> **Audience:** Security engineers, operators, and compliance reviewers.
> This document defines every detection rule enforced by the Warden gateway,
> how risk levels are assigned, and how rules can be extended or overridden.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Risk Level Taxonomy](#2-risk-level-taxonomy)
3. [Detection Architecture — 9-Stage Pipeline](#3-detection-architecture--9-stage-pipeline)
4. [Stage 1 — Topological Gatekeeper (TDA)](#4-stage-1--topological-gatekeeper-tda)
5. [Stage 2 — Obfuscation Decoder](#5-stage-2--obfuscation-decoder)
6. [Stage 3 — Secret & PII Redaction](#6-stage-3--secret--pii-redaction)
7. [Stage 4 — Semantic Rule Engine](#7-stage-4--semantic-rule-engine)
8. [Stage 5 — ML Jailbreak Detection (HyperbolicBrain)](#8-stage-5--ml-jailbreak-detection-hyperbolicbrain)
9. [Stage 6 — Causal Arbiter](#9-stage-6--causal-arbiter)
10. [Stage 7 — PhishGuard + SE-Arbiter](#10-stage-7--phishguard--se-arbiter)
11. [Stage 8 — Entity Risk Scoring (ERS) + Shadow Ban](#11-stage-8--entity-risk-scoring-ers--shadow-ban)
12. [Stage 9 — Decision](#12-stage-9--decision)
13. [SEP Transfer Guard](#13-sep-transfer-guard)
14. [Dynamic Rules (Evolution Loop)](#14-dynamic-rules-evolution-loop)
15. [Adding Custom Rules](#15-adding-custom-rules)
16. [Rule Governance](#16-rule-governance)
17. [File Scanner Rules (Community Business / SMB)](#17-file-scanner-rules-community-business--smb)
18. [Exemptions & Overrides](#18-exemptions--overrides)
19. [Obsidian Note Scanner Rules](#19-obsidian-note-scanner-rules)
20. [Secrets Governance Inventory Rules](#20-secrets-governance-inventory-rules)
21. [OTel Span Attribute Rules](#21-otel-span-attribute-rules)
22. [Public API Documentation Rules](#22-public-api-documentation-rules)
23. [SLO Burn-Rate Alerting Rules](#23-slo-burn-rate-alerting-rules)
24. [SMB AI Governance Rules](#24-smb-ai-governance-rules)
25. [Business Intelligence Module Rules](#25-business-intelligence-module-rules)
26. [GitHub Actions CI Scan Rules](#26-github-actions-ci-scan-rules-v53--in-15)
27. [ISO 27001:2022 Annex A Control Mapping Rules](#27-iso-270012022-annex-a-control-mapping-rules-v53--cp-22)
28. [Community Hub Rules](#28-community-hub-rules-v56--cm-53-cm-54)

---

## 1. Overview

Every payload through `POST /filter` is evaluated by a **9-stage sequential
pipeline**. Each stage can independently raise the risk level. The final
decision (`allowed` / `blocked`) is made after all stages run.

The pipeline never short-circuits on BLOCK — all stages record their verdict
for the XAI causal chain (`GET /xai/explain/{request_id}`).

---

## 2. Risk Level Taxonomy

| Level | Normal mode | Strict mode | Notes |
|-------|-------------|-------------|-------|
| `LOW` | ✅ Allowed | ✅ Allowed | Clean payload |
| `MEDIUM` | ✅ Allowed | ❌ Blocked | Suspicious but inconclusive |
| `HIGH` | ❌ Blocked | ❌ Blocked | Strong attack signal; Evolution Loop triggered |
| `BLOCK` | ❌ Blocked | ❌ Blocked | Zero-tolerance (CBRN, CSAM, self-harm) — hardcoded |

`BLOCK` cannot be overridden by the `strict` flag, API key, or any
runtime configuration. It is hardcoded and non-negotiable.

**Flag accumulation:** all fired flags are returned in `semantic_flags`.
Multiple flags can coexist. The highest risk level wins.

---

## 3. Detection Architecture — 9-Stage Pipeline

```
 Raw content
     │
     ▼
 ┌──────────────────────────────────────┐  Stage 1 · TDA
 │  TopologicalGatekeeper               │  n-gram point cloud → β₀/β₁ Betti numbers
 │  topology_guard.py                   │  < 2 ms; blocks bot payloads / DoS noise
 └────────────────────┬─────────────────┘
                      │ Passes topology check
                      ▼
 ┌──────────────────────────────────────┐  Stage 2 · Obfuscation
 │  ObfuscationDecoder                  │  base64 / hex / ROT13 / Caesar /
 │  obfuscation.py                      │  word-split / UUencode / homoglyphs
 └────────────────────┬─────────────────┘  depth-3 recursive decode
                      │ Decoded text
                      ▼
 ┌──────────────────────────────────────┐  Stage 3 · Secrets
 │  SecretRedactor                      │  15 regex patterns + Shannon entropy scan
 │  secret_redactor.py                  │  Replaces with [REDACTED:kind]
 └────────────────────┬─────────────────┘
                      │ Redacted text
                      ▼
 ┌──────────────────────────────────────┐  Stage 4 · Semantic Rules
 │  SemanticGuard                       │  10 rules (S-01 → S-10)
 │  semantic_guard.py                   │  3× MEDIUM → compound escalation to HIGH
 └────────────────────┬─────────────────┘
                      │ Risk: LOW → MEDIUM → HIGH → BLOCK
                      ▼
 ┌──────────────────────────────────────┐  Stage 5 · HyperbolicBrain
 │  BrainSemanticGuard                  │  MiniLM → Poincaré ball
 │  brain/semantic.py                   │  70% cosine + 30% hyperbolic distance
 └────────────────────┬─────────────────┘
                      │ ML score
                      ▼
 ┌──────────────────────────────────────┐  Stage 6 · CausalArbiter
 │  CausalArbiter                       │  Bayesian DAG, Pearl do-calculus
 │  causal_arbiter.py                   │  Gray-zone resolution in ~1–5 ms
 └────────────────────┬─────────────────┘
                      │ P(HIGH_RISK | evidence)
                      ▼
 ┌──────────────────────────────────────┐  Stage 7 · PhishGuard + SE-Arbiter
 │  PhishGuard + SocialEngineeringArbiter│  URL phishing + social engineering
 │  phishing_guard.py                   │  SEC-GAP-002 filter-bypass patterns
 └────────────────────┬─────────────────┘
                      │ phish_score, se_risk
                      ▼
 ┌──────────────────────────────────────┐  Stage 8 · ERS + Shadow Ban
 │  EntityRiskScorer                    │  Redis sliding window per tenant+IP
 │  shadow_ban.py                       │  Score ≥ 0.75 → shadow ban
 └────────────────────┬─────────────────┘  gaslight | delay | standard strategy
                      │
                      ▼
                  Stage 9 · Decision
          (highest risk level across all stages)
```

---

## 4. Stage 1 — Topological Gatekeeper (TDA)

**File:** `warden/topology_guard.py`

Converts the raw text to a character n-gram point cloud and computes Betti
numbers using persistent homology:

| Betti number | Geometric meaning | Attack signal |
|---|---|---|
| β₀ | Connected components | Fragmented / multi-part payloads |
| β₁ | 1-cycles (loops) | Repetitive loop / DoS patterns |

**Noise score formula:**
```
0.33×char_entropy + 0.27×wc_ratio + 0.22×diversity + 0.10×β₀ + 0.08×β₁
```

**Thresholds:**

| Content type | Threshold | Detection |
|---|---|---|
| Natural language | 0.82 | High-entropy / incoherent text |
| Code payloads | 0.65 | Tighter gate (code has lower natural entropy) |

Uses `ripser` for true persistent homology when installed; algebraic
fallback otherwise. Latency: < 2 ms on CPU.

---

## 5. Stage 2 — Obfuscation Decoder

**File:** `warden/obfuscation.py`

Recursively decodes obfuscated content **before** semantic analysis. Depth-3
recursion catches nested encodings (e.g. base64-encoded base64).

| Decoder | Technique detected |
|---|---|
| Base64 | Standard + URL-safe alphabet |
| Hex | `0x…` / bare hex strings |
| ROT13 | Character rotation |
| Caesar cipher | All 25 rotation offsets |
| Word-split injection | Space-separated characters |
| UUencode | `begin … end` blocks |
| Unicode homoglyphs | Cyrillic/Greek lookalikes mapped to ASCII |
| Zero-width characters | `U+200B`, `U+FEFF`, `U+00AD` stripping |

Risk contribution: `MEDIUM` when obfuscation detected; escalated to `HIGH`
when decoded content itself triggers a higher-level rule.

---

## 6. Stage 3 — Secret & PII Redaction

**File:** `warden/secret_redactor.py`

All 15 patterns run before semantic analysis. Matched values are replaced
with `[REDACTED:<kind>]` tokens — original values are never stored or logged
(GDPR Art. 5 data minimisation).

### Pattern catalog

| ID | Kind | Pattern description | Risk contribution | Strict-only |
|----|------|--------------------|--------------------|-------------|
| R-01 | `openai_api_key` | `sk-[A-Za-z0-9]{48}` | MEDIUM | No |
| R-02 | `anthropic_api_key` | `sk-ant-api03-[A-Za-z0-9\-_]{93}` | MEDIUM | No |
| R-03 | `huggingface_token` | `hf_[A-Za-z0-9]{34}` | MEDIUM | No |
| R-04 | `aws_access_key` | `AKIA[0-9A-Z]{16}` | HIGH | No |
| R-05 | `github_token` | `ghp_[A-Za-z0-9]{36}` | MEDIUM | No |
| R-06 | `stripe_key` | `sk_live_[A-Za-z0-9]{24}` | HIGH | No |
| R-07 | `gcp_api_key` | `AIza[0-9A-Za-z\-_]{35}` | MEDIUM | No |
| R-08 | `bearer_token` | `Bearer [A-Za-z0-9\-._~+/]+=*` | MEDIUM | No |
| R-09 | `pem_private_key` | `-----BEGIN … PRIVATE KEY-----` | HIGH | No |
| R-10 | `url_credentials` | `https?://[^:]+:[^@]+@` | MEDIUM | No |
| R-11 | `credit_card` | Luhn-validated 13–19-digit sequences | MEDIUM | No |
| R-12 | `us_ssn` | `\d{3}-\d{2}-\d{4}` | MEDIUM | No |
| R-13 | `iban` | `[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}` | MEDIUM | No |
| R-14 | `email` | RFC-5321 local + domain | LOW | No |
| R-15 | `ipv4_private` | RFC-1918 private IP ranges | LOW | **Yes** |

Shannon entropy scan flags unknown high-entropy tokens (≥ 4.5 bits/char,
32+ chars) that don't match any pattern above.

---

## 7. Stage 4 — Semantic Rule Engine

**File:** `warden/semantic_guard.py`

Rule-based analysis of the **redacted + decoded** text. Compound risk
escalation: 3 or more MEDIUM flags in a single request → escalated to HIGH.

### Rule catalog

| ID | Flag | Risk | Notes |
|----|------|------|-------|
| S-01 | `prompt_injection` | MEDIUM | "ignore previous", "disregard all instructions", DAN variants |
| S-02 | `harmful_content` | HIGH | Violence, abuse — non-CBRN |
| S-03 | `weapon_synthesis` | **BLOCK** | Chemical / biological / radiological / nuclear |
| S-04 | `self_harm` | **BLOCK** | Detailed methods only; general statements not flagged |
| S-05 | `csam` | **BLOCK** | Any content involving minors + sexual content; score locked 1.0 |
| S-06 | `exfiltration_probing` | HIGH | System-prompt extraction, training-data exfil |
| S-07 | `obfuscation` | MEDIUM | Residual obfuscation after Stage 2 (nested / partial) |
| S-08 | `policy_violation` | MEDIUM | Explicit requests to violate AI guidelines |
| S-09 | `explicit_content` | MEDIUM | Adult content (→ BLOCK if minors implied) |
| S-10 | `pii_detected` | MEDIUM | PII combos not caught by Stage 3 |

Rules S-03, S-04, S-05 are **hardcoded BLOCK** and cannot be lowered by
any configuration.

---

## 8. Stage 5 — ML Jailbreak Detection (HyperbolicBrain)

**Files:** `warden/brain/semantic.py`, `warden/brain/hyperbolic.py`

`sentence-transformers/all-MiniLM-L6-v2` (80 MB, CPU-only) encodes the
input, then computes a **blended similarity score**:

```
score = 0.70 × cosine_similarity + 0.30 × hyperbolic_distance
```

Embeddings are projected into the **Poincaré ball** (curvature c=1) before
the hyperbolic component is computed. Hyperbolic geometry separates
hierarchically-nested multi-layer attacks that appear close in Euclidean
cosine space but diverge near the ball boundary.

**Adversarial suffix stripping** removes known gradient-based adversarial
suffixes before encoding.

| Parameter | Default | Effect |
|-----------|---------|--------|
| `SEMANTIC_THRESHOLD` | `0.72` | Score ≥ threshold → HIGH risk |

**Built-in corpus:** 28 seed examples across 7 categories:
role override, persona injection, roleplay framing, system-prompt extraction,
obfuscated injection, harmful intent, self-harm semantic variants.

Extensible via Evolution Loop (Stage 6 output) — hot-reload without restart.

---

## 9. Stage 6 — Causal Arbiter

**File:** `warden/causal_arbiter.py`

Resolves gray-zone requests (ML score in uncertainty band) using a
lightweight Bayesian DAG with Pearl do-calculus backdoor-path correction.

**Causal nodes:**

| Node | Variable | Source |
|------|----------|--------|
| `ml_score` | P(jailbreak) from Stage 5 | `HyperbolicBrain.score` |
| `ers_score` | Entity reputation (0–1) | Redis sliding window |
| `obfuscation_detected` | Bool from Stage 2 | `ObfuscationDecoder` |
| `block_history` | Prior blocks this session | `AgentMonitor` |
| `tool_tier` | Agent capability level | `FilterRequest.tool_tier` |
| `content_entropy` | Shannon entropy of content | Stage 3 scan |
| `se_risk` | Social engineering risk | Stage 7 SE-Arbiter |

Output: `CausalResult.risk_probability` → if ≥ `CAUSAL_THRESHOLD` (default
0.65), risk is raised to HIGH.

Runs in ~1–5 ms CPU. Zero LLM calls.

---

## 10. Stage 7 — PhishGuard + SE-Arbiter

**File:** `warden/phishing_guard.py`

Two independent detectors run in parallel:

**PhishGuard** — URL phishing detection:
- Extracts all URLs from content
- Checks against known-bad domain patterns + homoglyph lookalikes
- Heuristics: excessive subdomains, IDN homoglyphs, URL shorteners

**SE-Arbiter** — Social engineering (SEC-GAP-002):

| Pattern group | Examples | Weight |
|---|---|---|
| AI filter bypass | "disable safety filters", "bypass restrictions" | 0.70 |
| Privileged mode override | "developer mode", "jailbreak mode" | 0.70 |
| AI creator impersonation | "I am your Anthropic", "I am OpenAI" | 0.70 |
| Unrestricted mode request | "no restrictions", "DAN mode" | 0.70 |

A single match pushes `se_risk ≥ 0.75` → HIGH. Score feeds Stage 6
CausalArbiter as `se_risk` node.

---

## 11. Stage 8 — Entity Risk Scoring (ERS) + Shadow Ban

**File:** `warden/shadow_ban.py`

Redis sliding-window reputation per `(tenant_id, client_ip)`.

**Score formula:**
```
ers_score = Σ(event_weight × event_count_in_window)
            ─────────────────────────────────────────
                         normalization_factor
```

| Event type | Weight |
|---|---|
| Block | 0.40 |
| Obfuscation detected | 0.25 |
| Honeytrap triggered | 0.20 |
| Evolution rule matched | 0.15 |

**Shadow ban threshold:** `ers_score ≥ 0.75`

**Shadow ban strategies:**

| Strategy | Trigger | Behaviour |
|---|---|---|
| `gaslight` | Prompt injection attack | Returns subtly wrong plausible output — breaks attacker feedback loop |
| `delay` | Credential stuffing / bot | Real async delay to slow automated tools |
| `standard` | Default | `allowed=true`, fake response, real LLM not called |

Shadow ban preserves 100% LLM inference cost — the attacker's next call
returns fabricated data while incurring no compute cost.

---

## 12. Stage 9 — Decision

The final `allowed` / `blocked` verdict is the **highest risk level** across
all 8 prior stages.

```
risk = max(stage_1_risk, stage_2_risk, …, stage_8_risk)
allowed = risk not in {HIGH, BLOCK}   # or MEDIUM if STRICT_MODE=true
```

**XAI chain:** all 9 stage verdicts (including the decision node) are
serialised into a `CausalChain` and stored for retrieval at
`GET /xai/explain/{request_id}`.

**Evolution trigger:** if `risk in {HIGH, BLOCK}` and `ANTHROPIC_API_KEY`
is set, `EvolutionEngine.add_examples()` is called asynchronously.

---

## 13. SEP Transfer Guard

**File:** `warden/communities/transfer_guard.py`

Applies **before** every `transfer_entity()` in the SEP pipeline.
Not part of the `/filter` path — runs only on inter-community document
transfers.

**Evidence mapping:**

| SEP context | CausalArbiter node | Mapping |
|---|---|---|
| `data_class` | `ml_score` | CLASSIFIED=0.90, PHI=0.80, FINANCIAL=0.65, PII=0.55, GENERAL=0.20 |
| Hourly velocity | `ers_score` | count/100, capped at 1.0 |
| Peering policy + age | `obfuscation_detected` | FULL_SYNC + age<7d = True |
| Prior rejections | `block_history` | count/10, capped at 1.0 |
| Policy tier enum | `tool_tier` | MIRROR_ONLY=0, REWRAP_ALLOWED=1, FULL_SYNC=2 |
| Data class entropy | `content_entropy` | 0.0–1.0 mapped from data class risk |
| 5-min burst | `se_risk` | burst_count/20, capped at 1.0 |

**Block threshold:** `TRANSFER_RISK_THRESHOLD` env var (default **0.70**).

Blocked transfers receive status `REJECTED` (not raised as exception) — the
`TransferRecord` is still written to DB and appended to the STIX audit chain.

---

## 14. Dynamic Rules (Evolution Loop)

**File:** `warden/brain/evolve.py`  
**Output:** `data/dynamic_rules.json`

When a `HIGH` or `BLOCK` request is blocked, `EvolutionEngine` sends a
structured summary (never raw content) to Claude Opus for analysis. The
engine generates a new rule and hot-reloads it — no restart required.

**Rule schema:**
```json
{
  "id": "uuid-v4",
  "created_at": "ISO-8601",
  "source_hash": "sha256-of-original-content",
  "attack_type": "prompt_injection",
  "explanation": "Attacker attempted…",
  "evasion_variants": ["variant 1", "variant 2"],
  "new_rule": {
    "rule_type": "semantic_example | regex_pattern",
    "value": "new corpus sentence or regex",
    "description": "Catches role-override via…"
  },
  "severity": "HIGH",
  "times_triggered": 0
}
```

| `rule_type` | Hot-reload target |
|---|---|
| `semantic_example` | `BrainSemanticGuard.add_examples()` |
| `regex_pattern` | `SemanticGuard._custom_checks()` |

Dynamic rules are deduplicated by SHA-256 of original blocked content.
`seen_hashes` is persisted to `dynamic_rules.json` — dedup survives restarts.

**Intel Bridge:** `INTEL_OPS_ENABLED=true` activates ArXiv paper ingestion →
`synthesize_from_intel()` → auto-evolution from published LLM attack research.

---

## 15. Adding Custom Rules

```python
from warden.semantic_guard import SemanticGuard

class MyGuard(SemanticGuard):
    def _custom_checks(self, text: str) -> list[SemanticFlag]:
        flags = []
        if "my_pattern" in text.lower():
            flags.append(SemanticFlag(
                flag=FlagType.POLICY_VIOLATION,
                risk=RiskLevel.MEDIUM,
                matched_rule="my_pattern",
            ))
        return flags
```

Custom `_custom_checks()` **cannot** override the risk level of any
hardcoded BLOCK rule (S-03, S-04, S-05).

---

## 16. Rule Governance

| Control | Mechanism |
|---|---|
| Rule creation | EvolutionEngine (automatic) or `add_examples()` API |
| Rule review | `data/dynamic_rules.json` — human-readable JSON ledger |
| Rule deletion | Remove entry from JSON; hot-reload via `SIGHUP` or restart |
| Audit trail | Every blocked request → Evidence Vault (MinIO + SHA-256 signed bundle) |
| SOC 2 CC6.8 | All rule changes logged with `source_hash` + timestamp |

---

## 17. File Scanner Rules (Community Business / SMB)

**File:** `warden/api/file_scan.py`  
**Endpoint:** `POST /filter/file` — multipart upload, max 10 MB

The file scanner runs a subset of the main pipeline optimised for offline file
triage before a file is uploaded to an external AI tool. It does **not** run
the full 9-stage pipeline; instead it applies Stages 3, 4, and injection
detection only.

### Risk Aggregation

| Condition | Risk Level |
|---|---|
| Prompt-injection patterns detected (SemanticGuard HIGH/BLOCK) | **CRITICAL** |
| 3+ secret findings *or* 10+ total findings | **HIGH** |
| 1+ secret finding *or* 4+ total findings | **MEDIUM** |
| PII only (email, SSN, IBAN, credit card) | **LOW** |
| No findings | **SAFE** |

### Finding Kinds

| Kind | Source | Examples |
|---|---|---|
| `secret` | SecretRedactor patterns R-01–R-15 | API keys, PEM certs, bearer tokens |
| `pii` | SecretRedactor patterns (email/ssn/iban/credit_card) | Emails, SSNs, IBANs |
| `prompt_injection` | SemanticGuard | DAN, role-override, CBRN patterns |
| `high_entropy` | Shannon entropy scan (≥4.5 bits/char, 32+ chars) | Unknown secrets |

### File Format Support

| Group | Extensions / MIME types |
|---|---|
| Text | `.txt`, `.md`, `.csv`, `.html`, `.xml`, `text/*` |
| Code | `.py`, `.js`, `.ts`, `application/javascript` |
| Data | `.json`, `application/json` |
| PDF | `.pdf`, `application/pdf` (pdfminer → pypdf → raw fallback) |

**Maximum file size:** 10 MB (`FILE_SCAN_MAX_MB` env var).  
**Safe for SMBs:** file content is **never logged or stored**. Only metadata
(filename, size, risk level, finding count, timing) is returned.

---

## 18. Exemptions & Overrides

| Override | Mechanism | Limits |
|---|---|---|
| Strict mode off | `STRICT_MODE=false` (env) or `strict: false` (per-request) | BLOCK-level rules always enforced |
| Per-tenant threshold | `SEMANTIC_THRESHOLD` env var | Cannot lower below 0.50 |
| Causal Arbiter | `CAUSAL_THRESHOLD` env var | Default 0.65; range 0.50–0.95 |
| Transfer risk | `TRANSFER_RISK_THRESHOLD` env var | Default 0.70; range 0.50–0.95 |
| Shadow ban | ERS score reset via `DELETE /admin/ers/{entity_id}` | Requires admin API key |

---

## 19. Obsidian Note Scanner Rules

**File:** `warden/integrations/obsidian/note_scanner.py`  
**Endpoint:** `POST /obsidian/scan`

The Obsidian note scanner runs a classification pipeline on the vault note
content **before** it can be shared to a Business Community via SEP.

### Data Classification Rules

| Priority | Source | Inference |
|---|---|---|
| 1 (highest) | YAML frontmatter `data_class` field | Explicit override — always wins |
| 2 | YAML frontmatter `tags` list | `[phi, medical, health]` → PHI; `[classified, secret]` → CLASSIFIED |
| 3 | Keyword scan (note body) | Medical/financial/legal keyword sets |
| 4 (fallback) | None of the above | `GENERAL` |

### Data Class Definitions

| Class | Keywords / Tags | Share restriction |
|---|---|---|
| `CLASSIFIED` | `classified`, `secret`, `top-secret` | Blocked from all cross-border SEP transfers |
| `PHI` | `patient`, `diagnosis`, `medical`, `health`, `dob` | EU/US/UK/CA/CH only |
| `FINANCIAL` | `invoice`, `payment`, `bank`, `account`, `iban` | All jurisdictions with adequacy check |
| `PII` | `email`, `address`, `phone`, `ssn`, `passport` | All jurisdictions with adequacy check |
| `GENERAL` | Default | No transfer restrictions |

### Share Gate Rules

| Condition | Action |
|---|---|
| `secrets_found > 0` | HTTP 422 — BLOCKED. UECIID never issued. |
| `data_class == CLASSIFIED` | HTTP 422 — BLOCKED. Cannot be shared via SEP. |
| `data_class == PHI` and target jurisdiction not in `[EU, US, UK, CA, CH]` | Causal Transfer Guard rejects |
| All checks pass | UECIID issued via `sep.register_ueciid()` |

### AI Filter Pre-Share (`POST /obsidian/ai-filter`)

Content is passed through `SecretRedactor` → `SemanticGuard` before any LLM
call. A HIGH or BLOCK verdict cancels the AI enrichment and returns the verdict
to the plugin.

---

## 20. Secrets Governance Inventory Rules

**Files:** `warden/secrets_gov/inventory.py`, `warden/secrets_gov/policy.py`,
`warden/secrets_gov/lifecycle.py`

### Risk Scoring

Inventory entries receive a composite risk score (0–100):

| Factor | Weight | Calculation |
|---|---|---|
| Rotation age | 40% | `min(rotation_age_days / max_age_days, 1.0) × 40` |
| Exposure level | 30% | INTERNAL=0.2 / EXTERNAL=0.6 / PUBLIC=1.0 → ×30 |
| Compliance violations | 20% | `min(violation_count / 5, 1.0) × 20` |
| Access frequency | 10% | Low=0 / Medium=5 / High=10 |

**Risk tiers:** 0–25 LOW · 26–50 MEDIUM · 51–75 HIGH · 76–100 CRITICAL

### Policy Violation Rules

| ID | Rule | Default |
|---|---|---|
| V-01 | `max_age_days` exceeded | 90 days |
| V-02 | `min_rotation_frequency` not met | 2 rotations / year |
| V-03 | Vault with no last-sync in >7 days | Required for managed vaults |
| V-04 | Secret with `exposure == PUBLIC` and no rotation in >30 days | Immediate HIGH |
| V-05 | Inventory entry with `status == ACTIVE` and `expires_at` < now | Auto-retire |
| V-06 | More than `max_secrets_per_vault` entries | 500 (configurable) |
| V-07 | No MFA on vault connector | Required for FINANCIAL/PHI classes |

### Compliance Score

```
score = 100 - (Σ violation_weight_i for all active violations)
```

Score < 60 → blocks new vault registrations (configurable via `min_compliance_score`).

---

---

## 21. OTel Span Attribute Rules

**Files:** `warden/telemetry.py`, all 9 pipeline stages

Every pipeline stage emits an OpenTelemetry span via `trace_stage()`. Span
attribute naming is governed by these rules to ensure GDPR compliance and
consistent Jaeger query patterns.

### Allowed Span Attributes

| Attribute | Type | Stage | Notes |
|-----------|------|-------|-------|
| `warden.stage` | string | All | Stage name (e.g. `topology`, `brain`) |
| `warden.risk_level` | string | All | LOW/MEDIUM/HIGH/BLOCK |
| `warden.allowed` | bool | Decision | Final verdict |
| `warden.latency_ms` | float | All | Stage latency |
| `warden.tenant_id` | string | All | Hashed — never plaintext |
| `warden.secrets_found` | int | Redactor | Count only |
| `warden.obfuscation_detected` | bool | Obfuscation | — |
| `warden.flags` | string | Semantic | Comma-separated flag names |
| `warden.ml_score` | float | Brain | 0.0–1.0 |
| `warden.causal_prob` | float | Causal | 0.0–1.0 |
| `warden.ers_score` | float | ERS | 0.0–1.0 |

### Prohibited Span Attributes

The following **must never** be set on any span — GDPR Art. 5(1)(c):

- Raw or decoded content (`text`, `content`, `body`, `decoded`)
- Secret values or patterns (`secret_value`, `matched_pattern`)
- PII or any user-identifiable token

Violation is caught by the GDPR no-content-log pre-commit hook (Hook §6).

---

*Rule.md — Shadow Warden AI detection rules reference v4.20 · 2026-05-16*

---

## 21. Vibe Coding Cowork — Claude Instructions

> **Audience:** Claude AI assistant across all coding sessions for this project.
> Internalize these preferences, patterns, and communication styles.

---

### 21.1 Preferred Approaches & Methods

- **Iterative refinement** — Build minimal viable versions first, then enhance based on feedback. Favour working prototypes over perfect upfront designs.
- **Conversational exploration** — Discuss trade-offs, options, and "what-ifs" before committing to code. Treat every coding decision as a conversation.
- **Incremental test-first thinking** — When generating new logic, always frame it around a quick test or a sanity check (even if just a mental run-through).
- **Explain-by-doing** — Accompany code with a concise rationale, but let the code speak first. After showing a snippet, add a short "why" or "trade-offs" note.
- **Refactor courageously** — Suggest renaming, restructuring, or simplifying when it adds clarity or reduces complexity, but always respect the current vibe (don't over-engineer without asking).
- **Debugging with curiosity** — When investigating errors, form and test hypotheses out loud before changing anything. Use logging/print statements liberally to understand state.
- **Tool-aware** — Assume a modern web stack (Node, React, Next.js, Tailwind, etc.) unless told otherwise. Prefer ES modules, async/await, and functional patterns.

---

### 21.2 Common Terms & Concepts

| Term | Meaning |
|------|---------|
| **Vibe coding** | Exploratory, flow-state programming where code emerges from conversation, rapid iteration, and creative experimentation |
| **Skeleton** | A minimal, running scaffold with placeholder parts (e.g. "create a page skeleton with a header, main, footer") |
| **Happy path first** | Implement the core logic without edge cases initially; harden it later |
| **Legibility over cleverness** | Write code that is instantly understandable, even if it's a few lines longer |
| **Signals** | Observable indicators of internal state or side effects (console logs, UI feedback) |
| **Scaffold and fill** | First define the structure (routes, components, data flow), then implement the internals |
| **Duck-tape prototype** | A quick-and-dirty working version using the simplest possible connections (often mocked data or in-memory stores) to validate an idea |

---

### 21.3 Typical Scenarios

- Starting a new feature from a vague idea or a user story.
- Refactoring a messy component or function into something cleaner.
- Debugging a runtime error that only appears under certain conditions.
- Exploring architectural choices (state management, routing, data fetching).
- Writing or updating tests after the fact.
- Setting up or modifying CI/CD, environment variables, or build configs.
- Teaching or rubber-ducking through a problem — needing Claude to ask clarifying questions rather than just producing code.
- "What-if" experiments: *"What if we switched from Context to Zustand?"* — prototype the change quickly.

---

### 21.4 General Communication Instructions

- **Default tone:** Collaborative, casual but focused. Conversational without unnecessary fluff.
- **Clarity over brevity:** Prefer short, digestible messages. If a reply would be long, break it into sections with descriptive headings.
- **Ask before assuming:** When in doubt about preferences (library, pattern, structure), present two options briefly and ask which direction to take.
- **Signal confidence:** End a code suggestion with a phrase like *"This should work as is,"* *"This is untested but looks correct,"* or *"This needs X before it will run."*
- **Embrace the vibe:** Match the user's energy — if playful and experimental, be playful back. If laser-focused and terse, be efficient.
- **Always surface hidden assumptions:** If a snippet relies on a specific file structure, environment variable, or package, mention it explicitly.

---

### 21.5 Project Workflow Guidelines

- **Branching:** Always assume work is on a feature branch; never suggest editing `main` directly.
- **File creation:** When proposing a new file, mention its full path and suggest where it fits in the existing directory tree.
- **Code generation style:** Prefer complete, copy-paste-able files or diffs. For small changes, show only the relevant snippet with surrounding context (a few lines before and after).
- **Commit rhythm:** Suggest commits after logical, self-contained steps. Use conventional commit messages (e.g. `feat: add transaction list skeleton`).

---

### 21.6 Communication Modes

Switch between these modes on request. Default to **collaborative vibe** when no mode is specified.

| Mode | Trigger | Behaviour |
|------|---------|-----------|
| **Concise / "Just the Diff"** | *"concise"*, *"quick diff"*, *"just the code"* | Shortest possible answer. No explanations unless asked. Inline comments only if critical. |
| **Explanatory / "Teach Me"** | *"explain"*, *"walk me through"*, *"why?"* | High-level concept → key decisions → code with line-by-line narration. Use analogies if helpful. |
| **Rubber Duck / Socratic** | *"rubber duck"*, *"help me think"*, *"ask me questions"* | No code immediately. Ask 1–2 open-ended questions to clarify the problem. Code only when the path is clear. |
| **"My Voice"** | *"write like me"*, *"in my style"* | Short punchy sentences. Direct and opinionated. Use "we" for collaborative steps. Pragmatic real-world examples. *e.g. "Let's drop a skeleton first. Then we'll wire up the data. Sound good?"* |

---

### 21.7 Role & Persona

- Senior full-stack engineer who values clean architecture but ships fast.
- Proactively flag edge cases but don't let them block progress.
- Suggest simpler alternatives when complexity creeps in.
- When stuck, propose a lightweight spike or experiment.
- Act as a thinking partner: challenge assumptions respectfully.

---

## 22. Public API Endpoint Rules

| # | Rule |
|---|------|
| P-01 | **`GET /openapi-public.json` is always public.** No `DOCS_PASSWORD` auth, no `X-API-Key` required. Never add auth dependencies to this endpoint. |
| P-02 | **CORS for docs domain.** `https://docs.shadow-warden-ai.com` must remain in `_DEFAULT_CORS`. Removing it silently breaks the Redoc site. |
| P-03 | **Schema must not leak internal routes.** `openapi-public.json` returns the same schema as `openapi.json`. Sensitive internal routes (admin, debug) are excluded via `include_in_schema=False` on their route decorators. |
| P-04 | **Redoc CDN pin.** `docs/redoc.html` loads Redoc from `cdn.jsdelivr.net/npm/redoc@latest`. Pin to a specific semver (`@2.x.x`) before GA launch to avoid breaking changes. |

---

## 23. SLO Burn-Rate Alerting Rules

| # | Rule |
|---|------|
| SLO-01 | **Multi-window AND gate required.** Burn-rate alerts must require both long-window AND short-window to exceed threshold. Single-window burn alerts generate excessive false positives during brief spikes. |
| SLO-02 | **Fast burn threshold: 14.4×.** For a 99.9% SLO, firing at 14.4× budget consumption rate means 2% of the monthly budget is consumed in 1 hour — page immediately. |
| SLO-03 | **Slow burn threshold: 6×.** At 6× budget consumption, 5% of the monthly budget burns per 6h — create a ticket for next-business-day investigation. |
| SLO-04 | **Labels required.** Every burn-rate alert must carry `category: slo_burn` + `window: fast|slow` labels so dashboards and PagerDuty routing can distinguish from threshold-based alerts. |
| SLO-05 | **`noDataState: OK` for slow burn.** When Prometheus has no data (service is down), the slow-burn alert must not fire. The availability alert (rule uid `warden-availability`) covers the outage. |

---

## 24. SMB AI Governance Rules

**Files:** `warden/vendor_gov/`, `warden/financial/`, `warden/communities/incident_register.py`,
`warden/communities/supplier_risk.py`, `warden/communities/prompt_library.py`,
`warden/communities/training_records.py`, `warden/integrations/smb_suite.py`

### Vendor Governance (BL-22)

| # | Rule |
|---|------|
| VG-01 | DPA expiry alerts fire at `within_days=30`. Expired DPAs reduce vendor compliance score. |
| VG-02 | Vendor `risk_tier` (LOW/MEDIUM/HIGH/CRITICAL) is set at registration. Only explicit update changes it — no auto-promotion. |
| VG-03 | Terminated vendors (`status=terminated`) are excluded from stats but retained for audit. |

### Cost Allocation (BL-23)

| # | Rule |
|---|------|
| CA-01 | `period_month` format is `YYYY-MM`. Summaries aggregate by exact period match. |
| CA-02 | `import_from_logs()` is idempotent — duplicate `request_id`-tagged entries are skipped. |

### Budget Dashboard (BL-24)

| # | Rule |
|---|------|
| BD-01 | Alert fires when `current_spend / cap_usd ≥ alert_pct` (default 0.80). Status levels: `ok` / `warning` / `over`. |
| BD-02 | Budget approvals: `pending → approved/rejected` only. Resolved approvals cannot be re-opened. |

### Incident Register (CM-35)

| # | Rule |
|---|------|
| IR-01 | Every `log_incident()` call appends to the STIX audit chain and stores `stix_chain_id` on the record. |
| IR-02 | `auto_log_from_filter_event()` only creates an incident when `decision == BLOCK` or `risk_level == HIGH`. |
| IR-03 | Severity mapping from filter: BLOCK → CRITICAL, HIGH → HIGH, MEDIUM → MEDIUM. |
| IR-04 | Status transitions: `open → investigating → resolved → closed`. Closed incidents cannot transition back. |

### Supplier Risk Assessment (CM-36)

| # | Rule |
|---|------|
| SR-01 | Composite score = weighted average of 5 sub-scores: `data_access (0.3) + ai_capability (0.2) + compliance_posture (0.2) + peering_history (0.2) + disclosure_recency (0.1)`. |
| SR-02 | Risk labels: 0.0–0.25 LOW · 0.26–0.50 MEDIUM · 0.51–0.75 HIGH · 0.76–1.0 CRITICAL. |
| SR-03 | `peering_history` sub-score derived from `sep_transfers` rejection rate over last 90 days. |

### Prompt Library (CM-37)

| # | Rule |
|---|------|
| PL-01 | `add_prompt()` runs `POST /filter` on prompt text before saving. HIGH/BLOCK verdict → HTTP 422, prompt not stored. |
| PL-02 | Every prompt receives a UECIID via `sep.new_ueciid()` at creation. |
| PL-03 | `share_to_peer()` uses the Causal Transfer Guard. PHI-classified prompts cannot cross jurisdictions. |

### Training Records (CM-38)

| # | Rule |
|---|------|
| TR-01 | `record_completion()` signs the record with `HMAC-SHA256(VAULT_MASTER_KEY, canonical_json)`. Unsigned completions are treated as invalid. |
| TR-02 | `expires_at = completed_at + valid_days`. Expired completions contribute to `overdue` count in `get_compliance_report()`. |
| TR-03 | `behavioral.record_event(community_id, "ai_training_completed", value=score)` is called on every completion for anomaly tracking. |

---

## 25. Business Intelligence Module Rules

**Files:** `warden/business_intelligence/service.py`, `warden/business_intelligence/repository.py`,
`warden/business_intelligence/predictive.py`, `warden/business_intelligence/benchmarking.py`

### Cache Rules

| # | Rule |
|---|------|
| BI-01 | All BI report functions cache via `repository.cache_set()` with 15-minute TTL. Cache key = `{function_name}:{tenant_id}:{params_hash}`. |
| BI-02 | `cache_get()` returns `None` on miss — caller must regenerate. No stale-while-revalidate. |
| BI-03 | `DELETE /business-intelligence/cache` invalidates all entries for a tenant. Purge applies to `expires_at < now()`. |

### Analytics Rules

| # | Rule |
|---|------|
| BI-04 | `get_usage_summary()` reads `LOGS_PATH` (`logs.json`). Returns `total_requests=0` when file is missing. |
| BI-05 | `get_threat_summary()` reads `ai_incidents` table in `SEP_DB_PATH`. Returns `total_threats=0` when table is empty. |
| BI-06 | `get_compliance_score()` weights: training compliance 30%, DPA coverage 30%, incident closure rate 20%, budget adherence 20%. Grade scale: ≥0.90→A, ≥0.80→B, ≥0.70→C, ≥0.60→D, else F. |
| BI-07 | `get_benchmarks()` uses a Gaussian synthetic peer distribution (μ = tenant_metric, σ = 0.1) when no real peer data exists — clearly labelled `"synthetic": true` in the response. |
| BI-08 | `get_incident_prediction()` uses a 90-day history window. OLS extrapolation via `predictive.linear_trend()`. Confidence = R² of the smoothed series. |

### Predictive Analytics Rules

| # | Rule |
|---|------|
| BI-09 | `trend_direction()` thresholds: slope > 0.1 → "rising", slope < -0.1 → "falling", else "stable". |
| BI-10 | `predict_next()` clamps all predictions to `max(0.0, value)`. Negative incident counts are impossible. |
| BI-11 | `r_squared()` returns 1.0 when `ss_tot == 0` (all values identical — perfect flat trend). |

### Report Builder Rules

| # | Rule |
|---|------|
| BI-12 | `build_report()` report types: `full` (all 6 sections), `executive` (usage + compliance + threats), `compliance` (compliance + vendors + training), `vendor` (vendors + costs), `cost` (costs + budget). |
| BI-13 | `include_sections` parameter overrides `report_type` section list when provided. |
| BI-14 | BI module is read-only across all peer module databases. It must never write to `SEP_DB_PATH`, `VENDOR_GOV_DB_PATH`, or `COST_ALLOC_DB_PATH`. |

---

## 20. Semantic Layer Rules (v5.1)

### SQL Safety Rules

| # | Rule |
|---|------|
| SL-01 | All identifiers (table, column, alias) must match `^[A-Za-z_][A-Za-z0-9_.]*$`. Anything else raises `ValueError`. |
| SL-02 | All filter values use `%s` positional placeholders — never string interpolation. |
| SL-03 | Operator whitelist: `=`, `!=`, `>`, `<`, `>=`, `<=`, `LIKE`, `IN`. Unsupported operators raise `ValueError`. |
| SL-04 | `SemanticEngine.generate()` is deterministic: identical `QueryObject` inputs always produce identical SQL. |
| SL-05 | Row limit range: 1 ≤ limit ≤ 10,000. |

### Access Control Rules

| # | Rule |
|---|------|
| SL-06 | `AccessRule.tenant_id = None` → global rule (applies to all tenants). |
| SL-07 | If any `AccessRule` exists for a model, all metrics/dimensions must pass the allow-list. Empty allow-list = open. |
| SL-08 | Access check runs before SQL generation. `PermissionError` → HTTP 403. |

### AI Query Rules

| # | Rule |
|---|------|
| SL-09 | AI Query endpoint (`/semantic-layer/query/intent`) requires Pro+ gate via `master_agent_enabled` feature. |
| SL-10 | If `ANTHROPIC_API_KEY` is not set, AI Query returns HTTP 503 (not 403). |
| SL-11 | LLM model used for intent translation: `claude-haiku-4-5-20251001` only. Never Opus or Sonnet for this path. |
| SL-12 | If LLM returns unparseable JSON, HTTP 500 is returned with the raw response truncated to 200 chars. |

---

## 21. Settings Hub Rules (v5.1)

### Storage Rules

| # | Rule |
|---|------|
| ST-01 | All settings keys follow the pattern `settings:{tenant_id}:{section}` in Redis. |
| ST-02 | When Redis is unavailable, the `_mem` in-process dict is used. Data is lost on process restart — this is intentional (ephemeral fallback). |
| ST-03 | Agent config TTL: no TTL (persistent). All settings keys have no expiry. |
| ST-04 | Secret values in `settings:{tid}:secrets` are not encrypted by the Settings Hub itself — use Secrets Governance (`warden/secrets_gov/`) for Fernet-encrypted at-rest storage. |

### Commerce Rules

| # | Rule |
|---|------|
| ST-05 | `per_transaction_limit_usd` ≥ 0. A value of 0 means no limit is applied by the Settings Hub (upstream AP2 may still enforce limits). |
| ST-06 | `require_approval_above_usd`: any purchase above this threshold must pass MCP human-in-the-loop approval before execution. |
| ST-07 | `approved_stores` list: empty list means all stores are permitted. Non-empty list is an allow-list. |
| ST-08 | `audit_all_transactions = true` by default. When true, every commerce action is appended to the STIX audit chain. |

### Notification Rules

| # | Rule |
|---|------|
| ST-09 | Channel kinds: `slack`, `teams`, `email`, `webhook`. Pattern validated by Pydantic. |
| ST-10 | Slack test sends `{"text": "..."}` POST to channel URL. Non-200 response → `{"ok": false, "status": <code>}`. |
| ST-11 | Channel IDs are UUID v4 strings, assigned at creation. Client must store the ID to update or delete. |

---

## 22. AI Analytics Hub Rules (v5.2)

### Cache Rules

| # | Rule |
|---|------|
| AH-01 | Cache key = `sl:query:{sha256(sorted QueryObject)[:24]}`. Sort is applied to `metrics` and `dimensions` lists before hashing — order-independent caching. |
| AH-02 | Minimum limit for caching is 10 rows. Queries with `limit < 10` bypass cache (assumed exploratory/debug). |
| AH-03 | Cache TTL = `SEMANTIC_CACHE_TTL` env var (default 600s). Increase for stable daily reports; decrease for real-time dashboards. |
| AH-04 | Cache is fail-open: Redis unavailability must never block SQL generation. All Redis exceptions are caught and logged at DEBUG level. |
| AH-05 | `use_cache=False` parameter bypasses cache entirely (for real-time `/budget/check` calls). |

### Model Registration Rules

| # | Rule |
|---|------|
| AH-06 | Built-in model IDs are reserved: `filter_events`, `ers_scores`, `billing_usage`, `incidents`, `vendor_contracts`, `agentic_orders`, `tunnel_sessions`, `compliance_attestations`, `ai_spend`. |
| AH-07 | Tenant model IDs must not collide with built-in IDs. `register_tenant_model()` raises `ValueError` on collision. |
| AH-08 | `bootstrap_tenant_models()` is called once at FastAPI startup to restore persisted models into the engine. |
| AH-09 | Model deletion removes from engine registry immediately. Cached queries for the deleted model may still return results until TTL expiry. |

---

## 23. Commerce Budget Guardian Rules (v5.2)

| # | Rule |
|---|------|
| BG-01 | Budget check is fail-open: exceptions in `check_budget()` log a WARNING and return `allowed=True`. Commerce must never be blocked by infrastructure failures. |
| BG-02 | Per-transaction limit is checked BEFORE monthly budget. Blocks immediately if exceeded — no monthly spend query needed. |
| BG-03 | MTD spend is queried from `ai_spend` Semantic Layer model (SQLite fallback in dev, TimescaleDB in prod). |
| BG-04 | `require_approval` flag propagates through the purchase workflow response so MCP bridge can trigger human-in-the-loop. |
| BG-05 | Slack alert fires on budget exceeded via `send_alert()`. Alert never blocks payment decision. |
| BG-06 | `get_spend_summary()` returns the generated Semantic Layer SQL in `semantic_layer_sql` field for transparency and audit.

---

## 26. GitHub Actions CI Scan Rules (v5.3 · IN-15)

The GitHub Actions scan gate (`scripts/warden_github_scan.py`) applies the following content rules in addition to the standard 9-stage filter pipeline.

| # | Rule |
|---|------|
| CI-01 | Commit messages and per-file diffs are scanned separately. Each item produces its own verdict. Aggregate verdict = highest individual verdict. |
| CI-02 | Files matching `_SKIP_EXTENSIONS` (`.lock`, `.pb`, `.pyc`, image/font/binary extensions) are silently skipped — no verdict recorded, no false positives from non-scannable content. |
| CI-03 | Lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`) are always skipped regardless of extension. |
| CI-04 | Generated directory prefixes (`dist/`, `build/`, `vendor/`, `node_modules/`, `.git/`) cause the file to be skipped. |
| CI-05 | Per-file diff is capped at 6,000 bytes. Content beyond the cap is truncated before scanning (not skipped). |
| CI-06 | Commit message is capped at 2,000 characters. |
| CI-07 | A maximum of 30 files are scanned per CI run. Files beyond the cap are counted as `files_skipped` but not scanned. |
| CI-08 | `fail_on=BLOCK` (default): job fails only on BLOCK verdict. `fail_on=HIGH`: job fails on HIGH or BLOCK. MEDIUM/LOW always pass regardless of setting. |
| CI-09 | Empty content (blank commit message or empty diff) returns `SKIP` verdict — never contributes to aggregate. |
| CI-10 | API errors (connection refused, HTTP 4xx/5xx) return `ERROR` verdict. ERROR does not trigger fail-on threshold — scan is fail-open on infrastructure failure. |
| CI-11 | PR comment is posted only when `github.event.pull_request.number` is non-empty. Push events produce a step summary but no PR comment. |
| CI-12 | Warden scan result is always uploaded as a 90-day GitHub Actions artifact (`warden-scan-{sha}`), regardless of pass/fail outcome. This constitutes the CI audit trail. |
| CI-13 | In pre-commit mode (`--mode pre-commit`), the script exits 1 (blocking the commit) when aggregate verdict meets `fail_on` threshold. Git client receives a clear terminal message identifying the flagged content. |
| CI-14 | `context` field sent to `/filter`: `"github_ci"` for CI mode commit message, `"github_diff"` for CI mode diff, `"git_pre_commit_message"` / `"git_pre_commit_diff"` for pre-commit mode. |
| CI-15 | `tenant_id` defaults to `"github-ci"`. Override via `WARDEN_TENANT_ID` env var or `tenant-id` composite action input. |

---

## 27. ISO 27001:2022 Annex A Control Mapping Rules (v5.3 · CP-22)

| # | Rule |
|---|------|
| ISO-01 | The canonical control list is `_ISO27001_CONTROLS_V2` in `warden/api/compliance_report.py` — a Python list of 5-tuples `(control_id, theme, domain, status, evidence)`. It must contain exactly 93 entries. CI tests enforce this count. |
| ISO-02 | Valid statuses: `"Implemented"`, `"Partial"`, `"Delegated"`. No other values are permitted. `"Implemented"` means the platform actively provides the control. `"Partial"` means partial implementation with a known gap documented in the evidence string. `"Delegated"` means the control responsibility rests with the infrastructure provider (Hetzner VPS) or a third party. |
| ISO-03 | Valid themes: `"Organizational"`, `"People"`, `"Physical"`, `"Technological"`. Theme counts must be exactly 37 / 8 / 14 / 34. CI tests enforce these counts. |
| ISO-04 | Every control must have a non-empty evidence string. The string must reference specific platform files, endpoints, or configuration — not generic assertions. |
| ISO-05 | Coverage score formula: `(implemented + partial × 0.5) / total × 100`. This weighted score counts partial compliance at half value — never round up. |
| ISO-06 | The `_ISO27001_CONTROLS` legacy alias exposes 4-tuples `(control_id, domain, status, evidence)` for backward compatibility with callers written before the `theme` field was added. The alias must stay in sync with `_ISO27001_CONTROLS_V2`. |
| ISO-07 | The `/compliance/iso27001` endpoint requires `iso27001_enabled` feature flag. Only Enterprise tier receives `True`. Requests from Pro or lower tiers receive HTTP 403. |
| ISO-08 | The HTML report (`/compliance/iso27001/html`) groups rows by theme with a theme-level header showing implemented/total counts. Individual control rows must be present for all 93 controls — no pagination or truncation in the HTML output. |
| ISO-09 | The `by_theme` response field maps each theme to a list of its controls. All four themes must be present. The union of all theme lists must equal all 93 controls with no duplicates. |
| ISO-10 | Physical controls (A.7.x) should be status `Delegated` unless a specific platform-level control justifies otherwise (e.g., A.7.9 off-premises asset security maps to MinIO encryption). Evidence must justify any non-Delegated status for A.7.x. |
| ISO-11 | Test fixtures for `/compliance/iso27001` must pass `X-Tenant-Tier: enterprise` header. Tests using the default tier (`starter`) will receive HTTP 403 and should assert that status code explicitly if testing the gate behaviour. |

---

## 28. Community Hub Rules (v5.6 · CM-53, CM-54)

| # | Rule |
|---|------|
| HUB-01 | All Community Hub API calls use the existing `/communities/*` router — no separate hub router. Community Hub UI is a presentation layer over those endpoints. |
| HUB-02 | SOC Dashboard community pages use `NEXT_PUBLIC_TENANT_ID` env var (fallback `"default"`) to identify the acting tenant. This is a SOC-level config, not per-user auth. |
| HUB-03 | The `useCommunityWebSocket` hook derives the WS URL from `NEXT_PUBLIC_API_URL` via regex replace: `https://` → `wss://`, `http://` → `ws://`. The negative lookahead `(?!s)` prevents double-replacing `https`. |
| HUB-04 | WebSocket reconnect: only reconnect on unclean close (`!ev.wasClean`). Clean server-side closes (code 1000) do not trigger retry. Retry delay is exactly 30 seconds. |
| HUB-05 | On component unmount the WebSocket is closed with code 1000 + reason `"unmount"`. The pending `retryTimer` is cleared before close to prevent a reconnect after unmount. |
| HUB-06 | Community lists (My Communities, public Explore, Members tab) are always sorted descending by their primary date field (`created_at` for communities, `joined_at` for members). The sort is performed client-side — APIs may return any order. |
| HUB-07 | All dates displayed in Community Hub UI (portal, SOC dashboard, Streamlit) use `dd/mm/yy` format. ISO 8601 strings are formatted client-side; never display raw ISO strings. |
| HUB-08 | Portal Community Hub toast notifications use `react-hot-toast`. Toasts must not be shown alongside legacy inline flash messages (`{msg && ...}` blocks). All legacy flash blocks are removed when toasts are added to a page. |
| HUB-09 | The `<Toaster>` component is rendered once in `portal/src/app/community-hub/layout.tsx` — not per-page. All pages in the `community-hub/` route group inherit it. |
| HUB-10 | Streamlit `st_toast()` wrapper: calls `st.toast(msg, icon=icon)` and catches `AttributeError` to fall back to `st.success()` for Streamlit < 1.28. This shim must remain until the minimum Streamlit version is raised to 1.28. |
| HUB-11 | `fmt_date()` in `22_Community_Hub.py` handles `Z`-suffix UTC strings via `.replace("Z", "+00:00")` before `datetime.fromisoformat()`. On parse failure it returns `iso[:10]` (not an empty string). |
| HUB-12 | Member removal in the Streamlit Hub requires the "Enable member removal" toggle to be active. Removal buttons are not rendered when the toggle is off — no accidental removals from list rendering. |
| HUB-13 | The SOC Dashboard `fmtDate` function guards against invalid ISO strings with a `try/catch` block returning `iso.slice(0, 10)` on failure — matches the Streamlit `fmt_date()` fallback behaviour. |
