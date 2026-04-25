# Shadow Warden AI — Security Model

**Version:** 4.7 · **Audience:** Security auditors, CISOs, penetration testers

---

## 1. Threat Model

Shadow Warden AI is designed to defend against the following threat actors and attack classes:

### 1.1 Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| Script kiddie | Low — uses public jailbreak templates | Curiosity, minor disruption |
| Insider threat | Medium — knows system prompts, has API access | Data exfiltration, sabotage |
| Organized adversary | High — adaptive, multi-turn, obfuscated | IP theft, PII exfiltration, model abuse |
| Nation-state / APT | Very high — zero-day TTP, supply chain | Espionage, infrastructure disruption |

### 1.2 Attack Classes (OWASP LLM Top 10 coverage)

| OWASP ID | Attack Class | Warden Control |
|----------|-------------|----------------|
| LLM01 | Prompt Injection | SemanticGuard + BrainGuard + TopologicalGatekeeper |
| LLM02 | Insecure Output Handling | OutputGuard + OutputSanitizer |
| LLM03 | Training Data Poisoning | EvolutionEngine corpus validation + CanaryGuard |
| LLM04 | Model Denial of Service | TopologicalGatekeeper (< 2ms noise filter) + ERS shadow ban |
| LLM05 | Supply Chain Vulnerabilities | Immutable Docker image + CPU-only torch (no CUDA supply chain) |
| LLM06 | Sensitive Information Disclosure | SecretRedactor + Encrypted PII Vault |
| LLM07 | Insecure Plugin Design | Zero-Trust Agent Sandbox (capability manifests) |
| LLM08 | Excessive Agency | AgentMonitor (7 session patterns) + kill-switch API |
| LLM09 | Overreliance | CausalArbiter (uncertainty quantification) |
| LLM10 | Resource Exhaustion | WalletShield (token budget per user per window) |

---

## 2. Security Architecture

### 2.1 Nine-Stage Defense Pipeline

Every request traverses all stages in sequence. Each stage fails open (never blocks a legitimate request due to an internal error) but logs the failure:

```
Stage 0:   Auth Gate           — per-tenant API key, constant-time compare
                                 Fail-closed: startup halts if no key configured
                                 (ALLOW_UNAUTHENTICATED=true required for dev mode)
Stage 0.5: Redis Cache         — SHA-256 content hash, 5-min TTL
Stage 1:   Topological Guard   — n-gram point cloud → β₀/β₁ Betti numbers, < 2ms
Stage 2:   Obfuscation Decoder — base64/hex/ROT13/homoglyphs, depth-3 recursive
Stage 3:   Secret Redactor     — 15 regex patterns + Shannon entropy scan
Stage 4:   Semantic Guard      — rule-based, compound escalation (3× MEDIUM → HIGH)
Stage 5:   Brain (ML)          — MiniLM cosine (70%) + Poincaré ball hyperbolic (30%)
Stage 5.5: Causal Arbiter      — Bayesian DAG, gray-zone only, do-calculus
                                 CPT drift gate: rejects MLE updates >25% from prior
Stage 6:   Entity Risk Score   — Redis sliding window → shadow ban at ≥ 0.75
                                 Shadow ban pool: 30+ entries, secrets.choice() (non-deterministic)
Stage 7:   Decision            — ALLOW / BLOCK / SHADOW_BAN
```

### 2.2 Defense-in-Depth Layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 1 — Network                                                            │
│   Caddy v2.8+ reverse proxy, HTTP/3 QUIC, TLS 1.2+, HSTS 2yr               │
│   Early-Data: 1 rejected on POST endpoints (HTTP 425 — RFC 8470)            │
├─────────────────────────────────────────────────────────────────────────────┤
│ Layer 2 — Authentication (fail-closed)                                       │
│   Per-tenant API keys, SHA-256 hash lookup, constant-time compare           │
│   Startup halts if WARDEN_API_KEY unset (unless ALLOW_UNAUTHENTICATED=true) │
│   SAML 2.0 SSO (optional), TOTP MFA for dashboard                           │
│   VAULT_MASTER_KEY validated as Fernet key at boot                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ Layer 3 — Content Inspection (pre-ML)                                        │
│   Topological Gatekeeper (TDA), Obfuscation Decoder, Secret Redactor        │
├─────────────────────────────────────────────────────────────────────────────┤
│ Layer 4 — Semantic Detection                                                 │
│   Rule engine + MiniLM ML + Poincaré ball hyperbolic space                  │
│   Evolution Engine regex gate: ReDoS check + nested-quantifier heuristic    │
├─────────────────────────────────────────────────────────────────────────────┤
│ Layer 5 — Causal Reasoning                                                   │
│   Bayesian DAG (gray zone only) — do-calculus, backdoor correction          │
│   CPT drift gate: rejects MLE updates >25% shift (anti-poisoning)           │
├─────────────────────────────────────────────────────────────────────────────┤
│ Layer 6 — Behavioural / Session                                              │
│   Entity Risk Scoring, AgentMonitor (7 patterns)                            │
│   Shadow Ban: 30+ pool, secrets.choice() (non-deterministic, unfingerprint.) │
├─────────────────────────────────────────────────────────────────────────────┤
│ Layer 7 — Output Guardrails                                                  │
│   OutputGuard (price manipulation, unauthorized commitments)                 │
│   WalletShield (token budget enforcement, DoS prevention)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ Layer 8 — Compliance & Evidence                                              │
│   Evidence Vault (SHA-256 sign-last), STIX 2.1 tamper-evident audit chain   │
│   GDPR-safe NDJSON logs, MinIO on-prem object storage                       │
│   Community key material: field-level Fernet + validated VAULT_MASTER_KEY   │
├─────────────────────────────────────────────────────────────────────────────┤
│ Layer 9 — Self-Improvement                                                   │
│   Evolution Engine (Claude Opus), CorpusHealthMonitor, canary validation    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Data Classification & Flow

### 3.1 Data Classes

| Class | Examples | Handling |
|-------|---------|---------|
| Request content | User prompt, tool call arguments | NEVER logged — only length/metadata |
| Secrets / PII | API keys, SSN, IBAN, email, credit card | Redacted before any processing stage; never stored |
| Masked PII tokens | `[EMAIL_1]`, `[SSN_1]` | Encrypted in Fernet vault; HMAC-SHA256 reverse map |
| Security metadata | Risk level, flags, timing, entity key | NDJSON log + MinIO — GDPR-safe |
| Evidence bundles | Tool names, timeline, compliance score | SHA-256 signed — litigation-ready; MinIO on-prem |
| Audit trail | Filter decision, action, processing_ms | SQLite hash-chain — SOC 2 evidence |

### 3.2 Data Flow

```
User Request
    │
    ▼
nginx (TLS termination)
    │
    ▼
Warden Gateway (/filter)
    │
    ├─► Secret Redactor — strips secrets → redacted_content (never stored)
    ├─► PII Vault (if masking enabled) — encrypts PII in memory
    │
    ▼
All detection stages operate on redacted_content only
    │
    ▼
Decision logged as metadata only (no content):
    ├─► Local NDJSON (data/logs.json) — GDPR-safe
    └─► MinIO S3 (background, fail-open) — on-prem only
```

### 3.3 Data Never Stored

- Raw prompt/response content
- Decrypted PII values (vault keys are ephemeral, per-process)
- Full API keys (only SHA-256 hash of the key is stored in key file)
- IP addresses (ERS entity key = SHA-256[:16] of `"{tenant}:{ip}"`)

---

## 4. Cryptographic Controls

| Control | Algorithm | Purpose |
|---------|-----------|---------|
| Evidence bundle signing | SHA-256 (sign-last) | Tamper detection |
| STIX audit chain | SHA-256 prev_hash chain | Deletion/modification detection |
| PII vault encryption | Fernet (AES-128-CBC + HMAC-SHA256) | At-rest PII protection |
| PII reverse map | HMAC-SHA256 | No-plaintext reverse lookup |
| API key storage | SHA-256 (one-way) | Credential protection |
| ERS entity key | SHA-256[:16] | GDPR pseudonymisation |
| Cache key | SHA-256 (full content hash) | Cache poisoning prevention |
| S3 transport | TLS 1.2+ (MinIO) | Data-in-transit protection |
| Community private keys | Fernet field-level (VAULT_MASTER_KEY) | At-rest key material protection |
| Causal Transfer Proofs | HMAC-SHA256 + ML-DSA-65 (Enterprise PQC) | Tamper-evident transfer records |
| Sovereignty attestations | HMAC-SHA256 (SOVEREIGN_ATTEST_KEY) | Jurisdiction compliance proof |
| PQC signatures | Ed25519 + ML-DSA-65 hybrid | Post-quantum signing |
| PQC KEM | X25519 + ML-KEM-768 hybrid | Post-quantum key encapsulation |

---

## 5. Vulnerability Disclosure

Shadow Warden AI follows responsible disclosure. Security researchers can report vulnerabilities at: **security@shadow-warden-ai.com**

- Please do not disclose publicly before we have had 90 days to remediate.
- Include reproduction steps, impact assessment, and your contact info.
- We aim to acknowledge within 48 hours and provide a timeline within 7 days.

---

## 6. Known Limitations

| Limitation | Mitigation |
|-----------|-----------|
| MiniLM model is fixed (no real-time retraining) | Evolution Engine hot-reloads new corpus examples continuously |
| Shadow ban relies on Redis state — lost on Redis restart | AOF persistence + Redis replica in production config |
| Vault keys are ephemeral — PII masking sessions break on restart | Design choice: prevents key persistence attacks; document in SLA |
| β₁ computation is approximate without ripser | Install `ripser` for true persistent homology in production |
| Causal Arbiter CPT can drift under long-horizon attacks | CPT drift gate (25% cap) + human review required for large updates |

---

*Shadow Warden AI · security-model.md · Updated v4.7 · 2026-04-25*
