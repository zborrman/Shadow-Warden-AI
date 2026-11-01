# OWASP Top 10 for Agentic Applications (2026) — control mapping

**Status: `SELF-ATTESTED`.** This is our own mapping of each OWASP agentic risk
to the controls in this repository. Nobody independent has verified it. It is
not a certification, an audit result or a coverage percentage, and it must not
be quoted as one (see `docs/capability-matrix.md`).

Source list: OWASP GenAI Security Project, *Top 10 for Agentic Applications for
2026*, published 2025-12-09 ([genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)).

Status values follow the capability matrix. `LIVE` means the control runs in
the deployed gateway. It does not mean it has defended real traffic: there are
zero registered users, so no control below has been tested by a third-party
agent.

| ID | Risk | Controls in this repository | Status | Known gap |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | `/filter` pipeline: obfuscation decoding, secret redaction, rule and ML semantic guards, causal arbiter (`warden/main.py` pipeline). Freetext pre-screen for Digital Staff tools (Rec-1). Negotiation-message scan (`marketplace/injection_guard.py`). | `LIVE` | Detection quality is `OVERSTATED` in the matrix: the public figure stays 36.2% until a held-out eval exists. Fiction or "educational" framing is still missed. |
| ASI02 | Tool Misuse | One gate for every agentic tool call: `agent/gate.py::agentic_gate()` (boundary fail-closed → velocity → GSAM quarantine). Staff path STAFF-01/02 in `staff/dispatcher.py`. SSRF/exfil screening of tool URLs, fail-closed (`sac/guard.py` via `net_guard`). | `LIVE` | Secret-path denylist only warns, does not block. |
| ASI03 | Identity & Privilege Abuse | Fail-closed API-key auth (`auth_guard.py`). Signing keys fail-closed via `secret_keys.resolve_key()`. Self-authenticating agent DIDs with Ed25519-signed x402 payments and replay nonces (`marketplace/x402_gate.py`). Single-use, scope-bound JIT credential leases (`gsam/jit_lease.py`). KYA screening before autonomy is granted (`marketplace/kya.py`). | `LIVE` | Routes that take a tenant or agent id from the request are ratcheted debt, not closed: `tenant_isolation_baseline.json` may only shrink. |
| ASI04 | Agentic Supply Chain Vulnerabilities | Pinned constraints with pip-audit gating fixable CVEs, Trivy image scan, SBOM, gitleaks, hadolint, Dependabot (`.github/workflows/ci.yml`). MCP protocol versions asserted against real revisions (`test_mcp_manifest.py`). | `LIVE` | Marketplace listings carry no content hash bound at listing time, so delivered content is not yet checked against what was listed. Production image is not yet pinned to a signed digest. |
| ASI05 | Unexpected Code Execution | No marketplace asset is executed by the gateway. AI-generated regex rules must pass a compile, timeout and nested-quantifier gate before use (`brain/evolve.py::_validate_regex_safety`). Browser sandbox disabled in the shipped image (`BROWSER_ENABLED=false`). Non-root container, UID 10001. | `LIVE` | If purchased rules are ever installed into a buyer's pipeline, they need the same regex gate and a hash check first. |
| ASI06 | Memory & Context Poisoning | CPT drift gate rejects calibration shifts above 25% (`causal_arbiter.py`). Poisoning-gated GSAM drift baselines (`gsam/drift.py`). Corpus canaries measured against a boot-time baseline (OB-F12). Bounded SOVA memory (6h TTL, 20-turn cap). | `LIVE` | One CPT parameter (`entropy_center`) is bounded by its clamp, not by the drift gate, and can be walked to the clamp edge across runs. Recorded for Track B. |
| ASI07 | Insecure Inter-Agent Communication | HMAC-signed A2A call tokens with a route whitelist and audit trail (`staff/a2a.py`). HMAC task tokens between MasterAgent sub-agents. HMAC peering handshakes and signed transfer proofs (`communities/peering.py`, `communities/sep.py`). | `LIVE` | No end-to-end record of a delegation chain (buyer agent → provider → sub-provider) per job. |
| ASI08 | Cascading Failures | Router isolation so a broken module cannot crash the pipeline (`app_factory.register_router_safe`). Security decisions fail closed, telemetry fails open, with every fail-open site inventoried (`docs/fail-open-inventory.md`). Spend ceilings: per-trade settlement cap (`SETTLEMENT_MAX_TRADE_USD`), Evolution and platform LLM budgets. | `LIVE` | — |
| ASI09 | Human-Agent Trust Exploitation | Draft-only outputs (`PENDING_REVIEW` / `PENDING_HUMAN_APPROVAL`). Agents never approve their own work. Human-in-the-loop approval tokens for high-impact actions (`agent/master.py`). Payment chokepoint returns REQUIRE_APPROVAL on any check error (`payments/authorize.py`). Per-decision explanations (`xai/`). | `LIVE` | Payment enforcement is opt-in (`AUTHORIZE_PAYMENT_ENFORCED`, default false). |
| ASI10 | Rogue Agents | GSAM behavioural drift with automatic quarantine (`gsam/quarantine.py`). Velocity guard. Trust graph and Sybil guard (`marketplace/sybil_guard.py`). ERS shadow ban. Agent revocation removes its autonomy policy (`kya.py::revoke_agent`). | `BUILT` | Trust graph and Sybil guard have zero production data (capability matrix). |

## What this mapping does not cover

- **On-chain settlement.** The escrow contract runs on testnet only and has not
  been externally audited. It is not counted as a control here.
- **Measured effectiveness.** Each row says a control exists and where. Only
  ASI01 has a measurement, and that measurement is the reason its row carries a
  gap.
