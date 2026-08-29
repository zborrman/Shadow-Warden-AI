# Shadow Warden AI

> Zero-trust AI security gateway. Every prompt, completion and agent tool call
> passes a nine-stage filter before it reaches a model or the outside world.

- Homepage: <https://shadow-warden-ai.com/>
- Machine index: <https://shadow-warden-ai.com/llms.txt>
- Agent instructions (when to use this): <https://shadow-warden-ai.com/.well-known/agent-instructions.md>
- OpenAPI 3.1: <https://shadow-warden-ai.com/openapi.json>
- API base URL: `https://api.shadow-warden-ai.com`

## What it does

`POST /filter` runs text through nine stages and returns a decision plus a
reason, so a caller can allow, redact or block before spending model tokens:

1. **TopologicalGatekeeper** — n-gram point cloud, Betti numbers β₀/β₁
2. **ObfuscationDecoder** — base64/hex/ROT13/Caesar/word-split/UUencode/homoglyph, depth 3
3. **SecretRedactor** — 15 secret patterns plus a Shannon-entropy scan for unknown secrets
4. **SemanticGuard** — rule engine with compound-risk escalation
5. **HyperbolicBrain** — MiniLM embeddings projected onto a Poincaré ball
6. **CausalArbiter** — Bayesian DAG for the gray zone
7. **ERS** — sliding-window reputation, shadow ban above a score threshold
8. **PhishGuard** — URL and lure analysis
9. **Decision** — verdict, risk score, and the stage that produced it

Content is never logged. Only metadata (type, length, timing) is written, which
is what makes the audit trail GDPR-safe.

## Interfaces

| Interface | Entry point |
|---|---|
| REST API | `POST https://api.shadow-warden-ai.com/filter` |
| OpenAI-compatible proxy | `POST https://api.shadow-warden-ai.com/v1/chat/completions` |
| Python SDK | `pip install shadow-warden-sdk` |
| TypeScript SDK | `npm install @shadow-warden/sdk` |
| CLI | `warden filter "text"` — console script of `shadow-warden-sdk` >= 1.1.0 |
| Agent Card (A2A / ADP) | `GET https://shadow-warden-ai.com/.well-known/agent.json` |
| DID document | `GET https://shadow-warden-ai.com/.well-known/did.json` |

## Where to go next

- [Documentation](https://shadow-warden-ai.com/doc.md)
- [SDK and CLI](https://shadow-warden-ai.com/sdk.md)
- [Pricing](https://shadow-warden-ai.com/pricing.md)
- [Agentic marketplace](https://shadow-warden-ai.com/agentic.md)
- [Trust centre](https://shadow-warden-ai.com/trust.md)
- [Sitemap](https://shadow-warden-ai.com/sitemap-index.xml)

## Maturity

Capability statuses — what is live, what is testnet, what is built but not
deployed — are published in the repository's capability matrix and are the
authority over any marketing copy. Nothing on this site should be read as a
certification, and the marketplace has no production traffic.
