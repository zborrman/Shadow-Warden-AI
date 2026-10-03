# About Shadow Warden AI

Human page: <https://shadow-warden-ai.com/about>

Shadow Warden AI is a zero-trust AI security gateway. It sits between your
application and every model it calls, screens each prompt before tokens are
spent, strips secrets and personal data, and records only metadata — request
content is never logged.

## What it does

- **Filter** — a nine-stage pipeline (topology, obfuscation decoding, secret
  redaction, semantic rules, an embedding model, causal arbitration, reputation
  scoring, phishing checks, decision) behind `POST /filter`.
- **Redact** — fifteen secret and PII patterns plus an entropy scan for secrets
  no pattern knows about.
- **Gate agents** — session-level detection of injection chains across tool
  calls, so a multi-step agent cannot be walked into a harmful action.
- **Explain** — every decision carries a request id whose causal chain can be
  retrieved later as audit evidence.

It also hosts an experimental machine-to-machine marketplace for detection
intelligence. That part runs on a test network; no real funds move.

## Who runs it

Shadow Warden AI is independently built and maintained, with a public contact
address and a published security-disclosure channel. The publisher's
registered-entity details will be added to this page and to the privacy notice
when incorporation completes; until then nothing on this site names a legal
entity that does not yet exist.

## What we do not claim

- Jailbreak detection is measured at 36.2% on our own 58-prompt adversarial
  corpus, with 0 of 35 benign prompts flagged. No higher figure is ours.
- We hold no certification of any kind. Control mappings are self-attested.
- There are no registered customers yet, so there are no customer references.
- Per-stage latency is not instrumented in production, so we quote none.

The full list lives in the [trust centre](https://shadow-warden-ai.com/trust).

## Get in touch

- General, sales and support: <vz@shadow-warden-ai.com> — [contact page](https://shadow-warden-ai.com/contact)
- Security disclosure: [security.txt](https://shadow-warden-ai.com/.well-known/security.txt)
- Privacy: [privacy notice](https://shadow-warden-ai.com/privacy)
- Developers: [developer portal](https://shadow-warden-ai.com/developers)
