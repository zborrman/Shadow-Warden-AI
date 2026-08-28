# Trust Centre — Shadow Warden AI

Human page: <https://shadow-warden-ai.com/trust>

## Data handling

- Request content is never logged. The event log records metadata only: type,
  length, timing, verdict, stage.
- Secret and PII redaction runs before any downstream call: 15 secret patterns
  plus an entropy scan for secrets that match no pattern.
- Key material at rest is encrypted with a boot-validated Fernet key; the
  backup path is fail-closed without it.

## Cryptography

- Hybrid post-quantum signatures (Ed25519 + ML-DSA-65) and hybrid KEM
  (X25519 + ML-KEM-768) are live, self-checked at boot.
- These implement the FIPS 203/204 algorithms. We hold no FIPS validation and
  claim none.

## Compliance posture

Our control mappings are self-attested. We hold no third-party certification of
any kind, and nothing on this site should be read as one. GDPR obligations —
content minimisation, Article 30 records, data-subject export and erasure — are
implemented in the product and described under
<https://shadow-warden-ai.com/doc/compliance>.

## Reporting a problem

Security reports: <https://shadow-warden-ai.com/contact>. Please include
reproduction steps and the request id from the response if you have one.
