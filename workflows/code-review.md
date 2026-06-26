# Workflow: Code Review

## Security-critical areas (review before every merge)

### Marketplace changes
Run the marketplace code-reviewer agent: see `agents/marketplace-code-reviewer.md`

Checklist:
- [ ] `search_and_buy()` used (not `auto_buy()` directly) — First-Proposal Bias Guard
- [ ] `POST /analytics/query` still SELECT-only — no DDL/DML path introduced
- [ ] Ed25519 signature check not bypassed in negotiation flow
- [ ] Sybil gate fires on every `POST /listings`
- [ ] `ClearingEngine` take rate uses `Decimal` math
- [ ] Sponsored boost applied in Python, not SQL ORDER BY

### Filter pipeline changes
- [ ] Stage order unchanged: topology → obfuscation → secrets → semantic_rules → brain → causal → phish → ers → decision
- [ ] No content logged (only metadata: type, length, timing)
- [ ] Fail-open on all external dependencies (Redis, Postgres, Anthropic)
- [ ] Atomic writes: `tempfile` + `os.replace()` for logs.json / dynamic_rules.json

### Auth / billing changes
- [ ] Fail-closed: `ALLOW_UNAUTHENTICATED=true` required to run without API key
- [ ] New tier gates in `TIER_LIMITS` with correct tier levels
- [ ] Add-on gates return HTTP 403 (tier too low) or 402 (not purchased) — not 401

### Crypto / PQC changes
- [ ] liboqs wrapped with `_OQS_AVAILABLE` guard (fail-open to classical)
- [ ] Hybrid kid convention: classical = "v1", PQC = "v1-hybrid"

## Standard review questions

1. **Is it fail-open?** External I/O (Redis, Postgres, Anthropic, S3, MinIO) must never crash the primary request path.
2. **Is it GDPR-safe?** No raw content, PII, or secrets on log lines, Prometheus labels, or OTel span attributes.
3. **Is the migration additive?** `ALTER TABLE ... ADD COLUMN` wrapped in `contextlib.suppress(Exception)` for SQLite; `ON CONFLICT DO NOTHING` for Postgres.
4. **Does it add comments that explain WHY?** No comments explaining WHAT — code should be self-explanatory.
5. **Is it tested?** New code path needs a test. Coverage must stay ≥ 75%.

## Running security audit agent

```
agents/security-auditor.md — use for marketplace, auth, crypto, and filter pipeline PRs
```
