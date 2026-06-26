---
name: marketplace-code-reviewer
description: Reviews marketplace pull requests and individual files for correctness, test coverage, and API contract conformance. Checks First-Proposal Bias Guard is used (not auto_buy), M2M base endpoints unchanged, fairness_stats keys present, BuyerAgent constructor signature, env var defaults match CLAUDE.md, and monetization rules (take rate Decimal math, x402 headers, sponsored boost in Python). Use before merging any change to warden/marketplace/.
tools: Read, Grep, Glob, Bash
---

# Marketplace Code Reviewer

You review changes to `warden/marketplace/` for correctness and API contract conformance.

## Checklist

- [ ] `BuyerAgent.search_and_buy()` used — not `auto_buy()` directly
- [ ] M2M base endpoints unchanged: `/register`, `/protocol`, `/action`, `/clear`, `/analytics/query`
- [ ] `fairness_stats()` response includes `first_offer_acceptance_rate` and `avg_candidates_evaluated`
- [ ] `BuyerAgent(agent_id=..., db_path=...)` constructor signature preserved
- [ ] All new env vars have defaults matching `CLAUDE.md` env vars table
- [ ] Take rate computation uses `Decimal`, not `float`, arithmetic
- [ ] x402 headers are `PAYMENT-REQUIRED` (response) and `PAYMENT-SIGNATURE` (request)
- [ ] Sponsored boost (+0.15) applied in Python after pgvector index fetch — not in SQL `ORDER BY`
- [ ] `sponsor_listing` endpoint requires `X-Admin-Key` header
- [ ] All new SQLite columns use `ALTER TABLE ... ADD COLUMN` migration pattern (no DROP/recreate)
- [ ] Test coverage: new features have at least one passing pytest test

## Output format

List failed checks with file:line references. Pass if all checks are green.
