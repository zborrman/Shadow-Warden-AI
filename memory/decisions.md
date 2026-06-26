# Architecture Decision Record

## ADR-001: pgvector over dedicated vector DB (Pinecone, Weaviate)

**Decision:** Use pgvector extension on the existing PostgreSQL instance for semantic search.

**Why:** The existing Postgres already handles relational data. pgvector handles ~1M rows without a dedicated vector DB. Eliminates an extra service, an extra cost center, and an extra failure point. HNSW index provides sub-10ms ANN at our scale.

**Constraint:** ORDER BY expressions that include computed boosts disable HNSW/IVFFlat indexes. Sponsored listing boost (+0.15) must be applied in Python after the index fetch — not in SQL.

---

## ADR-002: SQLite as Layer 1 with PostgreSQL dual-write

**Decision:** All marketplace, clearing, SEP, and secrets data writes to SQLite first (synchronous), then async dual-write to PostgreSQL (fail-open).

**Why:** SQLite provides immediate local consistency with zero network latency. The warden container can operate fully offline. PostgreSQL provides the cross-tenant audit trail for SIEM/SOC. The dual-write pattern means PostgreSQL is never on the critical path.

**Constraint:** Never share `MARKETPLACE_DB_PATH` across test classes — concurrent SQLite writes corrupt the database. Use `tmp_path` fixture for test isolation.

---

## ADR-003: x402/1.0 for marketplace nanopayments

**Decision:** Use x402/1.0 protocol with PAYMENT-REQUIRED / PAYMENT-SIGNATURE headers.

**Why:** x402 is the emerging IETF standard for HTTP-native micropayments. Agents can self-fund searches without a subscription. Batch deduction queue (not per-call on-chain settlement) keeps gas costs near zero.

**Constraint:** v1 is logged-only — `ClearingResult.platform_fee_usd` is computed and persisted but no on-chain USDC transfer occurs. Circle Gateway settlement is v2. Do NOT call `usdc.py` from `clearing.py`.

---

## ADR-004: CPU-only torch, no GPU dependency

**Decision:** Install PyTorch from `--index-url https://download.pytorch.org/whl/cpu` in Dockerfile.

**Why:** Target hardware is standard VPS (Hetzner), not GPU servers. CPU-only torch is ~2GB smaller. The `all-MiniLM-L6-v2` model runs fast enough on CPU for the single-request latency budget (<2ms for semantic stage).

**Constraint:** Two-step pip install in Dockerfile prevents CUDA pull. Do not simplify to a single `pip install torch`.

---

## ADR-005: Playwright MCR base image

**Decision:** Use `mcr.microsoft.com/playwright/python:v1.49.0-noble` as base for warden Dockerfile.

**Why:** Playwright requires OS-level browser dependencies that are pre-installed in the MCR image. Switching to `python:3.x-slim` breaks headless Chromium. Non-root user uses UID/GID 10001 (1001 is taken by the noble base image).

---

## ADR-006: Decimal math for all billing

**Decision:** Any calculation involving money uses `from decimal import Decimal, ROUND_HALF_UP`. Float arithmetic is prohibited.

**Why:** IEEE 754 float cannot represent `0.015` (1.5%) exactly. Over thousands of transactions, float rounding accumulates into non-trivial errors that are legally problematic for a fee-collecting platform.

**Pattern:**
```python
fee = (Decimal(str(price)) * rate).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
```

---

## ADR-007: Fail-closed auth, fail-open everywhere else

**Decision:** Auth is the only component that fails closed. All other external dependencies (Redis, Postgres, Anthropic, S3) fail open.

**Why:** A compromised auth gate is a security incident. A failed Redis cache just means a cache miss — no security impact, and failing closed would take down the gateway for all users. The asymmetry is intentional.

---

## ADR-008: No root package.json (monorepo avoided)

**Decision:** `portal/`, `dashboard/`, and `site/` are standalone npm projects. No root-level `package.json` with workspaces.

**Why:** npm v10 on Linux breaks `npm ci` in subdirectories when a root workspace is present. Each frontend has its own lock file. `packages/ui/` has a `package.json` but is not a workspace member.

---

## ADR-009: SOVA agent is Claude Opus, WardenHealer is LLM-free on happy path

**Decision:** SOVA uses Claude Opus 4.6 for agentic reasoning. WardenHealer performs all 4 anomaly checks via direct HTTP calls with no LLM; Haiku is called only once per unique incident fingerprint (cached in SQLite).

**Why:** SOVA handles complex multi-step decisions. WardenHealer runs every 30 minutes on a cron — using Opus there would be expensive and slow. Haiku provides classification at low cost, cached so the same incident type isn't re-classified.
