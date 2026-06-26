# Project Context — Shadow Warden AI

**Version:** 6.6 | **Updated:** 2026-06-26 | **Server:** 91.98.234.160 (Hetzner Ubuntu VPS)

## What this system is

A self-contained, GDPR-compliant AI security gateway that sits in front of every AI request.
It blocks jailbreaks, strips PII/secrets, and self-improves via Claude Opus — without sending sensitive data to third parties.

## Architecture invariants (do not break)

1. **Content is NEVER logged.** Only metadata: type, length, timing, verdict. Hard GDPR requirement.
2. **Filter pipeline stage order is fixed:** topology → obfuscation → secrets → semantic_rules → brain → causal → phish → ers → decision. Reordering breaks the compound risk escalation logic.
3. **All external dependencies are fail-open.** Redis, Postgres, Anthropic API, S3/MinIO — a failure must never crash the primary request path.
4. **Atomic file writes.** `tempfile` + `os.replace()` for `logs.json` and `dynamic_rules.json`. No partial writes.
5. **Fail-closed auth.** Startup raises `RuntimeError` if `WARDEN_API_KEY` and `WARDEN_API_KEYS_PATH` are both unset, unless `ALLOW_UNAUTHENTICATED=true`.
6. **Decimal math in billing.** `float` arithmetic is prohibited anywhere money is computed.

## Infrastructure

| Service | Port | Notes |
|---------|------|-------|
| warden (FastAPI gateway) | 8001 | Main filter + all APIs |
| analytics (Streamlit) | 8002 | Reads logs.json directly |
| dashboard (Next.js 14) | 3002 | SOC dashboard |
| portal (Next.js) | 3001 | Tenant self-service |
| site (Astro static) | — | Landing pages (pre-built to `landing/`) |
| postgres | 5432 | TimescaleDB, pgvector |
| redis | 6379 | Cache, ERS, session memory |
| minio | 9000 | Evidence vault, S3-compatible |
| prometheus + grafana | 9090/3000 | Metrics |

## Key env vars (production)

All in `/opt/shadow-warden/.env` on the server. Never commit secrets.

Critical for tests:
```
ALLOW_UNAUTHENTICATED=true
WARDEN_API_KEY=""
REDIS_URL=memory://
MODEL_CACHE_DIR=/tmp/warden_test_models
LOGS_PATH=/tmp/warden_test_logs.json
DYNAMIC_RULES_PATH=/tmp/warden_test_dynamic_rules.json
```

## ML model

`all-MiniLM-L6-v2` (384-dim). CPU-only torch. Loaded via `@lru_cache(maxsize=1)` singleton in `brain/semantic.py`. Pre-warmed in FastAPI `lifespan()`. Named Docker volume `warden-models` — persists across rebuilds.

## Deployment

GitHub Actions → SSH → `git pull` + `docker compose up -d --build warden`. CI must pass first.
SSH key: `~/.ssh/id_ed25519` (shadow-warden-deploy).
