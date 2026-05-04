# site-Rule.md — Professional Site Development Rules
# Shadow Warden AI · v4.11 · Cowork Build

> These rules govern every line of code and configuration that enters the
> Shadow Warden AI **public-facing website** (landing, dashboard, docs,
> settings, payments, community portal). They are enforced in CI and in
> every pair-coding / vibe-coding session via Claude.

---

## 1. Universal Architecture Principles

| Rule | Enforcement |
|------|-------------|
| **Fail-open always** — every external call (payment gateway, MinIO, Slack, API) must degrade gracefully; errors are logged, never raised to users | Hook pre-commit |
| **Immutable evidence** — all admin/financial actions write an audit trail to MinIO `evidence/site/` before mutating state | CI smoke test |
| **Zero-trust data plane** — no raw secret, key, or PII ever enters JS, HTML, or a public endpoint | secret-redactor hook |
| **Dataclass-first** — all API response shapes are dataclasses with `summary()` for human-readable logging | mypy CI |
| **No blocking I/O on the hot path** — async/await everywhere; Playwright sessions via ScreencastRecorder context manager only | ruff + mypy |
| **One source of truth** — all URLs, thresholds, and toggle states live in `Settings(frozen=True)` loaded from env | settings-frozen hook |

---

## 2. Module Rules

### 2.1 Business Community

- Auth: OAuth2/OIDC, mandatory MFA for admin roles.
- User-generated content passes through a `ContentFilter` (screenshot preview → Claude Vision assertion: "no hate speech, spam, or prohibited content") before publishing. Verdict stored in MinIO as SOC2 evidence.
- File uploads: ClamAV scan + `SecretRedactor` PII check; files rejected on hit, reason returned to uploader.
- Community data is multi-tenant: every DB query carries `tenant_id` — no cross-tenant row exposure permitted.
- Rate limiting: 100 posts/hour per user, 10 file uploads/day per user. ERS-style sliding window in Redis.

### 2.2 Cyber Security

- Every HTTP request is logged in ECS format (Elastic Common Schema) to the analytics pipeline.
- All secrets (API keys, DB passwords, SMTP creds) stored in HashiCorp Vault / env only; never in code, config files, or git history.
- Endpoints adhere to OWASP Top 10 (2021): parameterised queries only, CSRF tokens on all state-changing forms, Content-Security-Policy headers.
- Prometheus metrics exported for every section: request count, error rate, p99 latency.
- `WardenHealer`-equivalent watchdog checks circuit-breaker state, canary probe (`/health`), and bypass spike for site services every 5 min.
- Penetration test results stored under `docs/security/pentest-YYYY-MM.md`; findings tracked to closure.

### 2.3 Documentation

- Source: MkDocs with Material theme, auto-generated from docstrings (mkdocstrings).
- Versioned: `/docs/stable` → latest release tag, `/docs/latest` → main branch.
- Every merge to `main` runs `mkdocs build --strict` (zero warnings = zero broken links).
- Built artefacts (`.html` bundle) uploaded to MinIO `evidence/docs/<version>/` as immutable SOC2 snapshot.
- API reference auto-generated from OpenAPI spec; examples must include request + response JSON.
- Changelog entry required for every user-visible change (format: Keep a Changelog).

### 2.4 Settings Integration

- `Settings` class: `@dataclass(frozen=True)`, loaded via `pydantic-settings` from environment.
- Every configurable parameter has: type annotation, default value, description string, env-var name.
- Changes to Tier-1 settings (API keys, payment credentials, feature flags) require:
  1. Slack confirmation webhook (auto-sent by `sova_visual_patrol` watchdog).
  2. Manual approval recorded in MinIO `evidence/settings-changes/<timestamp>.json`.
- Settings UI (enterprise-settings page) posts changes to `POST /api/config`; backend validates and rejects unknown keys.
- Hot-reload supported for non-critical settings (thresholds, model versions); Tier-1 settings require container restart.

### 2.5 Payment Plan

- Primary gateway: Stripe (webhook-first, idempotent); fallback: Cryptomus.
- Every `charge()` call carries a `idempotency_key = sha256(tenant_id + plan_id + timestamp_bucket)`.
- Payment lifecycle events mirrored to MinIO `evidence/payments/YYYY-MM/<event_id>.json` immediately after webhook receipt.
- Failed payments: exponential back-off (1h → 6h → 24h → dunning email); never retry synchronously.
- Subscription downgrades enforced at end of billing period, never mid-cycle.
- Refunds processed via `POST /billing/refund`; require `X-Admin-Key`; audit trail to MinIO.
- PCI DSS: no card data touches the server; Stripe.js tokenisation only.

---

## 3. Coding Standards

```
Language      : Python 3.12+ (backend), TypeScript 5+ (frontend)
Framework     : FastAPI (API), Astro (landing/docs/settings), Playwright (e2e)
Type safety   : mypy --strict (Python), tsc --strict (TypeScript)
Lint          : ruff (Python), eslint + prettier (TS)
Line length   : 100 chars
Tests         : pytest (backend, >85% coverage), Playwright (e2e visual)
Async         : all I/O async; no blocking calls in FastAPI handlers
Evidence      : ScreencastRecorder + s3.ship_screencast() for all patrol runs
```

- No `print()` — use `logging.getLogger(__name__)`.
- No hardcoded URLs — all from `Settings`.
- No `except Exception: pass` — at minimum log the error with context.
- New SOVA tools follow numbering convention and must include fail-open path.

---

## 4. CI/CD Gates

Every PR must pass all of these before merge:

| Gate | Tool | Threshold |
|------|------|-----------|
| Unit tests | pytest | >85% coverage |
| Type check | mypy --strict | 0 errors |
| Lint | ruff + eslint | 0 errors |
| Secret scan | SecretRedactor hook | 0 hits |
| Visual smoke | sova_visual_patrol (5 URLs) | 0 CRITICAL verdicts |
| Doc build | mkdocs --strict | 0 warnings |
| Idempotency check | custom hook | all charge() calls verified |

Release to production is additionally gated on a visual_assert_page pass for:
`/community`, `/security`, `/docs`, `/settings`, `/payment/plans`
