# Shadow Warden AI — Engineering Rules

**Version 4.8 · Last updated 2026-04**

Engineering standards enforced across the entire codebase. Pre-commit hooks in `Hook.md` automate the critical subset.

---

## §1. Python Code Style

| Rule | Standard |
|------|----------|
| Python version | 3.11+ features allowed (`match/case`, `X \| Y` unions, `tomllib`) |
| Line length | 100 chars (Ruff `line-length=100`) |
| Ruff rules | `E,F,W,I,N,UP,B,C4,SIM` — ignore `E501,B008` |
| Imports | stdlib → third-party → internal (I001 enforced by Ruff) |
| Type annotations | Not required on unchanged code; use `X \| Y` over `Optional[X]` |
| Comments | Only when WHY is non-obvious. No docstrings on unchanged code. |

---

## §2. GDPR Hard Rules

These rules are non-negotiable and violation blocks merge.

| # | Rule |
|---|------|
| G-01 | **Content is NEVER logged.** Only metadata: timestamp, verdict, risk level, flag types, content length, latency. Violations: `log.info(...content...)`, `log.warning(...body...)`. |
| G-02 | **Atomic writes.** All log/config writes use `tempfile.mkstemp()` + `os.replace()`. No direct file open + write. |
| G-03 | **PII never in Redis keys or values** beyond HMAC/Fernet-encrypted tokens. |
| G-04 | **Right to erasure.** `purge_before(timestamp)` must remain functional in `analytics/logger.py`. |
| G-05 | **Data minimisation.** No new telemetry fields without DPIA justification (`docs/dpia.md`). |

---

## §3. Security Standards

| # | Rule |
|---|------|
| S-01 | **No raw SQL string concatenation.** All DB queries use parameterised statements (`?` placeholders). |
| S-02 | **No `eval()` or `exec()`** anywhere in `warden/`. |
| S-03 | **Constant-time comparison** for all API key checks: `hmac.compare_digest()`. |
| S-04 | **Admin endpoints** require `X-Admin-Key` header check via `_require_admin()` dependency. |
| S-05 | **No `--no-verify` commits.** Pre-commit hooks must pass or be explicitly overridden with written justification in the PR. |
| S-06 | **Fernet for secrets at rest.** No plaintext storage of API keys, MinIO credentials, or vault keys. |
| S-07 | **Input validation at boundaries.** `FastAPI`/Pydantic validators on all external inputs. No validation on internal module calls. |

---

## §4. Docker Standards

| # | Rule |
|---|------|
| D-01 | **Multi-stage builds required.** Every `Dockerfile*` must have at least one named `AS builder` stage. |
| D-02 | **Non-root runtime.** All services run as UID/GID 10001 (`wardenuser`). |
| D-03 | **Pinned base images.** No `:latest` tags. MCR Playwright: `v1.49.0-noble`. |
| D-04 | **HEALTHCHECK** in every service Dockerfile. |
| D-05 | **CPU-only torch.** Install via `--index-url https://download.pytorch.org/whl/cpu`. Never pull CUDA variants. |
| D-06 | **Named volumes** for persistent data (`warden-models`, `caddy-data`, `postgres-data`). No bind-mounts for production state. |
| D-07 | **SMB compose isolation.** `docker-compose.smb.yml` must not include `minio`, `prometheus`, or `grafana`. |

---

## §5. FastAPI Patterns

| # | Rule |
|---|------|
| F-01 | **Try/except ImportError** for every optional router mount in `main.py`. Missing package = silent skip, not crash. |
| F-02 | **Fail-open** for Redis, S3, and external services. Degraded status returned, not 500. |
| F-03 | **Admin routes** always under `/admin/` prefix with `X-Admin-Key` guard. |
| F-04 | **Tier gates** use `require_feature()` / `require_addon_or_feature()` FastAPI dependencies. HTTP 403 = wrong tier; HTTP 402 = add-on not purchased. |
| F-05 | **No content in logs.** `log.info(...)` in route handlers may include: tenant_id, filename, size, risk, verdict, ms. Never include request body. |

---

## §6. Testing Standards

| # | Rule |
|---|------|
| T-01 | **Coverage gate: ≥75%.** `--cov-fail-under=75`. Currently at 76.31%. |
| T-02 | **Pytest markers.** `adversarial`, `slow`, `integration` — slow/adversarial excluded from CI fast run. |
| T-03 | **In-memory Redis** for tests: `REDIS_URL=memory://`. No live Redis dependency in unit tests. |
| T-04 | **No model download in unit tests.** `MODEL_CACHE_DIR=/tmp/warden_test_models`. |
| T-05 | **SWFE fakes** (`warden/testing/fakes/`) for Anthropic, NVIDIA, S3, Evolution Engine. Do not mock the database. |
| T-06 | **Mutation testing threshold.** `mutmut` on `secret_redactor.py` + `semantic_guard.py` — max 20 surviving mutants. |

---

## §7. Branch and Commit Rules

| # | Rule |
|---|------|
| B-01 | **Single branch: `main`.** All work goes to `main`. No long-lived feature branches. |
| B-02 | **Conventional commits.** `feat(scope):`, `fix(scope):`, `chore(scope):`, `docs(scope):`. |
| B-03 | **No force-push to main.** |
| B-04 | **`[skip ci]` allowed** only for `chore(landing): sync Astro dist` auto-commits from CI. |
| B-05 | **Commit co-attribution.** AI-assisted commits include `Co-Authored-By: Claude Sonnet 4.6`. |

---

## §8. Offline Mode Rules

| # | Rule |
|---|------|
| O-01 | **All 9 filter layers run offline.** Evolution Engine, S3, and Anthropic SDK are the only components disabled by `OFFLINE_MODE=true`. |
| O-02 | **`require_online(feature)`** must be called before any LLM or external API call inside optional code paths. |
| O-03 | **Redis fail-open.** `REDIS_URL=memory://` provides in-process rate limiting when Redis is unavailable. |

---

## §9. Landing Page / Vercel Rules

| # | Rule |
|---|------|
| V-01 | **Clean URLs only.** Nav links use `/path` not `/path.html`. Vercel `cleanUrls: true` handles extension-less serving. |
| V-02 | **No file + directory conflict.** If `landing/page.html` exists, `landing/page/` must not exist (or vice versa). Causes Vercel 404. |
| V-03 | **Explicit rewrites** in `vercel.json` for any route that has a non-obvious resolution (e.g. `/dashboard`, `/fraud-score`, `/enterprise-settings`). |
| V-04 | **`outputDirectory: landing`** is the single source of truth. Never push to Vercel directly — always commit to git and let Vercel auto-deploy. |
| V-05 | **Astro pages sync via CI.** `site/src/pages/*.astro` → `npm run build` → `cp -r site/dist/. landing/` → commit `[skip ci]`. Do not manually edit Astro output files. |

---

## §10. Environment Variable Rules

| # | Rule |
|---|------|
| E-01 | **Never hardcode secrets.** All credentials via env vars. `.env.example` documents the shape. |
| E-02 | **Test env vars** set in `warden/tests/conftest.py`. Never read from `.env` in tests. |
| E-03 | **Empty string = disabled.** `ANTHROPIC_API_KEY=""` disables Evolution Engine (air-gap mode). |
| E-04 | **`ADMIN_KEY`** required for all `/admin/*` endpoints in production. Empty string disables auth check in dev. |

---

*Rull.md — Shadow Warden AI engineering standards v4.8 · 2026-04*
