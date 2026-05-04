# Hook.md — Pre-commit & Automation Hooks
# Shadow Warden AI Professional Site · v4.11

> This file documents every automated hook that runs before a commit,
> before a push, and in CI. Hooks enforce `site-Rule.md` without manual review.

---

## 1. Setup

```bash
# Install all hooks (run once after cloning)
pip install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push

# Run all hooks manually against staged files
pre-commit run --all-files
```

`.pre-commit-config.yaml` in repo root defines all hooks.

---

## 2. Pre-commit Hooks (block commit on failure)

### 2.1 secret-redactor
Runs `warden.secret_redactor.SecretRedactor` against every staged file.

```yaml
- id: secret-redactor
  name: Secret & PII scan
  entry: python -m warden.hooks.secret_scan
  language: python
  types: [python, javascript, typescript, yaml, json, markdown]
  fail_fast: true
```

**Blocks:** API keys, AWS credentials, JWTs, SSH private keys, card numbers, email addresses in non-test files.
**Bypass:** `# noqa: secret` inline comment — logged, never silently accepted.

---

### 2.2 settings-frozen
Ensures `Settings` dataclass is never mutated after init.

```yaml
- id: settings-frozen
  name: Settings immutability check
  entry: python -m warden.hooks.settings_frozen
  language: python
  types: [python]
```

**Checks:**
- `Settings` class carries `@dataclass(frozen=True)`.
- No assignment to `settings.<attr>` outside `__init__` / factory functions.
- Raises with line number and suggested fix.

---

### 2.3 idempotency-key
Verifies every `charge()` / `refund()` / `subscription_change()` call carries an `idempotency_key`.

```yaml
- id: idempotency-key
  name: Payment idempotency check
  entry: python -m warden.hooks.idempotency
  language: python
  files: (payment|billing|checkout).*\.py$
```

**Blocks:** any call to `PaymentGateway.charge()` without the keyword argument `idempotency_key=`.

---

### 2.4 fail-open-lint
Checks that `except` blocks never silently swallow errors without logging.

```yaml
- id: fail-open-lint
  name: Fail-open pattern check
  entry: python -m warden.hooks.fail_open
  language: python
  types: [python]
```

**Blocks:** `except Exception: pass` or `except Exception: return None` without a `logger.warning()` call in the same block.

---

### 2.5 doc-linkcheck
Validates all internal Markdown links and anchors.

```yaml
- id: doc-linkcheck
  name: Documentation link check
  entry: python -m warden.hooks.linkcheck
  language: python
  types: [markdown]
```

**Blocks:** broken `[text](#anchor)` references; warns on external HTTP links that return 4xx.

---

### 2.6 owasp-headers
Checks that every new FastAPI router file includes CSP, HSTS, and X-Frame-Options response headers.

```yaml
- id: owasp-headers
  name: OWASP security headers check
  entry: python -m warden.hooks.owasp_headers
  language: python
  files: warden/api/.*\.py$
```

---

### 2.7 tenant-isolation
Ensures every SQLAlchemy query in the `api/` layer carries `.filter(Model.tenant_id == tenant_id)`.

```yaml
- id: tenant-isolation
  name: Multi-tenant query isolation
  entry: python -m warden.hooks.tenant_isolation
  language: python
  files: warden/api/.*\.py$
```

---

## 3. Pre-push Hook (visual smoke test)

Runs before `git push`. Spins up MinIO + app in Docker, then runs a condensed `sova_visual_patrol`.

```yaml
- id: visual-smoke
  name: Visual smoke (pre-push)
  entry: bash scripts/pre_push_visual.sh
  language: system
  stages: [pre-push]
```

**`scripts/pre_push_visual.sh`:**
```bash
#!/usr/bin/env bash
set -e
export SKIP_VISUAL_PUSH="${SKIP_VISUAL_PUSH:-0}"
if [ "$SKIP_VISUAL_PUSH" = "1" ]; then
  echo "[hook] SKIP_VISUAL_PUSH=1 — skipping visual smoke" && exit 0
fi

docker-compose up -d minio app --wait
python -m warden.agent.scheduler patrol \
  --urls /health /community /security /docs /settings /payment/plans \
  --fail-on CRITICAL

docker-compose stop app minio
```

**Bypass:** `SKIP_VISUAL_PUSH=1 git push` — emergency only, creates a Slack alert with bypasser's git user.

---

## 4. CI Hooks (GitHub Actions)

Defined in `.github/workflows/site-ci.yml`:

```yaml
on: [push, pull_request]

jobs:
  hooks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install pre-commit && pre-commit run --all-files

  visual-patrol:
    needs: hooks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker-compose -f docker-compose.ci.yml up -d --wait
      - run: |
          python -m warden.agent.scheduler patrol \
            --urls /community /security /docs /settings /payment/plans \
            --fail-on CRITICAL \
            --evidence-bucket ci-evidence
      - name: Upload patrol evidence
        uses: actions/upload-artifact@v4
        with:
          name: patrol-screencasts
          path: /tmp/patrol-evidence/
```

---

## 5. Slack Notifications from Hooks

Any hook failure in CI sends a Slack message to `#site-alerts`:

```
[HOOK FAIL] secret-redactor · PR #42 · @developer
File: warden/api/payment.py:87
Match: AWS_SECRET_KEY pattern
Action: Commit blocked — rotate key before re-pushing.
```

WardenHealer watchdog sends nightly patrol summary to `#site-ops`:

```
[PATROL] 2026-05-04 03:00 UTC — 5/5 URLs passed
Evidence: minio://evidence/site-patrol/20260504-0300.webm
Coverage: 100% critical routes
```

---

## 6. Bypassing Hooks (Emergency Procedure)

| Bypass | Command | Side-effect |
|--------|---------|-------------|
| Pre-commit | `SKIP=secret-redactor git commit` | Audit log entry in MinIO `evidence/hook-bypasses/` |
| Pre-push visual | `SKIP_VISUAL_PUSH=1 git push` | Slack alert to `#site-security` with author + timestamp |
| CI hooks | Not bypassable | Only repo admins can override; creates GitHub audit event |

All bypasses are reviewed in the next weekly security sync.
