# Workflow: Feature Build

Use this blueprint when adding a new feature to Shadow Warden AI.

## Prerequisites

Read before starting:
- `memory/project-context.md` — architecture invariants
- `memory/decisions.md` — prior ADRs (avoid re-litigating settled choices)
- Relevant `rules/` file for the area (API, testing, or code-style)

## Steps

### 1. Branch
```bash
git checkout -b feat/<slug>
```
For large features that touch many files, use an isolated worktree:
```bash
git worktree add ../sw-feat-<slug> -b feat/<slug>
```

### 2. Design check (< 30 min)
- Does this touch the `/filter` pipeline? Verify stage order in `main.py:lifespan`.
- Does it add a new FastAPI router? Mount it with `try/except ImportError` (fail-open).
- Does it write billing data? Use `Decimal` math — never `float` arithmetic.
- Does it log content? Stop. Content is NEVER logged — metadata only (GDPR hard rule).

### 3. Write the test first
```bash
# Pick the right test file or create warden/tests/test_<module>.py
# Mark slow tests: @pytest.mark.slow
# Mark adversarial: @pytest.mark.adversarial
# Use tmp_path for DB isolation; set MARKETPLACE_DB_PATH per test class
```
Run with no-cov for speed during development:
```bash
ALLOW_UNAUTHENTICATED=true WARDEN_API_KEY="" REDIS_URL="memory://" \
  python -m pytest warden/tests/test_<module>.py -v --tb=short --no-cov
```

### 4. Implement
- Add module under `warden/<area>/`
- Mount router in `warden/main.py` (try/except pattern)
- Add feature key to `warden/billing/feature_gate.py` if tier-gated
- Add Prometheus counter to `warden/metrics.py` if it's a measurable event

### 5. Lint + type-check
```bash
ruff check warden/ --ignore E501
mypy warden/ --ignore-missing-imports --no-strict-optional
```
Fix all errors before continuing. `# noqa` only for documented exceptions.

### 6. Full test suite (coverage gate)
```bash
pytest warden/tests/ --tb=short -m "not adversarial" --cov=warden --cov-fail-under=75
```

### 7. Update docs
- Add row to `ROADMAP.md` with FE/CP/IN number, status=shipped, version
- Update `site/src/components/WhatsNew.astro` if user-facing
- Update `warden/<area>/CLAUDE.md` with new file map entry and any new env vars

### 8. Commit and deploy
```bash
git add <files>
git commit -m "feat(<area>): <description>"
git push origin feat/<slug>
# Open PR → CI must pass → merge → autodeploy via GitHub Actions
```

## Checklist before merge
- [ ] Tests pass (144+ marketplace, 75%+ coverage)
- [ ] Ruff clean
- [ ] Mypy clean
- [ ] ROADMAP.md updated
- [ ] No content logged (grep for `log.*content\|log.*prompt\|log.*text`)
- [ ] Fail-open on all external calls (Redis, Postgres, S3, Anthropic)
