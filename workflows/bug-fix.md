# Workflow: Bug Fix

## Steps

### 1. Reproduce
Write a failing test that captures the exact bug before touching any code:
```bash
pytest warden/tests/test_<module>.py::test_<bug_name> -v --tb=long --no-cov
```
If the test passes immediately, the bug is already fixed or the test is wrong.

### 2. Isolate
```bash
git stash          # confirm the test fails on main
git stash pop      # restore work
```
Check `git log --oneline -20` — if the bug was introduced in a recent commit, `git bisect` is faster than reading code.

### 3. Fix
Minimal change only. Do not refactor surrounding code or add unrelated improvements.

### 4. Confirm green
```bash
pytest warden/tests/test_<module>.py -v --tb=short --no-cov
```

### 5. Regression check
```bash
pytest warden/tests/ --tb=short -m "not adversarial and not slow" --no-cov -q
```
No new failures allowed.

### 6. Lint
```bash
ruff check warden/<area>/ --ignore E501
```

### 7. Commit
```bash
git commit -m "fix(<area>): <what was broken and why>"
```
The commit message should explain the root cause, not just "fixed bug".

## Common bug patterns in this codebase

| Symptom | Likely cause |
|---------|-------------|
| `no such column: is_sponsored` | New column added to schema but `ALTER TABLE` migration missing in the code path that bypasses `_conn()` |
| `assert ok is True` in evolution tests | `_validate_regex_safety()` rejecting the pattern — test the pattern against 8000-char degenerate string |
| Redis `ConnectionError` in tests | Missing `REDIS_URL=memory://` in test env |
| `RuntimeError: WARDEN_API_KEY` | Missing `ALLOW_UNAUTHENTICATED=true` in test env |
| `model not found` errors | Missing `MODEL_CACHE_DIR=/tmp/warden_test_models` |
| pgvector query disables HNSW | Computed expression in `ORDER BY` — move boost logic to Python |
| `float` precision errors in billing | Used `float` instead of `Decimal` math |
