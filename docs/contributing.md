# Contributing

## Development Setup

```bash
git clone https://github.com/zborrman/Shadow-Warden-AI.git
cd Shadow-Warden-AI
pip install -e ".[dev]" -r warden/requirements.txt
pre-commit install
```

## Running Tests

```bash
pytest warden/tests/ -v --tb=short -m "not adversarial and not slow"
```

Full coverage gate (≥75%):

```bash
pytest warden/tests/ --tb=short -m "not adversarial" --cov=warden --cov-fail-under=75
```

## Lint

```bash
ruff check warden/ --ignore E501
mypy warden/ --ignore-missing-imports --no-strict-optional
```

## Commit Convention

```
feat(scope): short description
fix(scope):  short description
docs(scope): short description
```

## Pre-commit Hooks

All 7 hooks from [Hook.md](Hook.md) are installed. Key ones:

- `detect-secrets` — blocks accidental credential commits
- `idempotency-key` — AST check: payment calls must pass `idempotency_key=`
- `fail-open-lint` — blocks bare `except: pass` without `logger.warning()`
- `tenant-isolation` — advisory: warns on DB queries missing `tenant_id`

Bypass with justification (audit-logged):

```bash
SKIP_SECRET_SCAN=1 git commit -m "docs: update example key in quickstart"
```

## Code Style

- Python 3.11+ (`match/case`, `X | Y` union types)
- Ruff: `line-length=100`
- No docstrings required unless the WHY is non-obvious
- No multi-paragraph comment blocks
- Fail-open pattern for all external deps
