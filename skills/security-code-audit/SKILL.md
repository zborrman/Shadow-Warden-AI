# Skill: Security Code Audit — Marketplace

**Purpose:** Systematic security review of the Shadow Warden marketplace codebase. Covers SQL injection, x402 header validation, Confused Deputy, auth bypass, and MAESTRO threat detection gaps.

---

## When to invoke

- Before merging any PR that touches `warden/marketplace/`
- After adding a new action type to `POST /marketplace/action`
- When a new MCP tool is wired to marketplace DB access
- On a monthly schedule (SOVA `sova_corpus_watchdog` can trigger this)

---

## Audit checklist (run in order)

### 1. SQL injection surface

```bash
# Find all f-string SQL patterns
grep -rn "f\".*SELECT\|f\".*INSERT\|f\".*UPDATE\|f\".*DELETE" warden/marketplace/ --include="*.py"
```

**Safe pattern** — f-string only interpolates Python-hardcoded clause strings, values are `?` params:
```python
# SAFE: type_clause is built from Python constants, not user input
f"SELECT ... WHERE 1=1 {type_clause} LIMIT ?"
```

**Dangerous pattern** — user-controlled string in SQL:
```python
f"SELECT ... WHERE name = '{user_input}'"   # NEVER
```

Check `analytics.py` `_pw()` helper specifically: verify every element in `l_where`, `p_where`, `e_where` is a Python literal string, never a value derived from request body.

### 2. x402 header validation

```bash
grep -n "PAYMENT-SIGNATURE\|PAYMENT-REQUIRED\|X-Payment" warden/marketplace/x402_gate.py
```

Verify:
- Server sends `PAYMENT-REQUIRED` (not `X-Payment-Required`)
- Client sends `PAYMENT-SIGNATURE` (not `X-Payment-Signature` or `X-Payment-Token`)
- `_parse_payment_signature()` returns `None` on any parse error (fail-open, not 500)
- `require_payment()` wraps everything in `try/except Exception` (fail-open)

### 3. Confused Deputy guard

```bash
grep -n "_confused_deputy_check\|_AGENT_ID_COLUMNS" warden/marketplace/api.py
```

Verify:
- `_AGENT_ID_COLUMNS` includes all DID-bearing column names: `agent_id`, `buyer_agent`, `seller_agent`, `caller_agent_id`
- The check fires when `caller_agent_id` is provided (body OR `X-Agent-ID` header)
- Regex pattern correctly handles single and double quote delimiters

### 4. Auth bypass paths

```bash
grep -n "ALLOW_UNAUTHENTICATED\|WARDEN_API_KEY" warden/main.py | head -20
```

Verify:
- `ALLOW_UNAUTHENTICATED=true` is only read once at startup, never per-request
- No endpoint bypasses `_require_marketplace_gate()` via a different route prefix
- `X-Admin-Key` endpoints (`/listings/{id}/sponsor`, `/billing/addons/grant`) check `ADMIN_KEY` with constant-time compare

### 5. Bare `except: pass` audit

```bash
python3 -c "
import ast, os
for root, _, files in os.walk('warden/marketplace'):
    for f in files:
        if not f.endswith('.py'): continue
        src = open(os.path.join(root,f)).read()
        tree = ast.parse(src)
        for n in ast.walk(tree):
            if isinstance(n, ast.ExceptHandler) and len(n.body)==1 and isinstance(n.body[0], ast.Pass):
                print(f'{root}/{f}:{n.lineno}')
"
```

**Allowed** (by design): MAESTRO isolation steps, SQLite `ALTER TABLE` migrations, `contextlib.suppress(Exception)`
**Must fix**: security gates (Sybil check, chain validation, auth guard) — add `log.warning()`

### 6. Decimal math in billing

```bash
grep -rn "price.*\*\|fee.*\*\|amount.*\*" warden/marketplace/clearing.py warden/marketplace/escrow.py
```

Every multiplication/division involving money must use `Decimal`, not `float`. Flag any `float(x) * rate` pattern.

### 7. MAESTRO coverage

```bash
grep -n "GoalMisalignment\|Collusion\|ModelPoisoning\|_run_isolation" warden/marketplace/maestro.py | wc -l
```

Must have all 3 detectors active. Check `_run_isolation_pipeline()` calls all 7 isolation steps in sequence even if one fails (fail-open, not fail-stop).

---

## Auto-fix commands

```bash
# Fix import order + unused imports
ruff check warden/marketplace/ --ignore E501 --fix

# Type errors
mypy warden/marketplace/ --ignore-missing-imports --no-strict-optional

# Full test suite (must stay 144+ passed)
ALLOW_UNAUTHENTICATED=true WARDEN_API_KEY="" REDIS_URL="memory://" \
  pytest warden/tests/test_marketplace*.py -v --tb=short --no-cov -q
```

---

## Escalation criteria

| Finding | Action |
|---------|--------|
| f-string with user input in SQL | BLOCK — fix before merge, create test |
| Wrong x402 header name | BLOCK — fix immediately, update CLAUDE.md rule #15 |
| Missing Confused Deputy for new column | HIGH — add column to `_AGENT_ID_COLUMNS` |
| New bare `except: pass` in security gate | MEDIUM — add `log.warning()` |
| Float math in take rate or escrow | HIGH — convert to `Decimal` |
