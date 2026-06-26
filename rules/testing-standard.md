# Testing Standard

Load this file when writing, modifying, or debugging tests.

## Required env vars for every test run

```bash
ALLOW_UNAUTHENTICATED=true
WARDEN_API_KEY=""
ANTHROPIC_API_KEY=""          # disables Evolution Engine (no live LLM calls)
LOGS_PATH="/tmp/warden_test_logs.json"
DYNAMIC_RULES_PATH="/tmp/warden_test_dynamic_rules.json"
STRICT_MODE="false"
REDIS_URL="memory://"         # in-memory limiter; no Redis needed
MODEL_CACHE_DIR="/tmp/warden_test_models"
SEMANTIC_THRESHOLD="0.72"
```

All set in `warden/tests/conftest.py`. Tests without these fail on auth or model loading.

## DB isolation (mandatory for marketplace tests)

Every test class that touches SQLite must set its own path via `tmp_path`:
```python
@pytest.fixture(autouse=True)
def _db(self, tmp_path):
    os.environ["MARKETPLACE_DB_PATH"] = str(tmp_path / "mkt.db")
```
Never share `MARKETPLACE_DB_PATH` across test classes — concurrent SQLite writes corrupt the file.

## Pytest markers

| Marker | Meaning | CI behavior |
|--------|---------|-------------|
| `@pytest.mark.slow` | >5s, requires model load | Excluded from default run |
| `@pytest.mark.adversarial` | Live LLM required | Informational (`\|\| true`), never blocks merge |
| `@pytest.mark.integration` | Requires real Redis/Postgres | Skipped in unit test runs |

Default CI run: `-m "not adversarial and not slow"`

## Coverage gate

≥75% overall (`--cov-fail-under=75`). Currently ~74% (post-security-fix additions). Omitted from coverage:
- `warden/analytics/dashboard.py`
- `warden/analytics/siem.py`
- `warden/integrations/langchain_callback.py`
- `warden/tools/browser.py`
- `warden/openai_proxy.py`

## Marketplace test counts (must all pass)

| File | Tests | Focus |
|------|-------|-------|
| `test_marketplace_m2m.py` | 23 | Protocol shape, action dispatcher, fairness guard, Confused Deputy |
| `test_marketplace_three_layer_db.py` | 21 | Layer 2 handoff memory, Layer 3 vector search, sponsored boost |
| `test_marketplace_m2m_lifecycle.py` | 27 | 4-stage lifecycle, Brand Agent, ClearingEngine take rate |
| `test_marketplace_import.py` | 73+ | Import smoke tests, full module surface |

Run all: `pytest warden/tests/test_marketplace*.py -v --tb=short --no-cov -q`

Known pre-existing failure: `test_inject_rule_regex_valid` — unrelated to marketplace code (in `brain/evolve.py` regex safety validation).

## TestClient + tier-gated endpoints

Tier-gated endpoints require the right header:
```python
client.get("/compliance/posture", headers={"X-Tenant-Tier": "pro"})
client.get("/compliance/iso27001", headers={"X-Tenant-Tier": "enterprise"})
```

## BuyerAgent constructor

`agent_id` is required as the first positional argument:
```python
BuyerAgent(agent_id="test-buyer-001", db_path=str(tmp_path / "mkt.db"))
```

## Mutation testing

Runs on `secret_redactor.py` + `semantic_guard.py` only. Threshold: ≤20 surviving mutants. Linux/WSL/CI only — not supported on native Windows.
