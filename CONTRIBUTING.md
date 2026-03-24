# Contributing to Shadow Warden AI

Shadow Warden is a security-critical project.  Every line of code runs in front of real AI workloads.  These guidelines exist to keep the codebase safe, fast, and reviewable.

---

## Before You Start

1. **Open an issue first** for anything beyond a typo fix.  Describe the problem, not just the solution.  This avoids duplicate effort and lets maintainers flag scope issues before you spend time coding.
2. **One concern per PR.**  A single PR that fixes a bug and adds a feature is two PRs.
3. **Read the architecture docs** before touching core pipeline stages: [`docs/pipeline-anatomy.md`](docs/pipeline-anatomy.md) and the key-files table in [`CLAUDE.md`](CLAUDE.md).

---

## Development Setup

```bash
# Clone and install in editable mode
git clone https://github.com/zborrman/Shadow-Warden-AI.git
cd Shadow-Warden-AI

pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[dev]"
pip install -r warden/requirements.txt

# Run the test suite (no live services needed)
pytest warden/tests/ -v --tb=short -m "not adversarial and not slow"
```

Required environment for tests (already set in `warden/tests/conftest.py`):

```
ANTHROPIC_API_KEY=""
WARDEN_API_KEY=""
REDIS_URL="memory://"
MODEL_CACHE_DIR="/tmp/warden_test_models"
```

---

## The Non-Negotiables

### No "phone home"

Every component must have an **offline mode**.  If your code calls an external API, it must:
- Fail gracefully (log a warning, return a safe default) when the service is unreachable
- Be disableable via an environment variable (pattern: empty string = disabled)
- Never block the main request pipeline — use async background tasks

Rationale: air-gapped enterprise deployments are a supported configuration.

### GDPR: content is never logged

`warden/analytics/logger.py` logs metadata only.  Do not log, cache, or persist prompt content, response content, or raw PII anywhere in the codebase.  This is a hard architectural constraint, not a style preference.

Accepted: `payload_tokens`, `risk_level`, `flags`, `secrets_found` (type names only)
Rejected: `payload_content`, `filtered_content`, `raw_prompt`, anything that is the actual text

### Latency budget

The full text pipeline (cache miss, no multimodal) must stay under **50 ms p95** on a standard developer laptop (2020-era, CPU-only).

- If your change adds > 5 ms to the hot path, it needs a benchmark and justification in the PR description
- Expensive operations belong in background tasks (`asyncio.create_task`, `ThreadPoolExecutor`) or separate endpoints
- Never call `time.sleep()` or block the event loop in request handlers

### CPU-only ML

The project targets CPU-only hardware.  Do not add GPU-required dependencies or CUDA-specific code paths.  Torch must be installed via:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

---

## Test Requirements

### Coverage gate

PRs must not drop coverage below **75%**.  Check locally:

```bash
pytest warden/tests/ --tb=short -m "not adversarial" \
    --cov=warden --cov-fail-under=75
```

### Test-Driven Development

New behaviour = new test.  The test should be written to describe the requirement, not just to exercise the implementation.  If you can delete your code and the test still passes, the test is wrong.

### Test isolation

- No real Redis — use `REDIS_URL=memory://` or the `_FakeRedis` fixture in `pre_release_final_test.py`
- No real Anthropic API — `ANTHROPIC_API_KEY=""` disables the Evolution Engine
- No filesystem side effects — use `tmp_path` (pytest fixture) for any file I/O
- No `time.sleep()` in tests

### Markers

```python
@pytest.mark.adversarial   # Known-hard attacks; informational, not blocking
@pytest.mark.slow          # > 5 s; skipped in standard CI run
@pytest.mark.integration   # Requires the full app stack (TestClient or live)
```

---

## Code Style

- **Python 3.11+** — match/case, `X | Y` unions, and `tomllib` are available
- **Ruff:** `line-length=100`, ruleset `E,F,W,I,N,UP,B,C4,SIM`, ignore `E501,B008`
- **No docstrings required** on code you did not write.  Add a docstring if the function's contract is non-obvious and there is no test that documents it
- **No type annotations required** beyond what the existing code uses.  Pydantic models and `@dataclass` fields are an exception

Lint check:

```bash
ruff check warden/ analytics/ --ignore E501
mypy warden/ --ignore-missing-imports --no-strict-optional
```

---

## Security-Specific Guidelines

### New threat patterns

Adding a regex to `_THREAT_PATTERNS` in `tool_guard.py` or `semantic_guard.py`:
- Provide at least one positive example (should match) and one negative example (should not match) in the PR description
- Mark `applies_to` correctly: `"call"` for outgoing tool arguments, `"result"` for incoming tool results, `"both"` for content that can appear in either
- Avoid catastrophic backtracking — test your regex against a 10 KB string of random input

### Evolution Engine rules

Do not modify `warden/brain/evolve.py` to broaden what Claude Opus is allowed to generate.  The corpus poisoning protections (growth cap, dedup cap, vetting prompt) are deliberate.

### Secrets

Never commit real API keys, tokens, or credentials — not even in test fixtures.  Use placeholder strings like `sk-test-...` in examples.  CI runs `gitleaks` on every push.

---

## Pull Request Checklist

Before marking a PR as ready for review:

- [ ] `pytest warden/tests/ -m "not adversarial and not slow"` passes locally
- [ ] Coverage has not dropped below 75%
- [ ] `ruff check` and `mypy` pass with no new errors
- [ ] No new external service calls without an offline fallback
- [ ] No prompt/response content is persisted or logged
- [ ] PR description explains **why**, not just **what**
- [ ] If a new env var is introduced, it is documented in `.env.example`
- [ ] If the pipeline is modified, `docs/pipeline-anatomy.md` is updated

---

## Commit Style

```
type(scope): short imperative description

Optional body explaining why, not what.
```

Types: `feat`, `fix`, `test`, `docs`, `refactor`, `perf`, `ci`, `chore`

Example:

```
fix(ers): use make_entity_key for TestClient caller in L3d test

/ers/score derives entity_key from tenant+IP, not a query param.
TestClient.client.host == "testclient", so the test must record events
under make_entity_key("default", "testclient") for the assertion to hold.
```

---

## Where to Get Help

- Open a [GitHub Discussion](https://github.com/zborrman/Shadow-Warden-AI/discussions) for questions
- Open an [Issue](https://github.com/zborrman/Shadow-Warden-AI/issues) for bugs or feature requests
- See [`docs/pipeline-anatomy.md`](docs/pipeline-anatomy.md) for architecture questions
- See [`docs/deployment-guide.md`](docs/deployment-guide.md) for infrastructure questions
