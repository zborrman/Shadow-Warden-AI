# Contributing to Shadow Warden AI

**Version 4.7 · Last updated 2026-04**

Shadow Warden is a security-critical project. Every line of code runs in front of real AI workloads across 9 filter layers, 153 modules, and 11 Docker services. These guidelines keep the codebase safe, fast, and reviewable.

---

## Before You Start

1. **Open an issue first** for anything beyond a typo fix. Describe the problem, not just the solution. This avoids duplicate effort and lets maintainers flag scope issues before you spend time coding.
2. **One concern per PR.** A single PR that fixes a bug and adds a feature is two PRs.
3. **Read the architecture docs** before touching core pipeline stages: [`docs/pipeline-anatomy.md`](docs/pipeline-anatomy.md) and the key-files table in [`CLAUDE.md`](CLAUDE.md).
4. **Access requires a license agreement.** This is proprietary software. If you do not have an executed agreement with Shadow Warden AI, you are not authorized to submit contributions. See [LICENSE](LICENSE).

---

## Development Setup

```bash
# Clone and install in editable mode
git clone https://github.com/zborrman/Shadow-Warden-AI.git
cd Shadow-Warden-AI

# CPU-only torch is mandatory — CUDA variants are not supported
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[dev]"
pip install -r warden/requirements.txt

# Install pre-commit hooks (Docker + GDPR guards)
pip install pre-commit
pre-commit install

# Run the test suite (no live services needed)
pytest warden/tests/ -v --tb=short -m "not adversarial and not slow"
```

Required environment variables for tests (already set in `warden/tests/conftest.py`):

```
ANTHROPIC_API_KEY=""           # disables Evolution Engine (air-gap mode)
WARDEN_API_KEY=""              # disables auth
REDIS_URL="memory://"          # in-process rate limiting — no Redis needed
MODEL_CACHE_DIR="/tmp/warden_test_models"
LOGS_PATH="/tmp/warden_test_logs.json"
DYNAMIC_RULES_PATH="/tmp/warden_test_dynamic_rules.json"
```

Optional — only needed for specific subsystems:

```
LIBOQS_AVAILABLE=false         # skip PQC tests if liboqs-python not installed
SEP_DB_PATH="/tmp/warden_sep.db"
```

---

## The Non-Negotiables

### GDPR: Content is never logged (G-01)

`warden/analytics/logger.py` logs **metadata only**. Do not log, cache, persist, or transmit prompt content, response content, or raw PII anywhere in the codebase. This is a hard architectural constraint, not a style preference.

| Allowed | Forbidden |
|---------|-----------|
| `payload_tokens`, `risk_level`, `flags` | `payload_content`, `raw_prompt` |
| `secrets_found` (count + type, no value) | `secret_value`, `matched_text` |
| `latency_ms`, `request_id`, `tenant_id` | `request_body`, `response_body` |

The pre-commit hook `check-gdpr-content-log` (.hooks/check-gdpr-content-log.sh) will block commits that violate this rule.

### Atomic writes (G-02)

All writes to `logs.json`, `dynamic_rules.json`, or any config file must use `tempfile.mkstemp()` + `os.replace()`. Direct `open(..., 'w')` writes are not allowed on persistent state files.

### No "phone home" — offline mode required (O-01)

Every component must have an offline mode. If your code calls an external API:

- Fail gracefully (log a warning, return a safe default) when the service is unreachable
- Disableable via environment variable (pattern: empty string = disabled)
- Never block the main request pipeline — use async background tasks
- Call `require_online(feature)` before any LLM or external API call in optional code paths

All 9 filter layers must remain functional when `OFFLINE_MODE=true`.

### Latency budget

The full text pipeline (cache miss, no multimodal) must stay under **50 ms p95** on standard CPU-only hardware.

- Changes that add > 5 ms to the hot path require a benchmark and justification in the PR
- Expensive operations belong in background tasks (`asyncio.create_task`) or separate endpoints
- Never call `time.sleep()` or block the event loop in request handlers

### CPU-only ML (D-05)

Do not add GPU-required dependencies or CUDA-specific code paths. Torch must be installed via:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

### Tier gates (F-04)

New features that are tier-restricted must use the existing gate dependencies:

```python
from warden.billing.feature_gate import require_feature
from warden.billing.addons import require_addon_or_feature

# HTTP 403 = tier too low; HTTP 402 = add-on not purchased
Depends(require_feature("sovereign_enabled"))
Depends(require_addon_or_feature("shadow_ai_enabled", "shadow_ai_discovery", "pro"))
```

Do not implement ad-hoc tier checks.

### Security constants (S-01 – S-07)

- No raw SQL string concatenation — parameterised statements only
- No `eval()` or `exec()` in `warden/`
- All API key comparisons: `hmac.compare_digest()`
- Admin endpoints require `_require_admin()` dependency
- Secrets at rest: Fernet encryption — no plaintext in Redis or SQLite

---

## Test Requirements

### Coverage gate (T-01)

PRs must not drop coverage below **75%**. Check locally:

```bash
pytest warden/tests/ --tb=short -m "not adversarial" \
    --cov=warden --cov-fail-under=75
```

Current coverage: **76.31%**. The margin is narrow — new code without tests will fail CI.

### SWFE Fake Layer (T-05)

Use the Shadow Warden Fake Environment (SWFE) for external service isolation. Do not mock the database.

| Service | Fake |
|---------|------|
| Anthropic Claude | `warden/testing/fakes/anthropic.py` — `FakeAnthropicClient` |
| NVIDIA Nemotron | `warden/testing/fakes/nvidia.py` — `FakeNvidiaClient` |
| S3 / MinIO | `warden/testing/fakes/s3.py` — `FakeS3Storage` |
| Evolution Engine | `warden/testing/fakes/evolution.py` — `FakeEvolutionEngine` |

Activate via `FakeContext` in `warden/testing/context.py`:

```python
from warden.testing.context import FakeContext

def test_something():
    with FakeContext(anthropic=True, s3=True):
        # Anthropic + S3 calls are intercepted by fakes
        ...
```

### Test isolation (T-02 – T-04)

- `REDIS_URL=memory://` — in-process rate limiting, no live Redis
- `ANTHROPIC_API_KEY=""` — disables Evolution Engine; use `FakeAnthropicClient` where needed
- `MODEL_CACHE_DIR=/tmp/warden_test_models` — prevents Docker-only path access
- Use `tmp_path` (pytest fixture) for all file I/O
- No `time.sleep()` in tests

### Pytest markers

```python
@pytest.mark.adversarial   # Known-hard attacks; informational, CI uses || true
@pytest.mark.slow          # > 5 s; excluded from standard CI run
@pytest.mark.integration   # Requires full app stack (TestClient or live services)
```

### Mutation testing (T-06)

Changes to `secret_redactor.py` or `semantic_guard.py` must not increase surviving mutants above 20:

```bash
# Linux/WSL/CI only — not supported on native Windows
mutmut run --no-progress
```

---

## Pre-commit Hooks

Install with `pre-commit install`. Hooks that run on every commit:

| Hook | What it checks |
|------|---------------|
| `check-stage` | Every `Dockerfile*` has an `AS builder` multi-stage build |
| `check-user` | Every `Dockerfile*` has a `USER` instruction (non-root) |
| `check-gdpr-content-log` | No `log.info/warning` with content/body/prompt in `warden/` |
| `check-rotation-redis` | `rotation.py` Redis key prefix stays `warden:key_age:` |
| `check-whitelist-schema` | `action_whitelist.py` schema has both required tables |
| `check-smb-compose` | `docker-compose.smb.yml` excludes enterprise-only services |

The `scan-vulnerabilities` hook (Trivy) runs on `git push` only.

---

## Code Style

- **Python 3.11+** — `match/case`, `X | Y` unions, `tomllib` are available
- **Ruff:** `line-length=100`, ruleset `E,F,W,I,N,UP,B,C4,SIM`, ignore `E501,B008`
- **Imports:** stdlib → third-party → internal (I001 enforced by Ruff)
- **No docstrings required** on code you did not write
- **No type annotations required** beyond existing usage; Pydantic/dataclass fields are the exception
- **No comments** unless the WHY is non-obvious (a hidden constraint, a workaround for a specific bug)

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
- Mark `applies_to` correctly: `"call"` / `"result"` / `"both"`
- Test against a 10 KB random string to rule out catastrophic backtracking

### Evolution Engine (evolve.py)

Do not modify `warden/brain/evolve.py` to broaden what Claude Opus is allowed to generate. The corpus poisoning protections (growth cap, dedup cap, vetting prompt) are deliberate. Changes require explicit sign-off from a maintainer.

### SEP / Communities

Changes to `warden/communities/` must preserve:

- STIX 2.1 audit chain integrity (`stix_audit.append_transfer()` called on every transfer, including REJECTED)
- Causal Transfer Guard invocation before `transfer_entity()` completes
- UECIID format: `SEP-{11 base-62 chars}` — do not change the Snowflake epoch or alphabet

### PQC (Post-Quantum Crypto)

Changes to `warden/crypto/pqc.py` must preserve the `_OQS_AVAILABLE` fail-open guard. Classical Ed25519/X25519 must work when `liboqs-python` is not installed. PQC features are Enterprise-only — do not remove the `pqc_enabled` feature gate.

### Secrets

Never commit real API keys, tokens, or credentials — not even in test fixtures. Use placeholder strings like `sk-test-...`. CI runs `gitleaks` on every push.

---

## Docker Standards

| Rule | Requirement |
|------|-------------|
| D-01 | Multi-stage builds — at least one `AS builder` stage |
| D-02 | Non-root runtime — UID/GID 10001 (`wardenuser`) |
| D-03 | Pinned base images — no `:latest` tags |
| D-04 | `HEALTHCHECK` in every service Dockerfile |
| D-05 | CPU-only torch — `--index-url https://download.pytorch.org/whl/cpu` |
| D-07 | SMB compose — `docker-compose.smb.yml` must not include `minio`, `prometheus`, `grafana` |

---

## Pull Request Checklist

- [ ] `pytest warden/tests/ -m "not adversarial and not slow"` passes locally
- [ ] Coverage has not dropped below 75%
- [ ] `ruff check` and `mypy` pass with no new errors
- [ ] Pre-commit hooks pass (`pre-commit run --all-files`)
- [ ] No new external service calls without an offline fallback
- [ ] No prompt/response content is persisted or logged
- [ ] New tier-restricted features use `require_feature()` / `require_addon_or_feature()`
- [ ] PR description explains **why**, not just **what**
- [ ] If a new env var is introduced, it is documented in `.env.example`
- [ ] If the `/filter` pipeline is modified, `docs/pipeline-anatomy.md` is updated
- [ ] If a new admin endpoint is added, `_require_admin()` dependency is present

---

## Commit Style

```
type(scope): short imperative description

Optional body explaining why, not what.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
```

Types: `feat`, `fix`, `test`, `docs`, `refactor`, `perf`, `ci`, `chore`

Scopes map to subsystems: `filter`, `brain`, `ers`, `sova`, `master`, `sep`, `pqc`, `sovereign`, `shadow-ai`, `xai`, `smb`, `billing`, `ci`, `landing`

Example:

```
fix(ers): use make_entity_key for TestClient caller in L3d test

/ers/score derives entity_key from tenant+IP, not a query param.
TestClient.client.host == "testclient", so the test must record events
under make_entity_key("default", "testclient") for the assertion to hold.
```

---

## Where to Get Help

- [GitHub Discussions](https://github.com/zborrman/Shadow-Warden-AI/discussions) — questions and design conversations
- [GitHub Issues](https://github.com/zborrman/Shadow-Warden-AI/issues) — bugs and feature requests
- [`docs/pipeline-anatomy.md`](docs/pipeline-anatomy.md) — architecture questions
- [`docs/security-model.md`](docs/security-model.md) — threat model and OWASP LLM coverage
- [`CLAUDE.md`](CLAUDE.md) — key files table, design constraints, build commands
- [`Rull.md`](Rull.md) — full engineering standards reference (§1–§10)
- [`Skill.md`](Skill.md) — 22 discrete skills and architectural patterns
