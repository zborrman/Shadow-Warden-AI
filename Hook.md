# Hook.md — Docker Pre-commit Hooks

Pre-commit hooks that enforce the Docker Engineering Standards defined in `Rule.md §11` before any commit reaches the remote.

---

## Setup

```bash
# Install pre-commit (once per machine)
pip install pre-commit

# Activate hooks for this repo
pre-commit install
```

All hooks are declared in `.pre-commit-config.yaml` at the repo root (see §5 below).

---

## Hook Catalogue

### Hook 1: check-stage — Multi-Stage Enforcement

Fails if any `Dockerfile*` in the diff does **not** contain at least one `AS builder` stage.

```bash
#!/usr/bin/env bash
# .hooks/check-stage.sh
set -euo pipefail

fail=0
for df in "$@"; do
  if ! grep -qiE '^FROM .+ AS ' "$df"; then
    echo "❌ $df: no named build stage found. Multi-stage builds are required (Rule §11.1)."
    fail=1
  fi
done
exit $fail
```

**What it catches:** Single-stage Dockerfiles that ship SDK + source into production.

---

### Hook 2: check-user — Non-Root Enforcement

Fails if a `Dockerfile*` has no `USER` instruction (i.e. container would run as root).

```bash
#!/usr/bin/env bash
# .hooks/check-user.sh
set -euo pipefail

fail=0
for df in "$@"; do
  if ! grep -qE '^USER ' "$df"; then
    echo "❌ $df: no USER instruction. Services must run as non-root (Rule §11.4)."
    fail=1
  fi
done
exit $fail
```

**What it catches:** Images that default to `root` at runtime — violates Rule §11.4 Security-First.

---

### Hook 3: check-context — Build Context Size Guard

Warns (and optionally fails) if the Docker build context exceeds a configurable threshold.

```bash
#!/usr/bin/env bash
# .hooks/check-context.sh
# Usage: check-context.sh [max_mb]
set -euo pipefail

MAX_MB="${1:-50}"   # default 50 MB

context_bytes=$(tar -czh --exclude='.git' . 2>/dev/null | wc -c)
context_mb=$(( context_bytes / 1024 / 1024 ))

if (( context_mb > MAX_MB )); then
  echo "❌ Docker build context is ${context_mb} MB (limit: ${MAX_MB} MB)."
  echo "   Add patterns to .dockerignore to reduce context (Skill §9.2)."
  exit 1
fi

echo "✅ Docker build context: ${context_mb} MB (within ${MAX_MB} MB limit)."
```

**What it catches:** Forgotten `node_modules/`, `.git/`, build artefacts bloating the context — slows CI and risks leaking secrets.

---

### Hook 4: scan-vulnerabilities — Trivy Image Scan

Runs a Trivy scan against the locally-built image and blocks commit if HIGH or CRITICAL CVEs are found.

```bash
#!/usr/bin/env bash
# .hooks/scan-vulnerabilities.sh
# Requires: trivy CLI on PATH, Docker daemon running
set -euo pipefail

IMAGE="${DOCKER_IMAGE:-shadow-warden:dev}"

echo "🔍 Scanning ${IMAGE} for vulnerabilities..."

trivy image \
  --exit-code 1 \
  --severity HIGH,CRITICAL \
  --no-progress \
  "$IMAGE"
```

Set `DOCKER_IMAGE` in your shell environment to the image tag built by your local dev workflow.

**What it catches:** Known CVEs in base images or installed packages before they enter the repository history.

---

## 5. .pre-commit-config.yaml

```yaml
repos:
  - repo: local
    hooks:
      - id: check-stage
        name: Docker multi-stage check
        language: script
        entry: .hooks/check-stage.sh
        files: (^|/)Dockerfile[^/]*$
        types: [file]

      - id: check-user
        name: Docker non-root user check
        language: script
        entry: .hooks/check-user.sh
        files: (^|/)Dockerfile[^/]*$
        types: [file]

      - id: check-context
        name: Docker build context size
        language: script
        entry: .hooks/check-context.sh
        pass_filenames: false
        always_run: true

      - id: scan-vulnerabilities
        name: Trivy vulnerability scan
        language: script
        entry: .hooks/scan-vulnerabilities.sh
        pass_filenames: false
        stages: [push]          # only on git push, not every commit
```

---

## 6. Docker Improvement ToDo

| # | Task | Owner | Status |
|---|------|-------|--------|
| 1 | Audit all `Dockerfile*` files for single-stage builds | DevOps | ✅ |
| 2 | Add `.dockerignore` to every service that lacks one | Dev | ✅ |
| 3 | Pin all base image versions (no `:latest`) | DevOps | ✅ |
| 4 | Add `USER appuser` + non-root group to every image | Dev | ✅ (UID/GID 10001) |
| 5 | Enable `docker scout` / Trivy in CI pipeline | DevOps | ☐ |
| 6 | Add `HEALTHCHECK` to every service Dockerfile | Dev | ✅ |
| 7 | Integrate `hadolint` as a GitHub Actions step | DevOps | ☐ |

---

## 7. Block D Module Hooks (Q1–Q4 Roadmap)

These hooks guard the five new API modules added in the Block D sprint.

### Hook 5: check-rotation-redis — Rotation Redis Key Guard

Fails if `warden/api/rotation.py` is modified but the Redis key prefix constant is changed from `warden:key_age:`.

```bash
#!/usr/bin/env bash
# .hooks/check-rotation-redis.sh
set -euo pipefail
if git diff --cached warden/api/rotation.py | grep -q 'redis_key\|key_age'; then
  if ! grep -q 'warden:key_age:' warden/api/rotation.py; then
    echo "❌ rotation.py: Redis key prefix must remain 'warden:key_age:' (breaks production key lookup)."
    exit 1
  fi
fi
echo "✅ rotation.py key prefix OK."
```

### Hook 6: check-gdpr-content-log — GDPR No-Content-Log Guard

Fails if any new logging statement in `warden/` logs `content`, `text`, `body`, or `prompt` at INFO/WARNING level (content must never be logged — GDPR Art.5(1)(c)).

```bash
#!/usr/bin/env bash
# .hooks/check-gdpr-content-log.sh
set -euo pipefail
fail=0
for f in $(git diff --cached --name-only | grep '^warden/.*\.py$'); do
  if grep -nE 'log\.(info|warning|error)\([^)]*\b(content|text|body|prompt)\b' "$f"; then
    echo "❌ $f: potential content logging detected. Content must NEVER be logged (GDPR Art.5(1)(c))."
    fail=1
  fi
done
exit $fail
```

### Hook 7: check-action-whitelist-schema — SQLite Schema Guard

Fails if `action_whitelist.py` is modified but the `_SCHEMA` constant no longer contains both required tables.

```bash
#!/usr/bin/env bash
# .hooks/check-whitelist-schema.sh
set -euo pipefail
FILE="warden/agentic/action_whitelist.py"
if git diff --cached --name-only | grep -q "$FILE"; then
  for tbl in agent_action_whitelist agent_action_rate; do
    if ! grep -q "CREATE TABLE IF NOT EXISTS $tbl" "$FILE"; then
      echo "❌ $FILE: missing required table '$tbl' in _SCHEMA."
      exit 1
    fi
  done
fi
echo "✅ action_whitelist schema OK."
```

Add all three to `.pre-commit-config.yaml`:
```yaml
      - id: check-rotation-redis
        name: Rotation Redis key prefix guard
        language: script
        entry: .hooks/check-rotation-redis.sh
        files: warden/api/rotation\.py

      - id: check-gdpr-content-log
        name: GDPR no-content-log guard
        language: script
        entry: .hooks/check-gdpr-content-log.sh
        files: ^warden/.*\.py$

      - id: check-whitelist-schema
        name: Action whitelist SQLite schema guard
        language: script
        entry: .hooks/check-whitelist-schema.sh
        files: warden/agentic/action_whitelist\.py
```

---

## 7. SMB Compose Hook

A lightweight hook for `docker-compose.smb.yml` — verifies the SMB stack before pushing.

```bash
#!/usr/bin/env bash
# .hooks/check-smb-compose.sh
set -euo pipefail

COMPOSE="docker-compose.smb.yml"
if [[ ! -f "$COMPOSE" ]]; then
  echo "❌ $COMPOSE missing — required for Community Business deployment."
  exit 1
fi

# Ensure no enterprise-only services (minio, prometheus, grafana) leak in
for svc in minio prometheus grafana; do
  if grep -q "^  ${svc}:" "$COMPOSE"; then
    echo "❌ $COMPOSE contains enterprise service '${svc}' — remove from SMB stack."
    exit 1
  fi
done

echo "✅ $COMPOSE: SMB stack clean."
```

Add to `.pre-commit-config.yaml`:
```yaml
      - id: check-smb-compose
        name: SMB Compose guard
        language: script
        entry: .hooks/check-smb-compose.sh
        pass_filenames: false
        files: docker-compose\.smb\.yml
```

---

---

## 8. CI / Lint / Type Hooks (v4.13)

These hooks mirror the CI gate added in Block K.

### Hook 8: check-ruff — Ruff Lint Guard

Fails if `ruff check` produces any error in `warden/` or `analytics/`.

```bash
#!/usr/bin/env bash
# .hooks/check-ruff.sh
set -euo pipefail
ruff check warden/ analytics/ --ignore E501
```

Add to `.pre-commit-config.yaml`:
```yaml
      - id: check-ruff
        name: Ruff lint gate
        language: script
        entry: .hooks/check-ruff.sh
        pass_filenames: false
        files: ^(warden|analytics)/.*\.py$
```

---

### Hook 9: check-mypy — Mypy Type Gate

Fails if mypy reports `attr-defined` or `assignment` errors in `warden/`.

```bash
#!/usr/bin/env bash
# .hooks/check-mypy.sh
set -euo pipefail
mypy warden/ --ignore-missing-imports --no-strict-optional
```

Add to `.pre-commit-config.yaml`:
```yaml
      - id: check-mypy
        name: Mypy type gate
        language: script
        entry: .hooks/check-mypy.sh
        pass_filenames: false
        files: ^warden/.*\.py$
```

---

### Hook 10: check-pip-resilience — python3 -m pip Enforcement

Fails if any `Dockerfile*` in the diff uses bare `pip install` instead of
`python3 -m pip install` — bare `pip` is not on PATH in some base images
and causes CI exit 127.

```bash
#!/usr/bin/env bash
# .hooks/check-pip-resilience.sh
set -euo pipefail
fail=0
for df in "$@"; do
  if grep -nE '^\s*RUN pip install' "$df"; then
    echo "❌ $df: use 'python3 -m pip install' instead of bare 'pip install' (PATH-resilient)."
    fail=1
  fi
done
exit $fail
```

Add to `.pre-commit-config.yaml`:
```yaml
      - id: check-pip-resilience
        name: python3 -m pip enforcement
        language: script
        entry: .hooks/check-pip-resilience.sh
        files: (^|/)Dockerfile[^/]*$
        types: [file]
```

---

*Hook.md last updated: 2026-05-16 — v4.20: Community & Tunnel web app, castle logo branding*
