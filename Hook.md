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
| 1 | Audit all `Dockerfile*` files for single-stage builds | DevOps | ☐ |
| 2 | Add `.dockerignore` to every service that lacks one | Dev | ☐ |
| 3 | Pin all base image versions (no `:latest`) | DevOps | ☐ |
| 4 | Add `USER appuser` + non-root group to every image | Dev | ☐ |
| 5 | Enable `docker scout` / Trivy in CI pipeline | DevOps | ☐ |
| 6 | Add `HEALTHCHECK` to every service Dockerfile | Dev | ☐ |
| 7 | Integrate `hadolint` as a GitHub Actions step | DevOps | ☐ |

---

*Hook.md last updated: 2026-03 — Docker Desktop Pro alignment*
