# ─────────────────────────────────────────────────────────────────────────────
#  Shadow Warden AI — Warden Gateway  (slim build)
#
#  Base: python:3.11-slim  (~130 MB vs ~1.8 GB playwright/python MCR image)
#
#  BuildKit required (DOCKER_BUILDKIT=1 or Docker Desktop ≥4.x default).
#  Cache mounts keep pip/apt caches across rebuilds → code-only change: ~30s.
#
#  Browser sandbox (warden/tools/browser.py) is DEFERRED.
#  To re-enable when server disk allows:
#    1. Switch FROM back to: mcr.microsoft.com/playwright/python:v1.49.0-noble
#    2. Add after pip installs: RUN playwright install chromium
#    3. Set BROWSER_ENABLED=true in docker-compose.yml
# ─────────────────────────────────────────────────────────────────────────────
# syntax=docker/dockerfile:1.7
FROM python:3.14-slim

WORKDIR /warden

# System deps — apt cache mount avoids re-downloading packages on every build.
# postgresql-client (R1 backups): the base image's own repo ships v17, which is
# newer than the timescale/timescaledb:latest-pg16 server — pg_dump/pg_restore
# support dumping from an older major server than the client, so no PGDG repo
# is needed. (Do NOT pin postgresql-client-16 via PGDG: on this base image's
# codename, PGDG's libpq5 conflicts with the system libldap, and apt fails.)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libgomp1 curl gosu git \
        cmake ninja-build libssl-dev astyle \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# ── Python deps (three-step: liboqs → torch CPU-only → everything else) ─────
#
#  DETERMINISM (P-0): requirements.txt states *intent* (floors, `>=`), while
#  constraints.txt is the lockfile that decides the actual resolved version of
#  every package. CI has installed with `-c constraints.txt` for a while; this
#  image did not, so the two drifted — on 2026-07-26 that drift put
#  prometheus-fastapi-instrumentator 8.1.0 into production while CI had tested
#  8.0.2, and its changed `_get_route_name` arity 502'd the whole API. A
#  measurement taken the next day found 48 packages differing between the
#  CI-tested set and the running production image.
#
#  Rule: every pip install on this image's critical path is version-decided —
#  either an explicit `==` here, or via `-c constraints.txt`. Enforced by
#  warden/tests/test_deps_pinned.py.
COPY requirements.txt constraints.txt ./

# Step 1 — liboqs-python (Post-Quantum Cryptography — NIST FIPS 203/204).
#   Builds liboqs C library from source via cmake (~60s first time, cached after).
#   Fail-open: the build continues even if liboqs is unavailable (classical
#   crypto still works) — but the *version* is pinned, so a successful build is
#   always the same build. Not in constraints.txt: it is a source build outside
#   the PyPI resolution done in step 3.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install "liboqs-python==0.16.0" || \
    echo "⚠ liboqs-python build failed — PQC disabled (classical crypto still active)"

# Step 2 — torch from the CPU-only wheel index (~800 MB wheel, cached after first pull).
#   Pinned explicitly rather than via constraints.txt: the `+cpu` local version
#   only exists on the PyTorch CPU index, so it cannot be resolved from PyPI and
#   is deliberately excluded from the constraints file (see its header).
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install "torch==2.13.0+cpu" --index-url https://download.pytorch.org/whl/cpu

# Step 3 — everything else from PyPI, version-decided by the lockfile.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt -c constraints.txt

# ── Non-root runtime user ─────────────────────────────────────────────────────
RUN addgroup --system --gid 10001 warden \
    && adduser --system --uid 10001 --gid 10001 --no-create-home wardenuser

# ── Application source ────────────────────────────────────────────────────────
ARG GIT_SHA=dev
COPY --chown=wardenuser:warden . .

RUN mkdir -p /warden/models /warden/data \
    && chown -R wardenuser:warden /warden/models /warden/data \
    && chmod -R 755 /warden/models /warden/data

# ── Runtime environment ───────────────────────────────────────────────────────
ENV MODEL_CACHE_DIR=/warden/models
ENV HF_HOME=/warden/models
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/
ENV BROWSER_ENABLED=false

# NOTE: We do NOT set USER here. The entrypoint runs as root so it can fix
# bind-mount directory ownership (Docker volumes arrive owned by root when
# the host directory was created outside the container). After fixing perms
# it execs uvicorn as wardenuser via gosu — same pattern as postgres/redis.

EXPOSE 8001

ENTRYPOINT ["/bin/bash", "/warden/entrypoint.sh"]
