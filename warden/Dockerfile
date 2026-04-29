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
FROM python:3.11-slim

WORKDIR /warden

# System deps — apt cache mount avoids re-downloading packages on every build.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libgomp1 curl gosu git \
        cmake ninja-build libssl-dev astyle \
    && rm -rf /var/lib/apt/lists/*

# ── Python deps (three-step: liboqs → torch CPU-only → everything else) ─────
COPY requirements.txt .

# Step 1 — liboqs-python (Post-Quantum Cryptography — NIST FIPS 203/204).
#   Builds liboqs C library from source via cmake (~60s first time, cached after).
#   Fail-open: || true so the build continues even if liboqs is unavailable.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install liboqs-python || \
    echo "⚠ liboqs-python build failed — PQC disabled (classical crypto still active)"

# Step 2 — torch from the CPU-only wheel index (~800 MB wheel, cached after first pull).
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install torch --index-url https://download.pytorch.org/whl/cpu

# Step 3 — everything else from PyPI.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

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
