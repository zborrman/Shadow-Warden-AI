# ─────────────────────────────────────────────────────────────────────────────
#  Shadow Warden AI — Warden Gateway  (slim build)
#
#  Base: python:3.11-slim  (~130 MB vs ~1.8 GB playwright/python MCR image)
#
#  Browser sandbox (warden/tools/browser.py) is DEFERRED.
#  To re-enable when server disk allows:
#    1. Switch FROM back to: mcr.microsoft.com/playwright/python:v1.49.0-noble
#    2. Add after pip installs: RUN playwright install chromium
#    3. Set BROWSER_ENABLED=true in docker-compose.yml
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /warden

# System deps:
#   gcc / g++   — compile C extensions in pip packages
#   libgomp1    — OpenMP required by torch CPU
#   curl        — healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python deps (two-step to guarantee CPU-only torch) ───────────────────────
COPY requirements.txt .

# Step 1 — torch from the CPU-only wheel index.
RUN pip install --no-cache-dir torch \
        --index-url https://download.pytorch.org/whl/cpu

# Step 2 — everything else from PyPI.
RUN pip install --no-cache-dir -r requirements.txt

# ── Non-root runtime user ─────────────────────────────────────────────────────
RUN addgroup --system --gid 10001 warden \
    && adduser --system --uid 10001 --gid 10001 --no-create-home wardenuser

# ── Application source ────────────────────────────────────────────────────────
ARG GIT_SHA=dev
COPY --chown=wardenuser:warden . .

RUN mkdir -p /warden/models /warden/data \
    && chown -R wardenuser:warden /warden/models /warden/data

# ── Runtime environment ───────────────────────────────────────────────────────
ENV MODEL_CACHE_DIR=/warden/models
ENV HF_HOME=/warden/models
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/
ENV BROWSER_ENABLED=false

USER wardenuser

EXPOSE 8001

ENTRYPOINT ["/bin/bash", "/warden/entrypoint.sh"]
