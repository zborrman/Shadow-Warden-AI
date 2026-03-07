# ─────────────────────────────────────────────────────────────────────────────
#  Shadow Warden AI — Warden Gateway
#  Base: mcr.microsoft.com/playwright/python
#    • Chromium, Firefox, WebKit + OS dependencies pre-installed
#    • Python 3.12  (noble variant — v1.49.0+)
#    • ~800 MB image (vs ~2 GB with CUDA torch)
# ─────────────────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

WORKDIR /warden

# ── Extra system tools ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python deps (two-step to guarantee CPU-only torch) ───────────────────────
COPY requirements.txt .

# Step 1 — torch from the CPU-only wheel index.
#   --index-url (not --extra-index-url) so pip cannot fall back to PyPI
#   and accidentally pull the 2 GB CUDA build.
RUN pip install --no-cache-dir torch \
        --index-url https://download.pytorch.org/whl/cpu

# Step 2 — everything else (FastAPI, transformers, playwright, …) from PyPI.
#   torch is already satisfied above, so pip skips re-downloading it.
RUN pip install --no-cache-dir -r requirements.txt

# Step 3 — install Playwright browser binaries (Chromium only — ~170 MB).
#   The mcr.microsoft.com/playwright image ships the OS dependencies;
#   this step installs the actual browser executables for Python.
RUN playwright install chromium

# ── Non-root runtime user ─────────────────────────────────────────────────────
# Created before COPY so --chown applies in a single layer.
# GID/UID 10001 — 1001 is already taken by the playwright/python:v1.49.0-noble
# base image (internal pwuser group), so we use a high ID to avoid conflicts.
RUN addgroup --system --gid 10001 warden \
    && adduser --system --uid 10001 --gid 10001 --no-create-home wardenuser

# ── Application source ────────────────────────────────────────────────────────
# ARG declared here so changing GIT_SHA (passed by CI) busts the COPY cache
# without invalidating the expensive pip/playwright layers above.
ARG GIT_SHA=dev
COPY --chown=wardenuser:warden . .

# Model cache dir must be writable by the runtime user before USER drops root.
RUN mkdir -p /warden/models && chown wardenuser:warden /warden/models

# ── Runtime environment ───────────────────────────────────────────────────────
ENV MODEL_CACHE_DIR=/warden/models
ENV HF_HOME=/warden/models
ENV PYTHONUNBUFFERED=1
# Package lives at /warden/ — add / to sys.path so `import warden` resolves.
ENV PYTHONPATH=/

USER wardenuser

EXPOSE 8001

# 2 workers: one handles live /filter requests while the other can run
# a browser sandbox audit without blocking the API.
CMD ["uvicorn", "warden.main:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2"]
