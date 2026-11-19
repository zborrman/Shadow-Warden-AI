# ─────────────────────────────────────────────────────────────────────────────
#  Shadow Warden AI — Analytics Service
#  Lightweight FastAPI service that exposes structured HTTP endpoints over the
#  NDJSON event log written by the warden gateway.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /analytics

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# P-0: exact pins, and QUOTED. The previous form was
#   pip install fastapi>=0.115.0 uvicorn[standard]>=0.30.0
# — unquoted in a shell-form RUN, so `>` was a redirection operator: the build
# installed *bare* `fastapi` and `uvicorn[standard]` (whatever was newest that
# minute) and wrote the version strings into files named `=0.115.0` and
# `=0.30.0`. Versions match warden/constraints.txt so the two services agree.
RUN pip install --no-cache-dir \
    "fastapi==0.139.0" \
    "uvicorn[standard]==0.50.0" \
    "prometheus-fastapi-instrumentator==8.0.2"

# Copy the analytics service source
COPY main.py /analytics/main.py

# Non-root, same uid as the gateway (10001): the log it reads lives in a
# mode-0700 directory owned by that uid, mounted read-only.
RUN groupadd --gid 10001 analytics && useradd --uid 10001 --gid 10001 --no-create-home analytics
USER 10001:10001

EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
