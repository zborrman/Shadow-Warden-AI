# ─────────────────────────────────────────────────────────────────────────────
#  Shadow Warden AI — Analytics Service
#  Lightweight FastAPI service that exposes structured HTTP endpoints over the
#  NDJSON event log written by the warden gateway.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.14-slim

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
    "uvicorn[standard]==0.50.0"

# Copy the analytics service source
COPY main.py /analytics/main.py

EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
