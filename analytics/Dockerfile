# ─────────────────────────────────────────────────────────────────────────────
#  Shadow Warden AI — Analytics Service
#  Lightweight FastAPI service that exposes structured HTTP endpoints over the
#  NDJSON event log written by the warden gateway.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.14-slim

WORKDIR /analytics

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    fastapi>=0.115.0 \
    uvicorn[standard]>=0.30.0

# Copy the analytics service source
COPY main.py /analytics/main.py

EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
