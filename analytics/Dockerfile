# ─────────────────────────────────────────────────────────────────────────────
#  Shadow Warden AI — Analytics API Service
#  Lightweight FastAPI service that exposes the log data over HTTP.
#  The Streamlit dashboard reads logs.json directly via the shared volume;
#  this service can be extended to serve aggregated metrics to external
#  SIEM tools, Grafana, or BI dashboards.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /analytics

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi uvicorn[standard]

# ── Minimal health-check app ──────────────────────────────────────────────────
RUN python -c "
content = '''
from fastapi import FastAPI
app = FastAPI(title=\"Shadow Warden — Analytics API\")

@app.get(\"/health\")
def health():
    return {\"status\": \"ok\", \"service\": \"warden-analytics\"}
'''
open('/analytics/main.py', 'w').write(content)
"

EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
