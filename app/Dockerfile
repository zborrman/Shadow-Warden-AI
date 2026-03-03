# ─────────────────────────────────────────────────────────────────────────────
#  Shadow Warden AI — App Service
#  Replace this with your application's actual Dockerfile.
#
#  Requirements:
#    • Health check endpoint at GET /health → HTTP 200
#    • All outbound AI payloads must be sent to WARDEN_URL/filter first
#      before forwarding to any LLM or downstream service.
#    • WARDEN_URL is injected via docker-compose environment.
#
#  Example integration (Python):
#    import httpx, os
#    WARDEN = os.getenv("WARDEN_URL", "http://warden:8001")
#
#    async def safe_prompt(text: str) -> str:
#        r = await httpx.AsyncClient().post(f"{WARDEN}/filter",
#                json={"content": text, "strict": False})
#        r.raise_for_status()
#        data = r.json()
#        if not data["allowed"]:
#            raise ValueError(f"Blocked: {data['reason']}")
#        return data["filtered_content"]
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Install curl for the healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# ── Dependencies ──────────────────────────────────────────────────────────────
COPY requirements.txt* ./
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true

# ── Application source ────────────────────────────────────────────────────────
COPY . .

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Replace with your app's actual entry point
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
