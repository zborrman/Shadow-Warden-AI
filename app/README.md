# app/ — Reference Customer Application

This directory contains a minimal FastAPI reference implementation showing
how a **customer application** integrates with the Shadow Warden AI gateway.

It is **not** part of the production warden service — it is documentation in code form.

## Purpose

Demonstrates the integration pattern:
1. Receive a user request
2. POST to `WARDEN_URL/filter` before sending to any LLM
3. Forward to LLM only if `allowed: true`
4. Return the `filtered_content` (secrets already redacted)

## Run standalone

```bash
WARDEN_URL=http://localhost:8001 \
WARDEN_API_KEY=your-key \
uvicorn app.main:app --port 9000
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/health` | Health check |
| `POST` | `/demo/filter` | Forward prompt through warden, then mock LLM call |

## Docker

```bash
docker build -t warden-reference-app .
docker run -e WARDEN_URL=http://warden:8001 -e WARDEN_API_KEY=... -p 9000:9000 warden-reference-app
```
