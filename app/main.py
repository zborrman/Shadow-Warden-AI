"""
Shadow Warden AI — App Service stub.
Replace with your actual application.

All AI calls should be routed through the Warden gateway:
  WARDEN_URL = os.getenv("WARDEN_URL", "http://warden:8001")
  POST {WARDEN_URL}/filter  →  check before sending to any LLM
"""
from __future__ import annotations

import os

import httpx
from fastapi import FastAPI

app = FastAPI(title="Shadow Warden App", version="0.1.0")

WARDEN_URL = os.getenv("WARDEN_URL", "http://warden:8001")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "warden_url": WARDEN_URL}


@app.post("/demo/filter")
async def demo_filter(body: dict) -> dict:
    """Forward a payload through the Warden /filter endpoint."""
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(f"{WARDEN_URL}/filter", json=body)
    return r.json()
