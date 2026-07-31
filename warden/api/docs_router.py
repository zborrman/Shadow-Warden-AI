"""
warden/api/docs_router.py
━━━━━━━━━━━━━━━━━━━━━━━━━
API documentation endpoints.

Endpoints
─────────
  GET /openapi.json         — full OpenAPI schema, HTTP Basic gated
  GET /openapi-public.json  — full OpenAPI schema, always open (see note below)
  GET /docs                 — Swagger UI, HTTP Basic gated
  GET /redoc                — Redoc UI, HTTP Basic gated

Extracted from ``warden/main.py`` (P-2, second increment: docs/openapi group).
The auth dependency (``_docs_auth``) and its two env-derived constants move
with the routes — nothing else in ``main.py`` referenced them.

``app.openapi()`` needs the live FastAPI application, which is defined in
``warden.main``. The no-upward-import layer rule forbids this module from
importing ``warden.main`` (CI-enforced by
``test_architecture_layers.py::test_no_module_imports_warden_main``), so the
two handlers that need it read ``runtime.app`` instead — ``main`` publishes it
immediately after construction, before the lifespan singletons.

⚠️ Read both docstrings below before touching either route. The comment that
used to sit above this block claimed "the actual OpenAPI schema is also gated
so attackers cannot enumerate routes" — true of ``/openapi.json`` alone, but
``/openapi-public.json`` serves the identical, unfiltered schema
unconditionally. It is a deliberate feature (see ``README.md``'s "Public
Redoc" entry — ``docs.shadow-warden-ai.com`` is a real static Redoc site that
fetches it cross-origin without credentials), not an oversight, so nothing
about its behavior changes here. But whatever protection ``DOCS_PASSWORD``
is meant to provide against route enumeration does not actually hold while
this sibling endpoint exists — worth knowing before relying on it.
"""
from __future__ import annotations

import os
import secrets

from fastapi import APIRouter, Depends, HTTPException
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from warden.runtime import runtime

# ── API Docs auth (HTTP Basic) ────────────────────────────────────────────────
# DOCS_PASSWORD="" (default) → docs served without auth (dev / CI only).
# DOCS_PASSWORD set          → /docs, /redoc, /openapi.json require HTTP Basic.
# Never set DOCS_PASSWORD="" on a public-facing server.

_DOCS_USERNAME: str = os.getenv("DOCS_USERNAME", "warden")
_DOCS_PASSWORD: str = os.getenv("DOCS_PASSWORD", "")
_http_basic = HTTPBasic(auto_error=False)


async def _docs_auth(
    credentials: HTTPBasicCredentials | None = Depends(_http_basic),
) -> None:
    """Dependency: pass-through in dev, HTTP Basic in production."""
    if not _DOCS_PASSWORD:
        return  # dev mode — no password configured → open access
    if credentials is None:
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Shadow Warden API Docs"'},
        )
    ok_user = secrets.compare_digest(
        credentials.username.encode(), _DOCS_USERNAME.encode()
    )
    ok_pass = secrets.compare_digest(
        credentials.password.encode(), _DOCS_PASSWORD.encode()
    )
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Shadow Warden API Docs"'},
        )


# No router-level `tags=`: FastAPI MERGES router tags with per-route tags. None
# of these four set a tag today (all four pass include_in_schema=False, so no
# published tag matters), but the omission is deliberate rather than accidental
# — matching the convention set in warden/api/masking.py.
router = APIRouter()


@router.get("/openapi.json", include_in_schema=False)
async def _openapi_schema(_: None = Depends(_docs_auth)):
    return JSONResponse(runtime.app.openapi())


@router.get("/openapi-public.json", include_in_schema=False)
async def _openapi_public():
    """Always-public OpenAPI schema — served to docs.shadow-warden-ai.com (Redoc)."""
    return JSONResponse(runtime.app.openapi())


@router.get("/docs", include_in_schema=False)
async def _swagger_ui(_: None = Depends(_docs_auth)):
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="Shadow Warden AI — API Docs",
    )


@router.get("/redoc", include_in_schema=False)
async def _redoc_ui(_: None = Depends(_docs_auth)):
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="Shadow Warden AI — API Docs",
    )
