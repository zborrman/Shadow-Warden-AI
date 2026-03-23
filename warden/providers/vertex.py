"""
warden/providers/vertex.py
━━━━━━━━━━━━━━━━━━━━━━━━━
Google Cloud Vertex AI adapter.

Vertex AI exposes an OpenAI-compatible endpoint so no payload conversion is
needed — the standard /v1/chat/completions JSON format works unchanged.
The only provider-specific work is building the correct URL and obtaining a
short-lived Google OAuth2 bearer token.

Model name format (used in openai_proxy):
    "vertex/<model-name>"
    e.g.  "vertex/gemini-1.5-flash-001"
          "vertex/gemini-1.0-pro"
          "vertex/mistral-nemo@2407"      (partner models via Model Garden)

Authentication (tried in priority order):
    1. VERTEX_ACCESS_TOKEN  env var — static bearer token (simplest; fine for CI/dev)
    2. google-auth library   — Application Default Credentials or service account JSON
       Install: pip install google-auth
    3. RuntimeError if neither is available

Environment variables:
    VERTEX_PROJECT_ID    — GCP project ID (required)
    VERTEX_LOCATION      — Vertex AI region (default: us-central1)
    VERTEX_ACCESS_TOKEN  — static access token (optional, overrides google-auth)

Vertex AI OpenAI-compatible endpoint docs:
    https://cloud.google.com/vertex-ai/generative-ai/docs/open-ai/overview
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("warden.providers.vertex")

_PROJECT  = os.getenv("VERTEX_PROJECT_ID",  "")
_LOCATION = os.getenv("VERTEX_LOCATION",    "us-central1")

# Base URL template — the model name is NOT part of the URL (unlike Bedrock).
# Vertex AI's OpenAI-compat endpoint selects the model from the request body.
_BASE_URL_TMPL = (
    "https://{location}-aiplatform.googleapis.com"
    "/v1beta1/projects/{project}/locations/{location}"
    "/endpoints/openapi"
)


# ── URL builder ───────────────────────────────────────────────────────────────

def build_completions_url(
    *,
    project:  str = "",
    location: str = "",
) -> str:
    """Return the full chat/completions URL for the configured Vertex AI project."""
    proj = project or _PROJECT
    loc  = location or _LOCATION
    if not proj:
        raise RuntimeError(
            "VERTEX_PROJECT_ID is not set. "
            "Add it to your .env file to enable Vertex AI routing."
        )
    base = _BASE_URL_TMPL.format(location=loc, project=proj)
    return f"{base}/chat/completions"


def build_embeddings_url(
    *,
    project:  str = "",
    location: str = "",
) -> str:
    """Return the full embeddings URL for the configured Vertex AI project."""
    proj = project or _PROJECT
    loc  = location or _LOCATION
    if not proj:
        raise RuntimeError("VERTEX_PROJECT_ID is not set.")
    base = _BASE_URL_TMPL.format(location=loc, project=proj)
    return f"{base}/embeddings"


# ── Token acquisition ─────────────────────────────────────────────────────────

async def get_access_token() -> str:
    """
    Return a Google OAuth2 bearer token for Vertex AI.

    Tries sources in priority order:
    1. ``VERTEX_ACCESS_TOKEN`` environment variable (static token — simplest)
    2. ``google-auth`` Application Default Credentials (``pip install google-auth``)

    Raises ``RuntimeError`` if no credentials are available.
    """
    # Option 1 — static token (dev / CI)
    static = os.getenv("VERTEX_ACCESS_TOKEN", "")
    if static:
        return static

    # Option 2 — google-auth (production ADC / service account)
    try:
        import google.auth  # type: ignore[import]
        import google.auth.transport.requests as _transport  # type: ignore[import]

        creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        if not creds.valid or getattr(creds, "expiry", None) is None:
            creds.refresh(_transport.Request())
        log.debug("Vertex AI token obtained via google-auth (ADC).")
        return creds.token  # type: ignore[return-value]
    except ImportError:
        pass  # google-auth not installed — fall through to error
    except Exception as exc:
        raise RuntimeError(f"google-auth credential refresh failed: {exc}") from exc

    raise RuntimeError(
        "No Google credentials configured for Vertex AI. "
        "Set VERTEX_ACCESS_TOKEN or install google-auth: pip install google-auth"
    )


# ── Public helpers used by openai_proxy ───────────────────────────────────────

async def resolve_vertex(model: str) -> tuple[str, dict[str, str], str]:
    """
    Resolve a ``vertex/<model-name>`` model string to provider details.

    Returns:
        (completions_url, extra_headers, model_id)

    ``extra_headers`` includes ``Authorization: Bearer <token>`` so the
    standard request-building path in openai_proxy can use it directly.
    ``model_id`` is the bare model name (stripped of the ``vertex/`` prefix)
    to be substituted back into the forwarded payload.
    """
    model_id = model[7:]   # strip "vertex/" prefix
    token    = await get_access_token()
    url      = build_completions_url()
    headers  = {"Authorization": f"Bearer {token}"}
    return url, headers, model_id
