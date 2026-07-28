"""
warden/api/masking.py
━━━━━━━━━━━━━━━━━━━━━
PII masking (Yellow Zone) + OWASP LLM output scanning REST API.

Endpoints
─────────
  POST /mask           — replace PII entities with reversible tokens
  POST /unmask         — restore original values from a vault session
  POST /filter/output  — scan AI *output* for OWASP LLM02 / LLM06 / LLM08 risks

Extracted from ``warden/main.py`` (P-2). These three handlers reached for no
``main`` state at all — every collaborator was already a plain import that
``main`` had simply aliased:

    _get_masking_engine    -> warden.masking.engine.get_engine
    _get_output_sanitizer  -> warden.output_sanitizer.get_sanitizer
    _xai_explain           -> warden.xai.explainer.explain
    _limiter / _tenant_limit -> warden.limiter.limiter / tenant_limit

so no ``warden.runtime`` slot is needed here (unlike the Phase 3 extractions
that carried singletons). Behaviour is unchanged: same paths, same
``response_model``s, same tags, same rate limit, same auth dependency.

GDPR note: ``/mask`` and ``/unmask`` handle raw PII by definition. Nothing here
logs request or response content — ``/filter/output`` logs only risk *metadata*
(categories and finding counts), never the scanned text or the matched snippet.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from fastapi import APIRouter, Depends, Request, status

from warden.auth_guard import AuthResult, require_api_key
from warden.limiter import limiter as _limiter
from warden.limiter import tenant_limit as _tenant_limit
from warden.masking.engine import get_engine as _get_masking_engine
from warden.output_sanitizer import get_sanitizer as _get_output_sanitizer
from warden.schemas import (
    MaskedEntityInfo,
    MaskRequest,
    MaskResponse,
    OutputFindingSchema,
    OutputScanRequest,
    OutputScanResponse,
    UnmaskRequest,
    UnmaskResponse,
)
from warden.xai.explainer import explain as _xai_explain

log = logging.getLogger("warden.api.masking")

# No router-level `tags=`: FastAPI MERGES router tags with per-route tags, which
# would turn /filter/output's ["Filter"] into ["masking", "Filter"] and change the
# published OpenAPI schema. Tags stay on the individual routes, exactly as they
# were in main.py.
router = APIRouter()


# ── PII masking (Yellow Zone) ────────────────────────────────────────────────
#
# Use-case: the OpenAI proxy calls /mask before forwarding to an LLM, then
# /unmask on the response. Can also be called directly from any client.
#
# Masking mode env var:
#   MASKING_MODE=off   — endpoints available but proxy does NOT auto-mask (default)
#   MASKING_MODE=auto  — proxy auto-masks user messages when PII detected


@router.post(
    "/mask",
    response_model=MaskResponse,
    tags=["masking"],
    summary="Yellow Zone — replace PII entities with reversible tokens",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit(_tenant_limit)
async def mask_text(
    payload: MaskRequest,
    request: Request,
    auth:    AuthResult = Depends(require_api_key),
) -> MaskResponse:
    """
    Scan the input text for PII entities (names, money amounts, dates,
    organisations, emails, phones, reference IDs) and replace each with a
    short reversible token such as [PERSON_1] or [MONEY_2].

    The returned ``session_id`` must be passed to ``POST /unmask`` to restore
    the original values in the LLM response.

    Supported entity types: PERSON, MONEY, DATE, ORG, EMAIL, PHONE, ID
    """
    engine = _get_masking_engine()
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: engine.mask(payload.text, payload.session_id)
    )

    entity_map: dict[str, int] = result.summary()
    entities = [
        MaskedEntityInfo(entity_type=k, token=f"[{k}_N]", count=v)
        for k, v in entity_map.items()
    ]

    return MaskResponse(
        masked       = result.masked,
        session_id   = result.session_id,
        entity_count = result.entity_count,
        entities     = entities,
    )


@router.post(
    "/unmask",
    response_model=UnmaskResponse,
    tags=["masking"],
    summary="Yellow Zone — restore original PII values in a masked text",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit(_tenant_limit)
async def unmask_text(
    payload: UnmaskRequest,
    request: Request,
    auth:    AuthResult = Depends(require_api_key),
) -> UnmaskResponse:
    """
    Replace all [TYPE_N] tokens in the text with the original values from the
    vault session created by a previous call to ``POST /mask``.

    The session vault expires 2 hours after creation.
    """
    engine = _get_masking_engine()
    loop   = asyncio.get_running_loop()
    unmasked = await loop.run_in_executor(
        None, lambda: engine.unmask(payload.text, payload.session_id)
    )
    return UnmaskResponse(unmasked=unmasked, session_id=payload.session_id)


# ── OWASP LLM Output Scanning ────────────────────────────────────────────────
#
# POST /filter/output — scan AI-generated text *after* it returns from the model.
#
# Covers three OWASP LLM Top 10 categories:
#   LLM02 — Insecure Output Handling: XSS, HTML injection, Markdown link injection
#   LLM06 — Sensitive Information Disclosure: prompt leakage, system prompt echo
#   LLM08 — Excessive Agency: shell/SQL/SSRF/path-traversal in AI-generated content


@router.post(
    "/filter/output",
    response_model=OutputScanResponse,
    tags=["Filter"],
    summary="Scan AI output for OWASP LLM02 / LLM06 / LLM08 risks",
)
@_limiter.limit(_tenant_limit)
async def filter_output(
    request:   Request,
    payload:   OutputScanRequest,
    auth:      AuthResult = Depends(require_api_key),
) -> OutputScanResponse:
    """
    Scan AI-generated text **before it reaches the browser or downstream system**.

    Unlike ``POST /filter`` (which scans *input* prompts), this endpoint scans
    the AI model's *output* — catching content that is harmless as a prompt but
    dangerous once rendered.

    **OWASP LLM Top 10 coverage:**

    | Category | Risks detected |
    |----------|---------------|
    | LLM02 — Insecure Output Handling | XSS (`<script>`, `onerror=`, `javascript:`), HTML injection (`<iframe>`, `<object>`), Markdown link injection |
    | LLM06 — Sensitive Information Disclosure | System prompt leakage, CoT scratchpad echo, internal tool name disclosure |
    | LLM08 — Excessive Agency | Shell command injection, SQL injection, SSRF (internal IP / metadata endpoints), path traversal |

    **Response:**
    - `safe`: `true` when no risks detected.
    - `sanitized`: the output with dangerous patterns stripped/escaped — safe to render.
    - `findings`: list of detected risks with OWASP category labels.
    """
    t0 = time.perf_counter()

    sanitizer = _get_output_sanitizer()
    result    = sanitizer.scan(payload.output)

    elapsed_ms = (time.perf_counter() - t0) * 1000

    findings = [
        OutputFindingSchema(risk=f.risk.value, snippet=f.snippet, owasp=f.owasp)
        for f in result.findings
    ]

    if result.risky:
        log.warning(
            json.dumps({
                "event":           "output_risk_detected",
                "tenant_id":       payload.tenant_id,
                "risk_categories": result.risk_categories,
                "owasp":           result.owasp_categories,
                "finding_count":   len(result.findings),
            })
        )

    _out_flags = [str(f.risk) for f in result.findings]
    _out_explanation = _xai_explain(
        risk_level       = "high" if result.risky else "low",
        flags            = _out_flags,
        reason           = ", ".join(result.owasp_categories),
        owasp_categories = result.owasp_categories,
    )

    return OutputScanResponse(
        safe             = not result.risky,
        findings         = findings,
        sanitized        = result.sanitized,
        risk_categories  = result.risk_categories,
        owasp_categories = result.owasp_categories,
        processing_ms    = round(elapsed_ms, 2),
        explanation      = _out_explanation,
    )
