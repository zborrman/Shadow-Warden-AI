"""
warden/api/xai.py
──────────────────
Explainable AI 2.0 — REST API.

Routes
──────
  GET  /xai/explain/{request_id}       — structured causal chain (JSON)
  POST /xai/explain/batch              — explain up to 20 request IDs
  GET  /xai/report/{request_id}        — HTML report (inline)
  GET  /xai/report/{request_id}/pdf    — PDF report (download)
  GET  /xai/dashboard                  — aggregated XAI statistics (last 24h)

Auth: standard X-API-Key.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key
from warden.billing.addons import require_addon_or_feature

router = APIRouter(prefix="/xai", tags=["Explainable AI"])

AuthDep = Depends(require_api_key)
_XaiReportGate = require_addon_or_feature(
    feature="xai_reports_enabled", addon_key="xai_audit", min_tier="individual"
)


# ── Request models ────────────────────────────────────────────────────────────

class BatchExplainRequest(BaseModel):
    request_ids: list[str] = Field(..., min_length=1, max_items=20)
    tenant_id:   str       = Field("default")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "/explain/{request_id}",
    summary="Get structured causal chain for a filter decision",
)
async def explain(
    request_id: str,
    tenant_id:  str = Query("default"),
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Return the full causal chain for a specific filter decision.

    The chain includes:
    - One node per pipeline stage (topology → obfuscation → secrets → semantic
      → brain → causal → phish → ERS → decision)
    - Per-stage verdict (PASS / FLAG / BLOCK / SKIP) and numeric score
    - Primary cause attribution (which stage triggered the block)
    - Counterfactual remediation suggestions
    - Plain-English rationale

    Use the `nodes[].color` and `nodes[].verdict` fields to drive your
    React Flow / D3 pipeline visualizer.
    """
    from warden.analytics.logger import read_by_request_id
    from warden.xai.chain import build_chain, chain_to_dict

    record = read_by_request_id(request_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Request ID {request_id!r} not found in logs.")

    chain = build_chain(record, tenant_id=tenant_id)
    return chain_to_dict(chain)


@router.post("/explain/batch", summary="Explain multiple filter decisions")
async def explain_batch(
    body: BatchExplainRequest,
    auth: AuthResult = AuthDep,
) -> list[dict]:
    """
    Explain up to 20 filter decisions in one call.

    Returns a list in the same order as `request_ids`.
    Missing / not-found IDs return `{"found": false, "request_id": "..."}`.
    """
    from warden.analytics.logger import read_by_request_id
    from warden.xai.chain import build_chain, chain_to_dict

    results: list[dict] = []
    for rid in body.request_ids:
        record = read_by_request_id(rid)
        if not record:
            results.append({"found": False, "request_id": rid})
        else:
            chain = build_chain(record, tenant_id=body.tenant_id)
            results.append(chain_to_dict(chain))
    return results


@router.get(
    "/report/{request_id}",
    summary="HTML causal chain report (inline)",
    dependencies=[_XaiReportGate],
)
async def report_html(
    request_id: str,
    tenant_id:  str = Query("default"),
    auth: AuthResult = AuthDep,
) -> Response:
    """
    Render a self-contained HTML report for a filter decision.

    The report includes:
    - Risk gauge and verdict banner
    - Interactive pipeline diagram (collapsible stage cards)
    - Counterfactual remediation table
    - Raw JSON payload (collapsible)

    Open directly in a browser or embed in an `<iframe>`.
    Add `?print=1` to your URL for a print-optimized layout.
    """
    from warden.analytics.logger import read_by_request_id
    from warden.xai.chain import build_chain
    from warden.xai.renderer import render_html

    record = read_by_request_id(request_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Request ID {request_id!r} not found.")

    chain   = build_chain(record, tenant_id=tenant_id)
    content = render_html(chain)
    return Response(content=content, media_type="text/html; charset=utf-8")


@router.get(
    "/report/{request_id}/pdf",
    summary="PDF causal chain report (download)",
    dependencies=[_XaiReportGate],
)
async def report_pdf(
    request_id: str,
    tenant_id:  str = Query("default"),
    auth: AuthResult = AuthDep,
) -> Response:
    """
    Download a PDF report for a filter decision.

    Requires `reportlab` to be installed for true PDF output.
    Falls back to a print-ready HTML page when reportlab is unavailable
    (Content-Type: text/html) — note in the `X-Report-Format` response header.

    Suitable for:
    - SOC 2 audit evidence packages
    - Incident investigation reports
    - Executive briefings
    """
    from warden.analytics.logger import read_by_request_id
    from warden.xai.chain import build_chain
    from warden.xai.renderer import render_pdf

    record = read_by_request_id(request_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Request ID {request_id!r} not found.")

    chain           = build_chain(record, tenant_id=tenant_id)
    content, ctype  = render_pdf(chain)
    fmt             = "pdf" if ctype == "application/pdf" else "html"

    headers = {
        "Content-Disposition": f'attachment; filename="xai-report-{request_id[:16]}.{fmt}"',
        "X-Report-Format":     fmt,
    }
    return Response(content=content, media_type=ctype, headers=headers)


@router.get("/dashboard", summary="Aggregated XAI statistics")
async def dashboard(
    tenant_id: str  = Query("default"),
    hours:     int  = Query(24, ge=1, le=168, description="Look-back window in hours"),
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Aggregated explainability statistics for the last N hours.

    Returns:
    - Total requests analyzed
    - Stage hit rates (how often each stage triggered a block/flag)
    - Top 5 flag types
    - Verdict distribution
    - Risk level distribution
    - Primary cause distribution (which stage most often triggers blocks)

    Use this to drive the XAI dashboard summary panel and identify which
    pipeline stages are most active for a given tenant.
    """
    import collections
    from datetime import UTC, datetime, timedelta

    from warden.analytics.logger import load_entries
    from warden.xai.chain import STAGE_ORDER, build_chain

    cutoff  = datetime.now(UTC) - timedelta(hours=hours)
    entries = [
        e for e in load_entries()
        if e.get("ts", "") >= cutoff.isoformat()
    ]

    if not entries:
        return {
            "tenant_id": tenant_id,
            "hours":     hours,
            "total":     0,
            "message":   "No log entries in the selected window.",
        }

    stage_verdicts: dict[str, collections.Counter] = {
        s: collections.Counter() for s in STAGE_ORDER
    }
    verdict_dist:  collections.Counter = collections.Counter()
    risk_dist:     collections.Counter = collections.Counter()
    flag_counter:  collections.Counter = collections.Counter()
    cause_counter: collections.Counter = collections.Counter()

    for rec in entries:
        chain = build_chain(rec, tenant_id=tenant_id)
        verdict_dist[chain.final_verdict] += 1
        risk_dist[chain.risk_level]       += 1
        cause_counter[chain.primary_cause] += 1
        for flag in chain.flags:
            flag_counter[flag] += 1
        for node in chain.nodes:
            stage_verdicts[node.stage_id][node.verdict] += 1

    stage_hit_rates = {
        sid: {
            "block": counts["BLOCK"],
            "flag":  counts["FLAG"],
            "pass":  counts["PASS"],
            "skip":  counts["SKIP"],
            "block_rate": round(
                counts["BLOCK"] / max(1, counts["BLOCK"] + counts["FLAG"] + counts["PASS"]), 3
            ),
        }
        for sid, counts in stage_verdicts.items()
    }

    top_causes = [
        {"stage_id": sid, "count": cnt}
        for sid, cnt in cause_counter.most_common(5)
    ]

    return {
        "tenant_id":        tenant_id,
        "hours":            hours,
        "total":            len(entries),
        "verdict_dist":     dict(verdict_dist),
        "risk_dist":        dict(risk_dist),
        "top_flags":        [{"flag": f, "count": c} for f, c in flag_counter.most_common(10)],
        "top_primary_causes": top_causes,
        "stage_hit_rates":  stage_hit_rates,
        "generated_at":     datetime.now(UTC).isoformat(),
    }
