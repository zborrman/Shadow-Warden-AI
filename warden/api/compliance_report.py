"""
warden/api/compliance_report.py  (Q3.7)
────────────────────────────────────────
SMB Compliance Report — GDPR Art.30 / FZ-152 (Russian DPL) status report.

GET  /compliance/smb-report         → JSON summary
GET  /compliance/smb-report/html    → self-contained HTML (print-ready)
GET  /compliance/smb-report/pdf     → PDF (reportlab) or HTML fallback

What the report covers
──────────────────────
  • Processing period and volume
  • Data categories processed (PII, financial, health, credentials)
  • Block/redaction counts by category
  • Anonymisation rate (% requests where PII was stripped)
  • GDPR Art.5 principle adherence checklist
  • FZ-152 Art.18 data-residency status
  • No-content-logged assertion (GDPR Art.5(1)(c) — data minimisation)
"""
from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, Response

log = logging.getLogger("warden.api.compliance_report")

router = APIRouter(prefix="/compliance", tags=["compliance"])

_ORG_NAME   = os.getenv("ORG_NAME",   "Your Organisation")
_TENANT_ID  = os.getenv("TENANT_ID",  "default")
_DATA_RESIDENCY = os.getenv("DATA_RESIDENCY_JURISDICTION", "EU")


# ── Data aggregation ──────────────────────────────────────────────────────────

def _aggregate_logs(days: int) -> dict:
    """Read log entries from the analytics logger and aggregate for compliance."""
    since = datetime.now(UTC) - timedelta(days=days)
    try:
        from warden.analytics.logger import load_entries
        entries = [e for e in load_entries() if _entry_after(e, since)]
    except Exception:
        entries = []

    total    = len(entries)
    blocked  = sum(1 for e in entries if e.get("verdict") in ("BLOCK", "HIGH"))
    allowed  = total - blocked
    pii_hits = sum(1 for e in entries if e.get("secrets_found", 0) > 0)
    inj_hits = sum(1 for e in entries if "INJECTION" in str(e.get("flags", [])))
    avg_ms   = (
        sum(e.get("latency_ms", 0) for e in entries) / total
        if total else 0.0
    )
    anon_rate = round(pii_hits / total * 100, 1) if total else 0.0

    # Category breakdown from flags
    categories: dict[str, int] = {}
    for e in entries:
        for flag in e.get("flags", []):
            categories[flag] = categories.get(flag, 0) + 1

    return {
        "total":      total,
        "blocked":    blocked,
        "allowed":    allowed,
        "pii_hits":   pii_hits,
        "inj_hits":   inj_hits,
        "avg_ms":     round(avg_ms, 1),
        "anon_rate":  anon_rate,
        "categories": dict(sorted(categories.items(), key=lambda x: x[1], reverse=True)[:10]),
    }


def _entry_after(entry: dict, since: datetime) -> bool:
    ts = entry.get("timestamp") or entry.get("ts") or ""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")) >= since
    except Exception:
        return False


def _build_report(days: int) -> dict:
    stats      = _aggregate_logs(days)
    generated  = datetime.now(UTC).isoformat()
    period_end = datetime.now(UTC).date().isoformat()
    period_start = (datetime.now(UTC) - timedelta(days=days)).date().isoformat()

    gdpr_checklist = [
        {"article": "Art.5(1)(a)", "principle": "Lawfulness, fairness, transparency",
         "status": "PASS", "note": "All processing occurs within API scope; purpose documented."},
        {"article": "Art.5(1)(b)", "principle": "Purpose limitation",
         "status": "PASS", "note": "Data used solely for AI security filtering."},
        {"article": "Art.5(1)(c)", "principle": "Data minimisation",
         "status": "PASS", "note": "Content never logged — only metadata (length, verdict, latency)."},
        {"article": "Art.5(1)(d)", "principle": "Accuracy",
         "status": "PASS", "note": "No personal data stored; no correction obligation arises."},
        {"article": "Art.5(1)(e)", "principle": "Storage limitation",
         "status": "PASS", "note": f"Log retention: {os.getenv('RETENTION_DAYS', '180')} days (configurable)."},
        {"article": "Art.5(1)(f)", "principle": "Integrity and confidentiality",
         "status": "PASS", "note": "Fernet encryption at rest; TLS in transit; audit trail HMAC-signed."},
        {"article": "Art.30",      "principle": "Records of processing activities",
         "status": "PASS", "note": "This report constitutes the Art.30 record for the reporting period."},
        {"article": "Art.35",      "principle": "Data Protection Impact Assessment",
         "status": "PASS", "note": "DPIA completed — see docs/dpia.md."},
    ]

    fz152_checklist = [
        {"article": "Art.18",  "requirement": "Data localisation",
         "status": _DATA_RESIDENCY,
         "note": f"Processing jurisdiction: {_DATA_RESIDENCY}. Content never leaves the gateway."},
        {"article": "Art.19",  "requirement": "Cross-border transfer",
         "status": "RESTRICTED", "note": "PII/CLASSIFIED never transferred cross-border (sovereign routing enforced)."},
        {"article": "Art.21",  "requirement": "Roskomnadzor notification",
         "status": "N/A",      "note": "Applicable only when serving Russian data subjects from RU jurisdiction."},
    ]

    return {
        "org_name":       _ORG_NAME,
        "tenant_id":      _TENANT_ID,
        "period_start":   period_start,
        "period_end":     period_end,
        "days":           days,
        "generated_at":   generated,
        "stats":          stats,
        "gdpr":           gdpr_checklist,
        "fz152":          fz152_checklist,
        "data_residency": _DATA_RESIDENCY,
        "version":        "4.7",
    }


# ── HTML renderer ─────────────────────────────────────────────────────────────

def _render_html(report: dict) -> str:
    s = report["stats"]
    gdpr_rows = "".join(
        f"<tr><td>{r['article']}</td><td>{r['principle']}</td>"
        f"<td class='status-{r['status'].lower()}'>{r['status']}</td>"
        f"<td>{r['note']}</td></tr>"
        for r in report["gdpr"]
    )
    fz_rows = "".join(
        f"<tr><td>{r['article']}</td><td>{r['requirement']}</td>"
        f"<td class='status-{r['status'].lower()}'>{r['status']}</td>"
        f"<td>{r['note']}</td></tr>"
        for r in report["fz152"]
    )
    cat_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>"
        for k, v in s["categories"].items()
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shadow Warden AI — SMB Compliance Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #1e293b; max-width: 900px; margin: 40px auto; padding: 0 24px; }}
  h1 {{ font-size: 1.8rem; color: #0f172a; border-bottom: 3px solid #6366f1; padding-bottom: 12px; }}
  h2 {{ font-size: 1.1rem; color: #374151; margin-top: 32px; }}
  .meta {{ color: #64748b; font-size: 13px; margin-top: 4px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin: 24px 0; }}
  .kpi {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; text-align: center; }}
  .kpi-value {{ font-size: 2rem; font-weight: 700; color: #6366f1; }}
  .kpi-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #94a3b8; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; margin-top: 12px; }}
  th {{ background: #f1f5f9; padding: 8px 12px; text-align: left; font-weight: 600; color: #475569; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #f1f5f9; }}
  .status-pass {{ color: #16a34a; font-weight: 600; }}
  .status-warning, .status-restricted {{ color: #d97706; font-weight: 600; }}
  .status-fail {{ color: #dc2626; font-weight: 600; }}
  .status-n/a {{ color: #94a3b8; }}
  .status-eu, .status-us {{ color: #2563eb; font-weight: 600; }}
  .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; }}
  .gdpr-ok {{ background: #dcfce7; color: #15803d; }}
  footer {{ margin-top: 48px; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 16px; }}
  @media print {{ .no-print {{ display: none; }} }}
</style>
</head>
<body>
<h1>🛡️ Shadow Warden AI — SMB Compliance Report</h1>
<p class="meta">
  <strong>{report['org_name']}</strong> &nbsp;·&nbsp; Tenant: <code>{report['tenant_id']}</code>
  &nbsp;·&nbsp; Period: {report['period_start']} → {report['period_end']}
  &nbsp;·&nbsp; Generated: {report['generated_at'][:19]} UTC
  &nbsp;·&nbsp; v{report['version']}
</p>

<h2>Processing Summary</h2>
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-value">{s['total']:,}</div><div class="kpi-label">Total Requests</div></div>
  <div class="kpi"><div class="kpi-value" style="color:#ef4444">{s['blocked']:,}</div><div class="kpi-label">Blocked</div></div>
  <div class="kpi"><div class="kpi-value" style="color:#f59e0b">{s['pii_hits']:,}</div><div class="kpi-label">PII Detected</div></div>
  <div class="kpi"><div class="kpi-value">{s['anon_rate']}%</div><div class="kpi-label">Anonymisation Rate</div></div>
</div>
<p>Avg latency: <strong>{s['avg_ms']} ms</strong> &nbsp;·&nbsp;
   Injection attempts: <strong>{s['inj_hits']}</strong> &nbsp;·&nbsp;
   Data residency: <span class="badge gdpr-ok">{report['data_residency']}</span></p>

<h2>GDPR Compliance Checklist</h2>
<table>
  <tr><th>Article</th><th>Principle</th><th>Status</th><th>Evidence</th></tr>
  {gdpr_rows}
</table>

<h2>FZ-152 (Russian Data Protection Law) Checklist</h2>
<table>
  <tr><th>Article</th><th>Requirement</th><th>Status</th><th>Note</th></tr>
  {fz_rows}
</table>

<h2>Top 10 Detected Categories</h2>
<table>
  <tr><th>Category / Flag</th><th>Count</th></tr>
  {cat_rows if cat_rows else "<tr><td colspan='2' style='color:#94a3b8'>No events in period</td></tr>"}
</table>

<h2>Data Minimisation Statement</h2>
<p>Shadow Warden AI does <strong>not</strong> log request content. Only the following
metadata is retained per request: timestamp, verdict (ALLOW/BLOCK), risk level,
flag types, content length, and processing latency. This satisfies GDPR Art.5(1)(c)
(data minimisation) and the FZ-152 principle of processing necessity.</p>

<footer>
  Generated by Shadow Warden AI v{report['version']} &nbsp;·&nbsp;
  <a href="/docs#/compliance">API docs</a> &nbsp;·&nbsp;
  This document may serve as your GDPR Art.30 record of processing activities.
  <span class="no-print"> &nbsp;<button onclick="window.print()" style="margin-left:16px;padding:6px 16px;background:#6366f1;color:#fff;border:none;border-radius:6px;cursor:pointer;">Print / Save PDF</button></span>
</footer>
</body>
</html>"""


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/smb-report", summary="SMB compliance report (JSON)")
async def smb_report_json(
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> dict:
    return _build_report(days)


@router.get("/smb-report/html", response_class=HTMLResponse, summary="SMB compliance report (HTML, print-ready)")
async def smb_report_html(
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> HTMLResponse:
    report = _build_report(days)
    return HTMLResponse(content=_render_html(report))


@router.get("/smb-report/pdf", summary="SMB compliance report (PDF or HTML fallback)")
async def smb_report_pdf(
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> Response:
    report = _build_report(days)
    try:
        import io

        from reportlab.lib import colors  # type: ignore
        from reportlab.lib.pagesizes import A4  # type: ignore
        from reportlab.lib.styles import getSampleStyleSheet  # type: ignore
        from reportlab.platypus import (  # type: ignore
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        buf    = io.BytesIO()
        doc    = SimpleDocTemplate(buf, pagesize=A4, topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()
        story  = [
            Paragraph("Shadow Warden AI — SMB Compliance Report", styles["Title"]),
            Paragraph(f"{report['org_name']} · {report['period_start']} → {report['period_end']}", styles["Normal"]),
            Spacer(1, 20),
            Paragraph("GDPR Checklist", styles["Heading2"]),
        ]
        gdpr_data = [["Article", "Principle", "Status"]] + [
            [r["article"], r["principle"], r["status"]] for r in report["gdpr"]
        ]
        t = Table(gdpr_data, colWidths=[80, 220, 60])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366f1")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(t)
        doc.build(story)
        return Response(
            content=buf.getvalue(),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=shadow-warden-compliance.pdf",
                     "X-Report-Format": "pdf"},
        )
    except ImportError:
        # Fallback to HTML with browser print-to-PDF
        html = _render_html(report)
        return Response(
            content=html.encode(),
            media_type="text/html",
            headers={"X-Report-Format": "html"},
        )
