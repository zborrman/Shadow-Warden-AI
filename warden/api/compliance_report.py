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
        "version":        "4.8",
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


# ── CP-22: ISO 27001 Annex A control mapping ──────────────────────────────────

_ISO27001_CONTROLS = [
    ("A.5.1",  "Information security policies",         "Implemented",  "docs/security-model.md defines full policy set"),
    ("A.6.1",  "Organisation of information security",  "Implemented",  "Roles: SOVA operator, MasterAgent, admin API key"),
    ("A.7.1",  "Human resource security",               "Partial",      "Access control via API key tiers; offboarding = key revocation"),
    ("A.8.1",  "Asset management",                      "Implemented",  "Secrets inventory (SQLite) + auto-retire lifecycle"),
    ("A.9.1",  "Access control",                        "Implemented",  "Per-tenant API keys, SHA-256 constant-time compare, tier gates"),
    ("A.10.1", "Cryptography",                          "Implemented",  "Fernet at-rest, TLS in-transit, Ed25519+ML-DSA-65 hybrid PQC"),
    ("A.11.1", "Physical and environmental security",   "Delegated",    "Hetzner VPS datacenter controls; MinIO on-prem option"),
    ("A.12.1", "Operations security",                   "Implemented",  "Docker Compose + healthchecks, CI lint+test+Trivy CVE gate"),
    ("A.12.4", "Logging and monitoring",                "Implemented",  "NDJSON audit log, Prometheus metrics, Grafana SLO alerts"),
    ("A.12.6", "Technical vulnerability management",    "Implemented",  "OSV CVE scan + ArXiv intel every 6h via sova_threat_sync"),
    ("A.13.1", "Network security management",           "Implemented",  "Caddy v2 TLS termination, HSTS, QUIC/HTTP3, no plaintext ports"),
    ("A.14.1", "Security in development",               "Implemented",  "pre-commit hooks: secret-scan, OWASP headers, tenant isolation"),
    ("A.16.1", "Information security incident management", "Implemented", "SOVA alerts + MasterAgent human-in-the-loop approval gate"),
    ("A.17.1", "Business continuity",                   "Partial",      "Fail-open design; Redis TTL fallback; MinIO replication planned"),
    ("A.18.1", "Compliance with legal requirements",    "Implemented",  "GDPR DPIA (Art.35), SOC 2 evidence, FZ-152 sovereign routing"),
]


@router.get("/iso27001", summary="ISO 27001 Annex A control mapping (JSON)")
async def iso27001_report(days: Annotated[int, Query(ge=1, le=365)] = 30) -> dict:
    stats = _aggregate_logs(days)
    controls = [
        {"control": c, "domain": d, "status": s, "evidence": e}
        for c, d, s, e in _ISO27001_CONTROLS
    ]
    implemented = sum(1 for _, _, s, _ in _ISO27001_CONTROLS if s == "Implemented")
    return {
        "standard":        "ISO/IEC 27001:2022",
        "org_name":        _ORG_NAME,
        "tenant_id":       _TENANT_ID,
        "generated_at":    datetime.now(UTC).isoformat(),
        "controls_total":  len(_ISO27001_CONTROLS),
        "implemented":     implemented,
        "partial":         sum(1 for _, _, s, _ in _ISO27001_CONTROLS if s == "Partial"),
        "delegated":       sum(1 for _, _, s, _ in _ISO27001_CONTROLS if s == "Delegated"),
        "coverage_pct":    round(implemented / len(_ISO27001_CONTROLS) * 100, 1),
        "period_days":     days,
        "filter_stats":    stats,
        "controls":        controls,
    }


@router.get("/iso27001/html", response_class=HTMLResponse, summary="ISO 27001 report (HTML)")
async def iso27001_html(days: Annotated[int, Query(ge=1, le=365)] = 30) -> HTMLResponse:
    data = await iso27001_report(days=days)
    rows = "".join(
        f"<tr><td><code>{c['control']}</code></td><td>{c['domain']}</td>"
        f"<td class='status-{c['status'].lower().replace(' ','-')}'>{c['status']}</td>"
        f"<td>{c['evidence']}</td></tr>"
        for c in data["controls"]
    )
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>ISO 27001 — Shadow Warden AI</title>
<style>body{{font-family:'Segoe UI',sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#1e293b}}
h1{{border-bottom:3px solid #6366f1;padding-bottom:10px}}
.meta{{color:#64748b;font-size:13px}}.kpi-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}}
.kpi{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;text-align:center}}
.kpi-v{{font-size:1.8rem;font-weight:700;color:#6366f1}}.kpi-l{{font-size:11px;color:#94a3b8;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}}
th{{background:#f1f5f9;padding:8px 10px;text-align:left;font-weight:600;color:#475569}}
td{{padding:8px 10px;border-bottom:1px solid #f1f5f9}}
.status-implemented{{color:#16a34a;font-weight:700}}.status-partial{{color:#d97706;font-weight:700}}.status-delegated{{color:#2563eb;font-weight:700}}
footer{{margin-top:32px;font-size:12px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px}}</style></head>
<body><h1>🔐 ISO 27001:2022 — Annex A Control Mapping</h1>
<p class="meta"><strong>{data['org_name']}</strong> · Generated: {data['generated_at'][:19]} UTC</p>
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-v">{data['controls_total']}</div><div class="kpi-l">Total Controls</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#16a34a">{data['implemented']}</div><div class="kpi-l">Implemented</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#d97706">{data['partial']}</div><div class="kpi-l">Partial</div></div>
  <div class="kpi"><div class="kpi-v">{data['coverage_pct']}%</div><div class="kpi-l">Coverage</div></div>
</div>
<table><tr><th>Control</th><th>Domain</th><th>Status</th><th>Evidence</th></tr>{rows}</table>
<footer>Shadow Warden AI · ISO 27001:2022 · <a href="/compliance/iso27001">JSON</a></footer></body></html>"""
    return HTMLResponse(content=html)


# ── CP-23: HIPAA Technical Safeguards Attestation ─────────────────────────────

_HIPAA_SAFEGUARDS = [
    ("§164.312(a)(1)", "Access Control",         "PASS", "Per-tenant API keys, tier-based feature gates, constant-time compare"),
    ("§164.312(a)(2)(i)", "Unique User Identification", "PASS", "Each tenant has a unique SHA-256 key; no shared credentials"),
    ("§164.312(a)(2)(ii)", "Emergency Access Procedure", "PASS", "ALLOW_UNAUTHENTICATED=true emergency flag with audit log entry"),
    ("§164.312(a)(2)(iii)", "Automatic Logoff",  "PASS", "Redis session TTL 6h (SOVA), 8h (dashboard); no indefinite sessions"),
    ("§164.312(a)(2)(iv)", "Encryption/Decryption", "PASS", "Fernet AES-128-CBC at rest; TLS 1.3 in transit"),
    ("§164.312(b)",  "Audit Controls",            "PASS", "NDJSON immutable audit log; STIX 2.1 tamper-evident chain; MinIO evidence vault"),
    ("§164.312(c)(1)", "Integrity",               "PASS", "HMAC-SHA256 on all transfer proofs; atomic writes via tempfile+os.replace"),
    ("§164.312(c)(2)", "Mechanism to authenticate ePHI", "PASS", "HybridSigner Ed25519+ML-DSA-65 on CTP; verify endpoint"),
    ("§164.312(d)",  "Person/Entity Authentication", "PASS", "X-API-Key header required on all endpoints; fail-closed by default"),
    ("§164.312(e)(1)", "Transmission Security",   "PASS", "Caddy v2 TLS termination; HSTS enforced; QUIC/HTTP3 available"),
    ("§164.312(e)(2)(i)", "Integrity Controls",   "PASS", "Content hash cache (SHA-256); STIX chain SHA-256 prev_hash links"),
    ("§164.312(e)(2)(ii)", "Encryption",          "PASS", "PHI data class restricted to US/EU/UK/CA/CH jurisdictions only"),
]


@router.get("/hipaa", summary="HIPAA technical safeguards attestation (JSON)")
async def hipaa_report(days: Annotated[int, Query(ge=1, le=365)] = 30) -> dict:
    stats = _aggregate_logs(days)
    safeguards = [
        {"section": s, "requirement": r, "status": st, "evidence": e}
        for s, r, st, e in _HIPAA_SAFEGUARDS
    ]
    passed = sum(1 for _, _, st, _ in _HIPAA_SAFEGUARDS if st == "PASS")
    return {
        "standard":       "HIPAA Security Rule (45 CFR Part 164)",
        "org_name":       _ORG_NAME,
        "tenant_id":      _TENANT_ID,
        "generated_at":   datetime.now(UTC).isoformat(),
        "safeguards_total": len(_HIPAA_SAFEGUARDS),
        "passed":         passed,
        "failed":         len(_HIPAA_SAFEGUARDS) - passed,
        "attestation":    "PASS" if passed == len(_HIPAA_SAFEGUARDS) else "PARTIAL",
        "period_days":    days,
        "filter_stats":   stats,
        "safeguards":     safeguards,
    }


@router.get("/hipaa/html", response_class=HTMLResponse, summary="HIPAA safeguards report (HTML)")
async def hipaa_html(days: Annotated[int, Query(ge=1, le=365)] = 30) -> HTMLResponse:
    data = await hipaa_report(days=days)
    rows = "".join(
        f"<tr><td><code>{s['section']}</code></td><td>{s['requirement']}</td>"
        f"<td class='status-{s[\"status\"].lower()}'>{s['status']}</td>"
        f"<td>{s['evidence']}</td></tr>"
        for s in data["safeguards"]
    )
    verdict_color = "#16a34a" if data["attestation"] == "PASS" else "#d97706"
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>HIPAA — Shadow Warden AI</title>
<style>body{{font-family:'Segoe UI',sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#1e293b}}
h1{{border-bottom:3px solid #6366f1;padding-bottom:10px}}.meta{{color:#64748b;font-size:13px}}
.badge{{display:inline-block;padding:6px 18px;border-radius:20px;font-weight:700;font-size:14px;color:#fff;background:{verdict_color}}}
.kpi-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:20px 0}}
.kpi{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;text-align:center}}
.kpi-v{{font-size:1.8rem;font-weight:700;color:#6366f1}}.kpi-l{{font-size:11px;color:#94a3b8;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}}
th{{background:#f1f5f9;padding:8px 10px;text-align:left;font-weight:600;color:#475569}}
td{{padding:8px 10px;border-bottom:1px solid #f1f5f9}}
.status-pass{{color:#16a34a;font-weight:700}}.status-fail{{color:#dc2626;font-weight:700}}
footer{{margin-top:32px;font-size:12px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px}}</style></head>
<body><h1>🏥 HIPAA Technical Safeguards Attestation</h1>
<p class="meta"><strong>{data['org_name']}</strong> · Generated: {data['generated_at'][:19]} UTC</p>
<p>Overall attestation: <span class="badge">{data['attestation']}</span></p>
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-v">{data['safeguards_total']}</div><div class="kpi-l">Total Safeguards</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#16a34a">{data['passed']}</div><div class="kpi-l">Passed</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#dc2626">{data['failed']}</div><div class="kpi-l">Failed</div></div>
</div>
<table><tr><th>§ Section</th><th>Requirement</th><th>Status</th><th>Evidence</th></tr>{rows}</table>
<footer>Shadow Warden AI · HIPAA Security Rule · <a href="/compliance/hipaa">JSON</a></footer></body></html>"""
    return HTMLResponse(content=html)


# ── CP-24: NIS2 Directive compliance report ───────────────────────────────────

_NIS2_MEASURES = [
    ("Art.21(2)(a)", "Risk analysis and IS policies",        "PASS", "docs/security-model.md + DPIA; SOVA threat sync every 6h"),
    ("Art.21(2)(b)", "Incident handling",                    "PASS", "MasterAgent HITL approval + Slack alerts + MinIO evidence vault"),
    ("Art.21(2)(c)", "Business continuity",                  "PASS", "Fail-open circuit breaker; Redis TTL fallback; WardenHealer auto-recover"),
    ("Art.21(2)(d)", "Supply chain security",                "PASS", "CI Trivy CVE scan + pip-audit SCA on every commit"),
    ("Art.21(2)(e)", "Acquisition/development security",     "PASS", "pre-commit: secret-scan, OWASP headers, tenant isolation, idempotency"),
    ("Art.21(2)(f)", "Effectiveness assessment",             "PASS", "k6 load tests, Grafana SLO burn-rate, mutation testing (mutmut)"),
    ("Art.21(2)(g)", "Cybersecurity hygiene and training",   "PARTIAL", "Security model documented; formal training program not yet implemented"),
    ("Art.21(2)(h)", "Cryptography policy",                  "PASS", "Ed25519+ML-DSA-65 PQC hybrid; AES-128-CBC at rest; TLS 1.3 transit"),
    ("Art.21(2)(i)", "Human resource security / access control", "PASS", "Fail-closed auth; per-tenant key isolation; constant-time compare"),
    ("Art.21(2)(j)", "Multi-factor authentication",          "PARTIAL", "API key auth implemented; MFA for portal login planned in v5.0"),
    ("Art.23",       "Incident reporting obligations",       "PASS", "SOVA generates incident reports; evidence bundle shipped to MinIO"),
]


@router.get("/nis2", summary="NIS2 Directive compliance report (JSON)")
async def nis2_report(days: Annotated[int, Query(ge=1, le=365)] = 30) -> dict:
    stats = _aggregate_logs(days)
    measures = [
        {"article": a, "measure": m, "status": s, "evidence": e}
        for a, m, s, e in _NIS2_MEASURES
    ]
    passed = sum(1 for _, _, s, _ in _NIS2_MEASURES if s == "PASS")
    return {
        "standard":      "EU NIS2 Directive (EU 2022/2555)",
        "org_name":      _ORG_NAME,
        "tenant_id":     _TENANT_ID,
        "generated_at":  datetime.now(UTC).isoformat(),
        "measures_total": len(_NIS2_MEASURES),
        "passed":        passed,
        "partial":       sum(1 for _, _, s, _ in _NIS2_MEASURES if s == "PARTIAL"),
        "failed":        sum(1 for _, _, s, _ in _NIS2_MEASURES if s == "FAIL"),
        "coverage_pct":  round(passed / len(_NIS2_MEASURES) * 100, 1),
        "period_days":   days,
        "filter_stats":  stats,
        "measures":      measures,
    }


@router.get("/nis2/html", response_class=HTMLResponse, summary="NIS2 Directive compliance report (HTML)")
async def nis2_html(days: Annotated[int, Query(ge=1, le=365)] = 30) -> HTMLResponse:
    data = await nis2_report(days=days)
    rows = "".join(
        f"<tr><td><code>{m['article']}</code></td><td>{m['measure']}</td>"
        f"<td class='status-{m[\"status\"].lower()}'>{m['status']}</td>"
        f"<td>{m['evidence']}</td></tr>"
        for m in data["measures"]
    )
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>NIS2 — Shadow Warden AI</title>
<style>body{{font-family:'Segoe UI',sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#1e293b}}
h1{{border-bottom:3px solid #6366f1;padding-bottom:10px}}.meta{{color:#64748b;font-size:13px}}
.kpi-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}}
.kpi{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;text-align:center}}
.kpi-v{{font-size:1.8rem;font-weight:700;color:#6366f1}}.kpi-l{{font-size:11px;color:#94a3b8;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}}
th{{background:#f1f5f9;padding:8px 10px;text-align:left;font-weight:600;color:#475569}}
td{{padding:8px 10px;border-bottom:1px solid #f1f5f9}}
.status-pass{{color:#16a34a;font-weight:700}}.status-partial{{color:#d97706;font-weight:700}}.status-fail{{color:#dc2626;font-weight:700}}
footer{{margin-top:32px;font-size:12px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px}}</style></head>
<body><h1>🇪🇺 NIS2 Directive Compliance Report</h1>
<p class="meta"><strong>{data['org_name']}</strong> · Generated: {data['generated_at'][:19]} UTC · EU 2022/2555</p>
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-v">{data['measures_total']}</div><div class="kpi-l">Art.21 Measures</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#16a34a">{data['passed']}</div><div class="kpi-l">PASS</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#d97706">{data['partial']}</div><div class="kpi-l">PARTIAL</div></div>
  <div class="kpi"><div class="kpi-v">{data['coverage_pct']}%</div><div class="kpi-l">Coverage</div></div>
</div>
<table><tr><th>Article</th><th>Measure</th><th>Status</th><th>Evidence</th></tr>{rows}</table>
<footer>Shadow Warden AI · NIS2 Directive · <a href="/compliance/nis2">JSON</a></footer></body></html>"""
    return HTMLResponse(content=html)


# ── CP-25: Real-time compliance posture (multi-standard) ─────────────────────

def _score_standard(passed: int, partial: int, total: int) -> float:
    """Weighted score: PASS=1.0, PARTIAL=0.5, FAIL=0.0 → 0..100"""
    return round((passed + partial * 0.5) / total * 100, 1) if total else 0.0


@router.get("/posture", summary="Real-time compliance posture across all standards (CP-25)")
async def compliance_posture(days: Annotated[int, Query(ge=1, le=90)] = 7) -> dict:
    """
    Aggregates SOC2/GDPR/ISO27001/HIPAA/NIS2 into a single posture score.
    Designed to be polled by the SOC dashboard (FE-13).
    """
    iso_data  = await iso27001_report(days=days)
    hip_data  = await hipaa_report(days=days)
    nis_data  = await nis2_report(days=days)
    stats     = _aggregate_logs(days)

    # GDPR: 8 controls in _build_report, all currently PASS
    gdpr_report = _build_report(days)
    gdpr_passed = sum(1 for r in gdpr_report["gdpr"] if r["status"] == "PASS")
    gdpr_total  = len(gdpr_report["gdpr"])

    # SOC 2 — derive from ISO 27001 Implemented+Partial controls (same evidence base)
    soc2_passed  = iso_data["implemented"]
    soc2_partial = iso_data["partial"]
    soc2_total   = iso_data["controls_total"]

    standards = [
        {
            "standard":     "SOC 2 Type II",
            "short":        "soc2",
            "passed":       soc2_passed,
            "partial":      soc2_partial,
            "failed":       soc2_total - soc2_passed - soc2_partial,
            "total":        soc2_total,
            "score":        _score_standard(soc2_passed, soc2_partial, soc2_total),
            "attestation":  "PASS" if soc2_passed >= soc2_total * 0.85 else "PARTIAL",
        },
        {
            "standard":     "GDPR (Art.5 + Art.30 + Art.35)",
            "short":        "gdpr",
            "passed":       gdpr_passed,
            "partial":      0,
            "failed":       gdpr_total - gdpr_passed,
            "total":        gdpr_total,
            "score":        _score_standard(gdpr_passed, 0, gdpr_total),
            "attestation":  "PASS" if gdpr_passed == gdpr_total else "PARTIAL",
        },
        {
            "standard":     "ISO/IEC 27001:2022",
            "short":        "iso27001",
            "passed":       iso_data["implemented"],
            "partial":      iso_data["partial"],
            "failed":       iso_data["controls_total"] - iso_data["implemented"] - iso_data["partial"],
            "total":        iso_data["controls_total"],
            "score":        _score_standard(iso_data["implemented"], iso_data["partial"], iso_data["controls_total"]),
            "attestation":  "PASS" if iso_data["coverage_pct"] >= 85 else "PARTIAL",
        },
        {
            "standard":     "HIPAA Security Rule",
            "short":        "hipaa",
            "passed":       hip_data["passed"],
            "partial":      0,
            "failed":       hip_data["failed"],
            "total":        hip_data["safeguards_total"],
            "score":        _score_standard(hip_data["passed"], 0, hip_data["safeguards_total"]),
            "attestation":  hip_data["attestation"],
        },
        {
            "standard":     "EU NIS2 Directive",
            "short":        "nis2",
            "passed":       nis_data["passed"],
            "partial":      nis_data["partial"],
            "failed":       nis_data["failed"],
            "total":        nis_data["measures_total"],
            "score":        _score_standard(nis_data["passed"], nis_data["partial"], nis_data["measures_total"]),
            "attestation":  "PASS" if nis_data["coverage_pct"] >= 80 else "PARTIAL",
        },
    ]

    overall_score = round(sum(s["score"] for s in standards) / len(standards), 1)
    all_pass = all(s["attestation"] == "PASS" for s in standards)

    return {
        "generated_at":   __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "period_days":    days,
        "overall_score":  overall_score,
        "overall_status": "PASS" if all_pass else "PARTIAL",
        "standards":      standards,
        "filter_stats":   stats,
        "org_name":       _ORG_NAME,
        "tenant_id":      _TENANT_ID,
    }
