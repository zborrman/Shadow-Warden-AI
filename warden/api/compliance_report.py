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
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse, Response

from warden.auth_guard import require_api_key

try:
    from warden.billing.feature_gate import require_feature as _require_feature
    _POSTURE_GATE = [_require_feature("compliance_scoring_enabled")]
except Exception:
    _POSTURE_GATE = []

log = logging.getLogger("warden.api.compliance_report")

router = APIRouter(prefix="/compliance", tags=["compliance"])

# Unprefixed router for regulator-expected paths (e.g. /api/compliance/gdpr/ropa)
router_api = APIRouter(tags=["compliance"])

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
    pii_hits = sum(1 for e in entries if bool(e.get("secrets_found", [])))
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


# ── CP-22: ISO 27001:2022 Annex A — complete 93-control mapping ───────────────
# Format: (control_id, theme, domain_name, status, evidence)
# Themes: Organizational (A.5), People (A.6), Physical (A.7), Technological (A.8)
# Statuses: Implemented | Partial | Delegated
#   Implemented — platform actively provides this control
#   Partial     — partially implemented; known gap noted in evidence
#   Delegated   — responsibility held by infrastructure provider (Hetzner VPS)

_ISO27001_CONTROLS_V2: list[tuple[str, str, str, str, str]] = [
    # ── A.5 Organizational controls (37) ─────────────────────────────────────
    ("A.5.1",  "Organizational", "Policies for information security",
     "Implemented",  "docs/security-model.md + docs/dpia.md + docs/soc2-evidence.md define policy set"),
    ("A.5.2",  "Organizational", "Information security roles and responsibilities",
     "Implemented",  "Roles: WARDEN_API_KEY owner, ADMIN_KEY operator, SOVA operator, MasterAgent sub-agents"),
    ("A.5.3",  "Organizational", "Segregation of duties",
     "Partial",      "MasterAgent REQUIRES_APPROVAL gate; HMAC task tokens prevent cross-agent injection; single-operator gap"),
    ("A.5.4",  "Organizational", "Management responsibilities",
     "Partial",      "CLAUDE.md defines responsibilities; formal RACI not yet documented"),
    ("A.5.5",  "Organizational", "Contact with authorities",
     "Delegated",    "Hetzner GmbH handles statutory authority liaison for datacenter"),
    ("A.5.6",  "Organizational", "Contact with special interest groups",
     "Delegated",    "ArXiv + OSV intel feeds provide passive threat-intel community participation"),
    ("A.5.7",  "Organizational", "Threat intelligence",
     "Implemented",  "OSV CVE scanner + ArXiv LLM-attack paper hunter; sova_threat_sync every 6h; intel_bridge auto-evolves corpus"),
    ("A.5.8",  "Organizational", "Information security in project management",
     "Partial",      "CI lint+test+coverage gate on every PR; formal security-review checklist in docs/security-remediation.md"),
    ("A.5.9",  "Organizational", "Inventory of information and other associated assets",
     "Implemented",  "secrets_gov/inventory.py — SQLite-backed secrets registry, risk scoring, expiry tracking"),
    ("A.5.10", "Organizational", "Acceptable use of information and other associated assets",
     "Partial",      "API key terms enforced via tier gates; acceptable-use policy not yet published externally"),
    ("A.5.11", "Organizational", "Return of assets",
     "Delegated",    "Key revocation = immediate asset return; hardware managed by Hetzner"),
    ("A.5.12", "Organizational", "Classification of information",
     "Implemented",  "5 data classes: GENERAL / PII / FINANCIAL / PHI / CLASSIFIED — enforced by SecretRedactor + sovereign router"),
    ("A.5.13", "Organizational", "Labelling of information",
     "Implemented",  "UECIID labels (SEP-{11 base-62}) + Sovereign Pod Tags per entity; frontmatter tags on Obsidian notes"),
    ("A.5.14", "Organizational", "Information transfer",
     "Implemented",  "SEP peering with HMAC handshake + Causal Transfer Guard (P≥0.70 block) + STIX 2.1 audit chain"),
    ("A.5.15", "Organizational", "Access control",
     "Implemented",  "Per-tenant API keys, SHA-256 constant-time compare, tier-based feature gates, fail-closed by default"),
    ("A.5.16", "Organizational", "Identity management",
     "Implemented",  "auth_guard.py — multi-key JSON registry; Fernet-encrypted vault; HMAC-SHA256 reverse map"),
    ("A.5.17", "Organizational", "Authentication information",
     "Implemented",  "X-API-Key SHA-256 hash store; no plaintext in memory; TOTP 2FA at Individual+"),
    ("A.5.18", "Organizational", "Access rights",
     "Implemented",  "require_feature() / require_plan() FastAPI deps; ADMIN_KEY for billing; VAULT_MASTER_KEY for crypto"),
    ("A.5.19", "Organizational", "Information security in supplier relationships",
     "Implemented",  "vendor_gov/registry.py — AI Vendor Register, DPA tracking, expiry alerts (BL-22)"),
    ("A.5.20", "Organizational", "Addressing information security within supplier agreements",
     "Partial",      "DPA records tracked in vendor registry; standard DPA template not yet automated"),
    ("A.5.21", "Organizational", "Managing information security in the ICT supply chain",
     "Partial",      "Trivy CVE scan in CI; SBOM generated via cosign; supplier_risk scoring (CM-36)"),
    ("A.5.22", "Organizational", "Monitoring, review and change management of supplier services",
     "Implemented",  "secrets_gov/lifecycle.py — auto-retire, rotation scheduling, expiry alerts per vendor"),
    ("A.5.23", "Organizational", "Information security for use of cloud services",
     "Implemented",  "ShadowAIDetector — 18-provider fingerprint DB, subnet probe, DNS telemetry; MONITOR/BLOCK_DENYLIST policy"),
    ("A.5.24", "Organizational", "Information security incident management planning and preparation",
     "Implemented",  "communities/incident_register.py — STIX-linked severity journal; auto-log from filter events"),
    ("A.5.25", "Organizational", "Assessment and decision on information security events",
     "Implemented",  "CausalArbiter — Bayesian DAG P(HIGH_RISK|evidence), do-calculus, counterfactual remediation"),
    ("A.5.26", "Organizational", "Response to information security incidents",
     "Implemented",  "alerting.py — Slack + PagerDuty on HIGH/BLOCK; WardenHealer autonomous anomaly response"),
    ("A.5.27", "Organizational", "Learning from information security incidents",
     "Implemented",  "EvolutionEngine — Claude Opus auto-rule generation from HIGH/BLOCK events; hot-reload corpus"),
    ("A.5.28", "Organizational", "Collection of evidence",
     "Implemented",  "STIX 2.1 tamper-evident audit chain (SHA-256 prev_hash) + MinIO evidence vault (warden-evidence/)"),
    ("A.5.29", "Organizational", "Information security during disruption",
     "Partial",      "Fail-open design for optional components; Redis TTL fallback; full DR runbook not yet published"),
    ("A.5.30", "Organizational", "ICT readiness for business continuity",
     "Partial",      "Docker Compose restart policies + healthchecks; single-node; multi-region topology planned"),
    ("A.5.31", "Organizational", "Legal, statutory, regulatory and contractual requirements",
     "Implemented",  "GDPR Art.35 DPIA (docs/dpia.md), SOC 2 Type II evidence (docs/soc2-evidence.md), HIPAA + NIS2 reports"),
    ("A.5.32", "Organizational", "Intellectual property rights",
     "Delegated",    "Proprietary license declared in LICENSE; OSS dependencies audited via SBOM in CI"),
    ("A.5.33", "Organizational", "Protection of records",
     "Implemented",  "NDJSON immutable audit log, atomic writes via tempfile+os.replace(), MinIO S3 retention"),
    ("A.5.34", "Organizational", "Privacy and protection of PII",
     "Implemented",  "SecretRedactor (15 patterns + Shannon entropy); GDPR Art.17 purge API; no content logged (data minimisation)"),
    ("A.5.35", "Organizational", "Independent review of information security",
     "Partial",      "mutmut mutation testing + adversarial test suite; third-party penetration test not yet scheduled"),
    ("A.5.36", "Organizational", "Compliance with policies, rules and standards for information security",
     "Implemented",  "Ruff lint + mypy type-check mandatory in CI; coverage gate ≥75%; compliance scoring dashboard (CP-25)"),
    ("A.5.37", "Organizational", "Documented operating procedures",
     "Implemented",  "CLAUDE.md (200-line ops runbook), docs/deployment-hardening.md, docker-compose.yml with comments"),

    # ── A.6 People controls (8) ──────────────────────────────────────────────
    ("A.6.1",  "People", "Screening",
     "Delegated",    "Hetzner staff screening; background-check policy for internal operators not yet formalised"),
    ("A.6.2",  "People", "Terms and conditions of employment",
     "Delegated",    "Employment contracts managed by legal entity; API key usage terms in ToS"),
    ("A.6.3",  "People", "Information security awareness, education and training",
     "Partial",      "communities/training_records.py — HMAC-attested completion records (CM-38); external LMS not yet integrated"),
    ("A.6.4",  "People", "Disciplinary process",
     "Delegated",    "HR disciplinary process managed by legal entity; API key revocation = immediate technical sanction"),
    ("A.6.5",  "People", "Responsibilities after termination or change of employment",
     "Partial",      "API key rotation on role change; sova_rotation_check cron 02:00 UTC daily; formal exit checklist pending"),
    ("A.6.6",  "People", "Confidentiality or non-disclosure agreements",
     "Delegated",    "NDA managed by legal entity; tenant data isolated by design (no cross-tenant leakage)"),
    ("A.6.7",  "People", "Remote working",
     "Implemented",  "MASQUE H3/H2 jurisdictional tunnels; TLS 1.3 mandatory; all access via authenticated API endpoints"),
    ("A.6.8",  "People", "Information security event reporting",
     "Implemented",  "Slack webhook alerts on HIGH/BLOCK; /agent/sova for natural-language incident queries; STIX audit chain"),

    # ── A.7 Physical controls (14) ───────────────────────────────────────────
    ("A.7.1",  "Physical", "Physical security perimeters",
     "Delegated",    "Hetzner Nuremberg datacenter — ISO 27001 certified facility; cage-level physical security"),
    ("A.7.2",  "Physical", "Physical entry",
     "Delegated",    "Hetzner datacenter access controls; biometric + badge authentication at facility level"),
    ("A.7.3",  "Physical", "Securing offices, rooms and facilities",
     "Delegated",    "Hetzner datacenter physical security; application is fully cloud-hosted"),
    ("A.7.4",  "Physical", "Physical security monitoring",
     "Delegated",    "Hetzner datacenter CCTV and security monitoring; no on-premise hardware"),
    ("A.7.5",  "Physical", "Protecting against physical and environmental threats",
     "Delegated",    "Hetzner redundant power, cooling, fire suppression; Tier III+ datacenter standards"),
    ("A.7.6",  "Physical", "Working in secure areas",
     "Delegated",    "Hetzner datacenter secure-area procedures; remote-only platform development"),
    ("A.7.7",  "Physical", "Clear desk and clear screen",
     "Delegated",    "Remote-work policy; no sensitive data displayed in shared physical spaces by design"),
    ("A.7.8",  "Physical", "Equipment siting and protection",
     "Delegated",    "Hetzner datacenter equipment placement and cable management standards"),
    ("A.7.9",  "Physical", "Security of assets off-premises",
     "Implemented",  "MinIO S3 encrypted object storage; Fernet-encrypted secret keys at rest; no unencrypted off-site data"),
    ("A.7.10", "Physical", "Storage media",
     "Delegated",    "Hetzner encrypted volumes; Docker named volumes for model persistence; no removable media"),
    ("A.7.11", "Physical", "Supporting utilities",
     "Delegated",    "Hetzner UPS, generator, redundant power feeds; datacenter-level utility management"),
    ("A.7.12", "Physical", "Cabling security",
     "Delegated",    "Hetzner structured cabling standards; TLS encryption renders physical cable tap ineffective"),
    ("A.7.13", "Physical", "Equipment maintenance",
     "Delegated",    "Hetzner hardware maintenance SLA; immutable Docker images eliminate OS-level patching risk"),
    ("A.7.14", "Physical", "Secure disposal or re-use of equipment",
     "Delegated",    "Hetzner certified data destruction on decommission; platform uses ephemeral containers"),

    # ── A.8 Technological controls (34) ──────────────────────────────────────
    ("A.8.1",  "Technological", "User endpoint devices",
     "Partial",      "BrowserSandbox (Playwright) isolates visual-patrol pages; BYOD policy for developer endpoints pending"),
    ("A.8.2",  "Technological", "Privileged access rights",
     "Implemented",  "ADMIN_KEY for billing ops; MasterAgent sub-agents use least-privilege tool subsets; no root in containers (UID 10001)"),
    ("A.8.3",  "Technological", "Information access restriction",
     "Implemented",  "Per-tenant API key isolation; tier-based feature gates; require_feature() FastAPI dependency"),
    ("A.8.4",  "Technological", "Access to source code",
     "Partial",      "GitHub private repo with branch protection; no external contractor access; code review required on PRs"),
    ("A.8.5",  "Technological", "Secure authentication",
     "Implemented",  "X-API-Key SHA-256 hash; constant-time hmac.compare_digest(); TOTP 2FA; fail-closed: RuntimeError if key unset"),
    ("A.8.6",  "Technological", "Capacity management",
     "Implemented",  "Redis ERS sliding window rate-limiting; Prometheus REQUESTS_TOTAL + latency histograms; Grafana SLO alerts"),
    ("A.8.7",  "Technological", "Protection against malware",
     "Implemented",  "9-layer filter pipeline blocks injection, jailbreak, prompt-stuffing payloads; TopologicalGatekeeper <2ms"),
    ("A.8.8",  "Technological", "Management of technical vulnerabilities",
     "Implemented",  "OSV API CVE scan + ArXiv paper hunter (intel_ops.py); sova_threat_sync every 6h; Trivy image scan in CI"),
    ("A.8.9",  "Technological", "Configuration management",
     "Implemented",  "Docker Compose + env-var configuration; CLAUDE.md version-controlled runbook; no secrets in git"),
    ("A.8.10", "Technological", "Information deletion",
     "Implemented",  "DELETE /gdpr/purge (Art.17); ARQ cron for retention enforcement; GDPR_RETENTION_DAYS configurable per tenant"),
    ("A.8.11", "Technological", "Data masking",
     "Implemented",  "masking/engine.py — Fernet-encrypted PII vault; HMAC-SHA256 reverse map; no plaintext PII in memory"),
    ("A.8.12", "Technological", "Data leakage prevention",
     "Implemented",  "SecretRedactor — 15 regex patterns + Shannon entropy scan; blocks AWS keys, JWT, Fernet, PEM, PII"),
    ("A.8.13", "Technological", "Information backup",
     "Implemented",  "MinIO S3 background ship; warden-logs/<date>/<id>.json retention; fail-open on MinIO unavailable"),
    ("A.8.14", "Technological", "Redundancy of information processing facilities",
     "Partial",      "Fail-open design for optional components; single Hetzner VPS; multi-node HA topology planned for v6"),
    ("A.8.15", "Technological", "Logging",
     "Implemented",  "NDJSON audit log (metadata only, no content — GDPR); atomic writes; Splunk HEC + Elastic ECS SIEM integration"),
    ("A.8.16", "Technological", "Monitoring activities",
     "Implemented",  "Prometheus /metrics + Grafana dashboards; SLO alerts (P99 latency, 5xx rate, shadow ban rate, corpus drift)"),
    ("A.8.17", "Technological", "Clock synchronisation",
     "Implemented",  "Docker host NTP; all timestamps UTC (datetime.now(UTC)); STIX chain uses ISO 8601 with timezone"),
    ("A.8.18", "Technological", "Use of privileged utility programs",
     "Implemented",  "entrypoint.sh runs as wardenuser (UID 10001); privileged utilities require ADMIN_KEY; no sudo in containers"),
    ("A.8.19", "Technological", "Installation of software on operational systems",
     "Implemented",  "Immutable Docker images pinned to digest; no runtime pip-install; CI Trivy gate blocks known-vulnerable layers"),
    ("A.8.20", "Technological", "Networks security",
     "Implemented",  "Caddy v2 reverse proxy; internal Docker network (not exposed); no plaintext HTTP on port 80 (redirect only)"),
    ("A.8.21", "Technological", "Security of network services",
     "Implemented",  "TLS 1.3 termination at Caddy; HSTS enforced; Alt-Svc QUIC/HTTP3; MASQUE H3 for sovereign tunnels"),
    ("A.8.22", "Technological", "Segregation of networks",
     "Implemented",  "Docker internal network isolates warden (8001) from public; proxy (80/443) only exposed service"),
    ("A.8.23", "Technological", "Web filtering",
     "Implemented",  "PhishGuard — URL phishing detection; SE-Arbiter social-engineering classification; SEC-GAP-002 fixed"),
    ("A.8.24", "Technological", "Use of cryptography",
     "Implemented",  "Fernet AES-128-CBC at-rest; TLS 1.3 in-transit; Ed25519+ML-DSA-65 hybrid PQC signatures; X25519+ML-KEM-768 KEM"),
    ("A.8.25", "Technological", "Secure development lifecycle",
     "Implemented",  "CI: ruff lint + mypy typecheck + pytest ≥75% coverage + mutmut mutation testing + adversarial test suite"),
    ("A.8.26", "Technological", "Application security requirements",
     "Implemented",  "OWASP LLM Top-10 coverage (docs/security-model.md §2); injection, jailbreak, PII-leak all addressed"),
    ("A.8.27", "Technological", "Secure system architecture and engineering principles",
     "Implemented",  "9-layer defense-in-depth (topology→obfuscation→secrets→semantic→brain→causal→phish→ERS→decision)"),
    ("A.8.28", "Technological", "Secure coding",
     "Implemented",  "Ruff B/S/C4/SIM rules enforce safe patterns; CPT drift gate prevents data poisoning; evolution regex safety gate"),
    ("A.8.29", "Technological", "Security testing in development and acceptance",
     "Implemented",  "pytest adversarial markers; mutation testing threshold 20; CI blocks merge on test failure or coverage drop"),
    ("A.8.30", "Technological", "Outsourced development",
     "Partial",      "GitHub Actions CI runs on GitHub-hosted runners (Microsoft); runner supply-chain risk accepted; no external contractors"),
    ("A.8.31", "Technological", "Separation of development, test and production environments",
     "Implemented",  "Docker Compose profiles; test env uses REDIS_URL=memory://, MODEL_CACHE_DIR=/tmp; prod uses named volumes"),
    ("A.8.32", "Technological", "Change management",
     "Implemented",  "Git branch protection; CI must pass before merge; semantic commit convention; CLAUDE.md records design decisions"),
    ("A.8.33", "Technological", "Test information",
     "Implemented",  "Test fixtures use synthetic data only; GDPR: no production content in tests; conftest.py sets LOGS_PATH=/tmp"),
    ("A.8.34", "Technological", "Protection of information systems during audit testing",
     "Implemented",  "BrowserSandbox (Playwright headless) isolates visual-patrol; SWFE FakeContext for in-process test isolation"),
]

# Legacy alias — existing callers that iterate 4-tuples still work
_ISO27001_CONTROLS = [(c, d, s, e) for c, _, d, s, e in _ISO27001_CONTROLS_V2]

_ISO27001_THEMES = ["Organizational", "People", "Physical", "Technological"]


def _iso27001_data(days: int) -> dict:
    """Shared data builder for JSON + HTML + PDF endpoints."""
    stats      = _aggregate_logs(days)
    controls   = [
        {"control": c, "theme": th, "domain": d, "status": s, "evidence": e}
        for c, th, d, s, e in _ISO27001_CONTROLS_V2
    ]
    by_theme = {
        t: [x for x in controls if x["theme"] == t]
        for t in _ISO27001_THEMES
    }
    implemented  = sum(1 for x in controls if x["status"] == "Implemented")
    partial      = sum(1 for x in controls if x["status"] == "Partial")
    delegated    = sum(1 for x in controls if x["status"] == "Delegated")
    total        = len(controls)
    coverage_pct = round((implemented + partial * 0.5) / total * 100, 1) if total else 0.0
    return {
        "standard":        "ISO/IEC 27001:2022",
        "org_name":        _ORG_NAME,
        "tenant_id":       _TENANT_ID,
        "generated_at":    datetime.now(UTC).isoformat(),
        "controls_total":  total,
        "implemented":     implemented,
        "partial":         partial,
        "delegated":       delegated,
        "coverage_pct":    coverage_pct,
        "period_days":     days,
        "filter_stats":    stats,
        "controls":        controls,
        "by_theme":        by_theme,
        "themes": {
            t: {
                "total":       len(by_theme[t]),
                "implemented": sum(1 for x in by_theme[t] if x["status"] == "Implemented"),
                "partial":     sum(1 for x in by_theme[t] if x["status"] == "Partial"),
                "delegated":   sum(1 for x in by_theme[t] if x["status"] == "Delegated"),
            }
            for t in _ISO27001_THEMES
        },
    }


try:
    from warden.billing.feature_gate import require_feature as _require_feature
    _ISO_GATE = [_require_feature("iso27001_enabled")]
except Exception:
    _ISO_GATE = []


@router.get("/iso27001", summary="ISO 27001:2022 Annex A control mapping — all 93 controls (CP-22)", dependencies=_ISO_GATE)
async def iso27001_report(days: Annotated[int, Query(ge=1, le=365)] = 30) -> dict:
    return _iso27001_data(days)


@router.get("/iso27001/html", response_class=HTMLResponse,
            summary="ISO 27001:2022 control mapping — print-ready HTML (CP-22)", dependencies=_ISO_GATE)
async def iso27001_html(days: Annotated[int, Query(ge=1, le=365)] = 30) -> HTMLResponse:
    data = _iso27001_data(days)

    def _rows_for_theme(theme: str) -> str:
        out = [f"<tr class='theme-hdr'><td colspan='4' style='background:#f1f5f9;font-weight:700;"
               f"color:#475569;padding:10px'>{theme} Controls "
               f"({data['themes'][theme]['implemented']}/{data['themes'][theme]['total']} implemented)</td></tr>"]
        for c in data["by_theme"].get(theme, []):
            css = {"Implemented": "status-implemented", "Partial": "status-partial",
                   "Delegated": "status-delegated"}.get(c["status"], "")
            out.append(
                f"<tr><td><code>{c['control']}</code></td><td>{c['domain']}</td>"
                f"<td class='{css}'>{c['status']}</td><td>{c['evidence']}</td></tr>"
            )
        return "".join(out)

    all_rows = "".join(_rows_for_theme(t) for t in _ISO27001_THEMES)
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>ISO 27001:2022 — Shadow Warden AI</title>
<style>
body{{font-family:'Segoe UI',sans-serif;max-width:1080px;margin:40px auto;padding:0 20px;color:#1e293b}}
h1{{border-bottom:3px solid #6366f1;padding-bottom:10px;color:#0f172a}}
.meta{{color:#64748b;font-size:13px;margin-bottom:20px}}
.kpi-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0}}
.kpi{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;text-align:center}}
.kpi-v{{font-size:1.8rem;font-weight:700;color:#6366f1}}
.kpi-l{{font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}}
.theme-bar{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:16px 0 24px}}
.tb{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:10px 12px}}
.tb-name{{font-size:11px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.05em}}
.tb-score{{font-size:1.4rem;font-weight:800;color:#6366f1;margin:4px 0 2px}}
.tb-bar{{height:5px;background:#e2e8f0;border-radius:3px;overflow:hidden}}
.tb-fill{{height:100%;background:linear-gradient(90deg,#6366f1,#8b5cf6);border-radius:3px}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}}
th{{background:#e2e8f0;padding:8px 10px;text-align:left;font-weight:600;color:#475569;font-size:11px;text-transform:uppercase;letter-spacing:.04em}}
td{{padding:7px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top}}
code{{font-family:monospace;font-size:11.5px;background:#f1f5f9;padding:1px 5px;border-radius:3px;color:#6366f1}}
.status-implemented{{color:#16a34a;font-weight:700}}
.status-partial{{color:#d97706;font-weight:700}}
.status-delegated{{color:#2563eb;font-weight:700}}
footer{{margin-top:32px;font-size:12px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px}}
@media print{{body{{margin:20px}}.kpi-v{{font-size:1.4rem}}}}
</style></head>
<body>
<h1>🔐 ISO/IEC 27001:2022 — Annex A Control Mapping</h1>
<p class="meta"><strong>{data['org_name']}</strong> · Generated: {data['generated_at'][:19]} UTC · Period: {days} days</p>

<div class="kpi-grid">
  <div class="kpi"><div class="kpi-v">{data['controls_total']}</div><div class="kpi-l">Total Controls</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#16a34a">{data['implemented']}</div><div class="kpi-l">Implemented</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#d97706">{data['partial']}</div><div class="kpi-l">Partial</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#2563eb">{data['delegated']}</div><div class="kpi-l">Delegated</div></div>
  <div class="kpi"><div class="kpi-v">{data['coverage_pct']}%</div><div class="kpi-l">Coverage</div></div>
</div>

<div class="theme-bar">
{"".join(
    f'<div class="tb"><div class="tb-name">{t}</div>'
    f'<div class="tb-score">{round(data["themes"][t]["implemented"]/max(data["themes"][t]["total"],1)*100)}%</div>'
    f'<div style="font-size:10px;color:#94a3b8;margin-bottom:5px">'
    f'{data["themes"][t]["implemented"]}/{data["themes"][t]["total"]} implemented</div>'
    f'<div class="tb-bar"><div class="tb-fill" style="width:{round(data["themes"][t]["implemented"]/max(data["themes"][t]["total"],1)*100)}%"></div></div>'
    f'</div>'
    for t in _ISO27001_THEMES
)}
</div>

<table>
<tr><th>Control</th><th>Domain</th><th>Status</th><th>Evidence</th></tr>
{all_rows}
</table>

<footer>Shadow Warden AI · ISO/IEC 27001:2022 · 93 Annex A Controls · <a href="/compliance/iso27001">JSON</a> · CP-22</footer>
</body></html>"""
    return HTMLResponse(content=html, headers={"X-Report-Format": "html"})


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
        f"<td class='status-{s['status'].lower()}'>{s['status']}</td>"
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
        f"<td class='status-{m['status'].lower()}'>{m['status']}</td>"
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

# Ring buffer: up to 168 hourly snapshots (one week) stored in-process.
# Populated on every /posture call so the /history endpoint has data.
_posture_history: deque[dict] = deque(maxlen=168)


def _score_standard(passed: int, partial: int, total: int) -> float:
    """Weighted score: PASS=1.0, PARTIAL=0.5, FAIL=0.0 → 0..100"""
    return round((passed + partial * 0.5) / total * 100, 1) if total else 0.0


@router.get("/posture", summary="Real-time compliance posture across all standards (CP-25)", dependencies=_POSTURE_GATE)
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

    now = datetime.now(UTC)
    result = {
        "generated_at":   now.isoformat(),
        "period_days":    days,
        "overall_score":  overall_score,
        "overall_status": "PASS" if all_pass else "PARTIAL",
        "standards":      standards,
        "filter_stats":   stats,
        "org_name":       _ORG_NAME,
        "tenant_id":      _TENANT_ID,
    }

    # Append lightweight snapshot to history ring buffer
    _posture_history.append({
        "ts":             now.isoformat(),
        "overall_score":  overall_score,
        "overall_status": result["overall_status"],
        "scores":         {s["short"]: s["score"] for s in standards},
    })

    return result


@router.get("/history", summary="Compliance score history — last N snapshots (CP-25)", dependencies=_POSTURE_GATE)
async def compliance_history(
    hours: Annotated[int, Query(ge=1, le=168, description="Number of past hours to return")] = 24,
) -> dict:
    """
    Returns up to `hours` compliance posture snapshots collected by /compliance/posture.
    Snapshots are stored in a 168-entry (1-week) ring buffer per process.
    Call /compliance/posture first to seed data.
    """
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    snapshots = [
        s for s in _posture_history
        if datetime.fromisoformat(s["ts"]) >= cutoff
    ]
    return {
        "hours":     hours,
        "count":     len(snapshots),
        "snapshots": snapshots,
    }


# ── CP-30: Real-time Compliance Gap Analysis ─────────────────────────────────
#
# These endpoints build on the existing /posture infrastructure but add live
# multi-source aggregation, per-gap remediation guidance, and a WebSocket
# channel for real-time dashboard updates.

try:
    _CP30_GATE = [_require_feature("compliance_scoring_enabled")]
except Exception:
    _CP30_GATE = []


@router.get("/posture/gaps", summary="List all compliance gaps with remediation guidance (CP-30)", dependencies=_CP30_GATE)
async def compliance_gaps(
    tenant_id: str = "default",
    severity:  str | None = None,
    framework: str | None = None,
) -> dict:
    """
    Returns all currently detected compliance gaps across GDPR, SOC 2,
    ISO 27001, and HIPAA, with remediation instructions for each.
    Filtered by `severity` (high/medium/low) or `framework` (gdpr/soc2/iso27001/hipaa).
    """
    from warden.compliance.posture_service import CompliancePostureService
    report = CompliancePostureService().get_current_posture(tenant_id)
    all_gaps = [g for f in report.frameworks for g in f.gaps]
    if severity:
        all_gaps = [g for g in all_gaps if g.severity == severity.lower()]
    if framework:
        all_gaps = [
            g for f in report.frameworks for g in f.gaps
            if f.framework == framework.lower()
        ]
    return {
        "tenant_id": tenant_id,
        "total":     len(all_gaps),
        "gaps":      [g.to_dict() for g in all_gaps],
    }


@router.get("/posture/{framework}", summary="Per-framework compliance detail (CP-30)", dependencies=_CP30_GATE)
async def compliance_framework_detail(
    framework: str,
    tenant_id: str = "default",
) -> dict:
    """
    Returns score, status, passed/total controls, and gap list for a single
    framework: gdpr | soc2 | iso27001 | hipaa
    """
    from warden.compliance.posture_service import CompliancePostureService
    report = CompliancePostureService().get_current_posture(tenant_id)
    match = next((f for f in report.frameworks if f.framework == framework.lower()), None)
    if not match:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Framework {framework!r} not found. "
                            "Valid: gdpr, soc2, iso27001, hipaa")
    return match.to_dict()


@router.post("/posture/recalculate", summary="Force cache invalidation and recompute posture (CP-30)", dependencies=_CP30_GATE)
async def compliance_recalculate(tenant_id: str = "default") -> dict:
    """Clears the Redis cache and recomputes the posture report immediately."""
    from warden.compliance.posture_service import CompliancePostureService
    svc = CompliancePostureService()
    svc.invalidate_cache(tenant_id)
    report = svc.get_current_posture(tenant_id)
    return {"status": "recomputed", **report.to_dict()}


# ── WebSocket: real-time compliance updates ───────────────────────────────────

import asyncio as _asyncio  # noqa: E402 — placed after guard

from fastapi import WebSocket, WebSocketDisconnect  # noqa: E402


@router.post("/evidence/generate")
async def generate_evidence_bundle_endpoint(tenant_id: str = "default") -> dict:
    """Generate a SOC 2 Type II evidence bundle ZIP and return a presigned download URL. (TC-04)"""
    try:
        from warden.compliance.evidence_bundle import generate_evidence_bundle  # noqa: PLC0415
        result = await generate_evidence_bundle(tenant_id)
        return result
    except Exception as exc:
        from fastapi import HTTPException  # noqa: PLC0415
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.websocket("/ws")
async def compliance_ws(ws: WebSocket, tenant_id: str = "default") -> None:
    """
    WebSocket endpoint — sends a ComplianceReport immediately on connect,
    then re-sends every 30 s (or when /posture/recalculate is called and
    publishes to the compliance:events Redis channel).
    """
    await ws.accept()
    try:
        from warden.compliance.posture_service import CompliancePostureService
        svc = CompliancePostureService()
        await ws.send_json(svc.get_current_posture(tenant_id).to_dict())
        while True:
            await _asyncio.sleep(30)
            await ws.send_json(svc.get_current_posture(tenant_id).to_dict())
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


# ── Live compliance endpoints (migrated from main.py inline, Phase 3) ─────────
# These read the AgentMonitor / AuditTrail singletons from warden.runtime,
# published by main.py in lifespan (avoids importing warden.main).


@router.get(
    "/art30",
    summary="GDPR Article 30 Record of Processing Activities",
    dependencies=[Depends(require_api_key)],
)
async def compliance_art30(days: float = 30, format: str = "json"):
    """
    Generate a GDPR Art. 30 RoPA from real traffic data.

    Set ``format=html`` to receive a styled HTML document ready for DPO sign-off
    (print to PDF from the browser).  Default is ``json``.
    """
    import asyncio  # noqa: PLC0415

    from fastapi.responses import HTMLResponse as _HTMLResponse  # noqa: PLC0415

    from warden.compliance.art30 import Art30Generator  # noqa: PLC0415

    gen    = Art30Generator()
    record = await asyncio.to_thread(gen.generate, days)
    if format.lower() == "html":
        html = await asyncio.to_thread(gen.to_html, record)
        return _HTMLResponse(content=html)
    return record


@router.get(
    "/soc2/export",
    summary="SOC 2 Evidence Bundle — ZIP archive for auditors",
    dependencies=[Depends(require_api_key)],
)
async def compliance_soc2_export(days: float = 30):
    """
    Export a tamper-evident ZIP bundle containing:
    config snapshot, threat statistics, audit chain status,
    evolved rules, session summaries, and SHA-256 audit manifest.

    Safe to share with external auditors — no prompt content or PII values included.
    """
    import asyncio  # noqa: PLC0415
    from datetime import UTC, datetime  # noqa: PLC0415

    from fastapi.responses import StreamingResponse  # noqa: PLC0415

    from warden.compliance.soc2 import SOC2Exporter  # noqa: PLC0415
    from warden.runtime import runtime as _runtime  # noqa: PLC0415

    exporter = SOC2Exporter(audit_trail=_runtime.get("audit_trail"))
    buf      = await asyncio.to_thread(exporter.export_bundle, days)
    slug     = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    filename = f"soc2_evidence_{slug}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/incident/{session_id}",
    summary="Incident Post-Mortem report for a session or ERS entity",
    dependencies=[Depends(require_api_key)],
)
async def compliance_incident_report(
    session_id: str,
    entity_key: str | None = None,
    format: str = "json",
):
    """
    Generate a post-mortem report for *session_id*.

    Includes threat timeline, detected patterns, attestation chain status,
    ERS profile (if *entity_key* provided), and recommended actions.

    Set ``format=html`` for a printable HTML document.
    """
    import asyncio  # noqa: PLC0415

    from fastapi.responses import HTMLResponse as _HTMLResponse  # noqa: PLC0415

    from warden.compliance.incident import IncidentReporter  # noqa: PLC0415
    from warden.runtime import runtime as _runtime  # noqa: PLC0415

    reporter = IncidentReporter(agent_monitor=_runtime.get("agent_monitor"))
    report   = await asyncio.to_thread(reporter.generate, session_id, entity_key)
    if format.lower() == "html":
        html = await asyncio.to_thread(reporter.to_html, report)
        return _HTMLResponse(content=html)
    return report


@router.get(
    "/dashboard",
    summary="Compliance & Risk Mitigation ROI dashboard",
    dependencies=[Depends(require_api_key)],
)
async def compliance_dashboard(days: float = 30):
    """
    Return risk-mitigation ROI metrics: shadow-ban compute savings,
    estimated breach cost avoided, secret protection value, agent security summary,
    and the Compliance Score (Cs = verified_audit_entries / total_log_entries).

    Override ``COMPLIANCE_*`` environment variables to use your organisation's
    actual LLM pricing and breach cost estimates.
    """
    import asyncio  # noqa: PLC0415

    from warden.compliance.dashboard import ComplianceDashboard  # noqa: PLC0415
    from warden.runtime import runtime as _runtime  # noqa: PLC0415

    dash    = ComplianceDashboard(
        agent_monitor=_runtime.get("agent_monitor"),
        audit_trail=_runtime.get("audit_trail"),
    )
    metrics = await asyncio.to_thread(dash.get_metrics, days)
    return metrics


@router.get(
    "/evidence/{session_id}",
    summary="Export a cryptographically-signed evidence bundle for a session",
    dependencies=[Depends(require_api_key)],
)
async def compliance_evidence_bundle(
    session_id: str,
    agent_id:   str = "",
    entity_key: str = "",
):
    """
    Generate a tamper-evident JSON evidence bundle for *session_id*.

    The bundle includes session metadata, ERS profile, attestation chain
    status, tool timeline, and a ``bundle_hash`` (SHA-256 over canonical JSON).
    Any post-export modification invalidates the hash.

    Use ``POST /compliance/evidence/verify`` to check integrity later.
    """
    import asyncio  # noqa: PLC0415

    from warden.runtime import runtime as _runtime  # noqa: PLC0415

    agent_monitor = _runtime.get("agent_monitor")
    if agent_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AgentMonitor not available.",
        )
    from warden.compliance.bundler import EvidenceBundler  # noqa: PLC0415

    bundler = EvidenceBundler(agent_monitor=agent_monitor)
    bundle  = await asyncio.to_thread(bundler.generate, session_id, agent_id, entity_key)
    return bundle


@router.post(
    "/evidence/verify",
    summary="Verify integrity of a previously exported evidence bundle",
    dependencies=[Depends(require_api_key)],
)
async def compliance_evidence_verify(bundle: dict):
    """
    Verify the ``bundle_hash`` of a submitted evidence bundle.

    Returns ``{"valid": true}`` if the bundle is intact, ``{"valid": false}``
    if any field has been modified since export.
    """
    import asyncio  # noqa: PLC0415

    from warden.compliance.bundler import EvidenceBundler  # noqa: PLC0415

    valid = await asyncio.to_thread(EvidenceBundler.verify_bundle, bundle)
    return {"valid": valid, "bundle_hash": bundle.get("bundle_hash", "")}


@router_api.get(
    "/api/compliance/gdpr/ropa",
    summary="GDPR Article 30 RoPA — regulatory path alias",
    dependencies=[Depends(require_api_key)],
)
async def compliance_gdpr_ropa(days: float = 30, format: str = "json"):
    """
    Alias for ``GET /compliance/art30`` using the path regulators expect.
    Returns the Art. 30 Record of Processing Activities.
    """
    return await compliance_art30(days=days, format=format)
