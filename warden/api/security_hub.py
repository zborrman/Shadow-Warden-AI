"""
Cyber Security Hub REST API — /security/*

Public endpoints:
  GET /security/posture      — overall security posture badge + CVE summary
  GET /security/cve-feed     — paginated CVE findings list
  GET /security/pentest      — redacted pentest findings timeline
  GET /security/compliance   — SOC2 / GDPR / OWASP control evidence links

Internal (X-Admin-Key required):
  POST /security/cve-scan    — trigger on-demand CVE scan
  POST /security/pentest     — add pentest finding (admin)

CVE data comes from `warden/workers/cve_scanner.py` (ARQ, every 6h).
Posture badge: GREEN (0 critical), YELLOW (1–3), RED (4+).
"""
from __future__ import annotations

import hmac
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

log = logging.getLogger("warden.api.security_hub")

router = APIRouter(prefix="/security", tags=["security"])

_CVE_REPORT_PATH   = Path(os.getenv("CVE_REPORT_PATH",   "data/cve_report.json"))
_PENTEST_DB_PATH   = Path(os.getenv("PENTEST_DB_PATH",   "data/pentest_findings.json"))
_POSTURE_PATH      = Path(os.getenv("SECURITY_POSTURE_PATH", "data/security_posture.json"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_admin(key: str | None) -> None:
    admin = os.getenv("ADMIN_KEY", "")
    if not admin or not key or not hmac.compare_digest(key, admin):
        raise HTTPException(status_code=403, detail="Admin key required")


def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text()) if path.exists() else default
    except Exception as exc:
        log.warning("load_json(%s) failed: %s", path, exc)
        return default


def _badge(critical: int, high: int) -> str:
    if critical >= 4:
        return "RED"
    if critical >= 1 or high >= 5:
        return "YELLOW"
    return "GREEN"


def _compute_posture() -> dict:
    cve_data  = _load_json(_CVE_REPORT_PATH, {})
    findings  = cve_data.get("findings", []) if isinstance(cve_data, dict) else []
    critical  = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high      = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium    = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    badge     = _badge(critical, high)

    posture = _load_json(_POSTURE_PATH, {})
    return {
        "badge": badge,
        "cve_counts": {"critical": critical, "high": high, "medium": medium,
                       "total": len(findings)},
        "last_scan": cve_data.get("scanned_at") if isinstance(cve_data, dict) else None,
        "certifications": posture.get("certifications", _DEFAULT_CERTS),
        "controls_passing": posture.get("controls_passing", 0),
        "controls_total":   posture.get("controls_total",   0),
        "generated_at": datetime.now(UTC).isoformat(),
    }


_DEFAULT_CERTS = [
    {"name": "SOC 2 Type II", "status": "in_progress", "link": "/docs/soc2-evidence"},
    {"name": "GDPR Art. 35",  "status": "compliant",   "link": "/docs/dpia"},
    {"name": "OWASP LLM Top 10", "status": "compliant", "link": "/docs/security-model"},
]

_COMPLIANCE_CONTROLS = [
    {"framework": "SOC 2",   "control": "CC6.1 — Logical access",       "status": "passing", "evidence": "docs/soc2-evidence.md"},
    {"framework": "SOC 2",   "control": "CC7.2 — Anomaly detection",    "status": "passing", "evidence": "docs/soc2-evidence.md"},
    {"framework": "GDPR",    "control": "Art. 32 — Security measures",  "status": "passing", "evidence": "docs/dpia.md"},
    {"framework": "GDPR",    "control": "Art. 35 — DPIA",               "status": "passing", "evidence": "docs/dpia.md"},
    {"framework": "OWASP",   "control": "LLM01 — Prompt Injection",     "status": "passing", "evidence": "docs/security-model.md"},
    {"framework": "OWASP",   "control": "LLM06 — Sensitive Info Disc.", "status": "passing", "evidence": "docs/security-model.md"},
]


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class PentestFindingRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    severity: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    status: str   = Field(pattern="^(open|remediated|accepted)$", default="open")
    summary: str  = Field(min_length=10, max_length=1000)
    remediated_at: str | None = None
    cve_id: str | None = None


# ── Public endpoints ──────────────────────────────────────────────────────────

@router.get("/posture")
def get_posture():
    """Overall security posture — badge colour, CVE counts, certifications."""
    return _compute_posture()


@router.get("/cve-feed")
def get_cve_feed(
    limit:  int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
):
    """Paginated list of CVE findings from the latest OSV scan."""
    cve_data = _load_json(_CVE_REPORT_PATH, {})
    findings = cve_data.get("findings", []) if isinstance(cve_data, dict) else []
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.upper()]
    page = findings[offset: offset + limit]
    return {
        "findings": page,
        "total": len(findings),
        "scanned_at": cve_data.get("scanned_at") if isinstance(cve_data, dict) else None,
    }


@router.get("/pentest")
def get_pentest_findings(
    status: str | None = Query(default=None),
    redacted: bool = Query(default=True),
):
    """
    Pentest findings timeline (public-safe, redacted by default).
    Remediated findings include the date; open findings omit technical detail.
    """
    findings = _load_json(_PENTEST_DB_PATH, [])
    if not isinstance(findings, list):
        findings = []

    if status:
        findings = [f for f in findings if f.get("status") == status]

    if redacted:
        findings = [
            {
                "id":             f.get("id"),
                "title":          f.get("title"),
                "severity":       f.get("severity"),
                "status":         f.get("status"),
                "remediated_at":  f.get("remediated_at"),
                "cve_id":         f.get("cve_id"),
            }
            for f in findings
        ]

    return {"findings": findings, "count": len(findings)}


@router.get("/compliance")
def get_compliance():
    """SOC 2 / GDPR / OWASP control status + evidence links."""
    posture = _load_json(_POSTURE_PATH, {})
    return {
        "controls": _COMPLIANCE_CONTROLS,
        "certifications": posture.get("certifications", _DEFAULT_CERTS),
        "last_updated": posture.get("last_updated"),
    }


# ── Admin endpoints ───────────────────────────────────────────────────────────

@router.post("/cve-scan", status_code=202)
async def trigger_cve_scan(
    x_admin_key: Annotated[str | None, Header()] = None,
):
    """Enqueue an on-demand CVE scan (admin only)."""
    _require_admin(x_admin_key)
    try:
        from arq import create_pool
        from arq.connections import RedisSettings
        pool = await create_pool(RedisSettings.from_dsn(
            os.getenv("REDIS_URL", "redis://localhost:6379")
        ))
        await pool.enqueue_job("scan_cves")
        await pool.aclose()
        return {"queued": True, "job": "scan_cves"}
    except Exception as exc:
        log.warning("cve-scan enqueue failed, running inline: %s", exc)
        from warden.workers.cve_scanner import scan_cves
        result = await scan_cves({})
        return {"queued": False, "inline": True, **result}


@router.post("/pentest", status_code=201)
def add_pentest_finding(
    req: PentestFindingRequest,
    x_admin_key: Annotated[str | None, Header()] = None,
):
    """Add a pentest finding (admin only)."""
    import tempfile
    import uuid
    _require_admin(x_admin_key)
    findings = _load_json(_PENTEST_DB_PATH, [])
    if not isinstance(findings, list):
        findings = []
    finding = {
        "id":            str(uuid.uuid4()),
        "title":         req.title,
        "severity":      req.severity,
        "status":        req.status,
        "summary":       req.summary,
        "remediated_at": req.remediated_at,
        "cve_id":        req.cve_id,
        "created_at":    datetime.now(UTC).isoformat(),
    }
    findings.append(finding)
    _PENTEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=_PENTEST_DB_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(findings, fh, indent=2)
        os.replace(tmp, _PENTEST_DB_PATH)
    except Exception:
        os.unlink(tmp)
        raise
    return finding
