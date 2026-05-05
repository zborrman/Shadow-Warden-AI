"""
ARQ worker: scan dependencies for CVEs every 6 hours via OSV API.

Pipeline:
  1. Parse warden/requirements.txt → package list
  2. Bulk-query https://api.osv.dev/v1/querybatch
  3. Deduplicate + score severity
  4. Atomic write to data/cve_report.json
  5. Slack alert if new CRITICAL CVEs found
  6. Update data/security_posture.json badge

Runs automatically via WorkerSettings cron.
Can also be triggered on-demand via POST /security/cve-scan.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger("warden.workers.cve_scanner")

_CVE_REPORT_PATH  = Path(os.getenv("CVE_REPORT_PATH",   "data/cve_report.json"))
_POSTURE_PATH     = Path(os.getenv("SECURITY_POSTURE_PATH", "data/security_posture.json"))
_REQ_FILE         = Path(os.getenv("REQUIREMENTS_PATH", "warden/requirements.txt"))
_OSV_BATCH_URL    = "https://api.osv.dev/v1/querybatch"

# Severity order for sorting
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

# Packages we accept / version-locked
_IGNORED: dict[str, str] = {
    "bcrypt": "IG-compat-passlib-1.7.4",
}


def _parse_requirements(req_file: Path) -> list[dict[str, str]]:
    """Return list of {name, version} from requirements.txt."""
    packages = []
    for line in req_file.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)[=><~!]+([^\s;#]+)", line)
        if m:
            packages.append({"name": m.group(1).lower(), "version": m.group(2).strip()})
    return packages


def _osv_severity(vuln: dict) -> str:
    """Best-effort severity from OSV vulnerability record."""
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        if isinstance(score_str, str) and score_str.startswith("CVSS"):
            pass
        rating = sev.get("score", "")
        if "CRITICAL" in str(rating).upper():
            return "CRITICAL"
        if "HIGH" in str(rating).upper():
            return "HIGH"
    # Fallback: check database_specific
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            pass
    severity_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    db_sev = vuln.get("database_specific", {}).get("severity", "UNKNOWN")
    return severity_map.get(db_sev.upper(), "UNKNOWN")


async def _batch_osv(packages: list[dict[str, str]], client: httpx.AsyncClient) -> list[dict]:
    """Query OSV batch API. Returns flat list of findings."""
    queries = [
        {"package": {"name": p["name"], "ecosystem": "PyPI"}, "version": p["version"]}
        for p in packages
    ]
    findings: list[dict] = []
    # OSV batch accepts up to 1000 queries
    for i in range(0, len(queries), 100):
        chunk = queries[i: i + 100]
        try:
            resp = await client.post(_OSV_BATCH_URL, json={"queries": chunk}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log.warning("OSV batch query failed: %s", exc)
            continue

        for pkg, result in zip(packages[i: i + 100], data.get("results", []), strict=False):
            for vuln in result.get("vulns", []):
                pkg_name = pkg["name"]
                if pkg_name in _IGNORED:
                    continue
                severity = _osv_severity(vuln)
                findings.append({
                    "package":     pkg_name,
                    "version":     pkg["version"],
                    "vuln_id":     vuln.get("id", ""),
                    "aliases":     vuln.get("aliases", []),
                    "severity":    severity,
                    "summary":     vuln.get("summary", ""),
                    "published":   vuln.get("published", ""),
                    "modified":    vuln.get("modified", ""),
                    "link":        f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
                })

    findings.sort(key=lambda f: _SEV_RANK.get(f["severity"], 99))
    return findings


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    except Exception:
        os.unlink(tmp)
        raise


async def _slack_alert(new_criticals: list[dict]) -> None:
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook or not new_criticals:
        return
    lines = "\n".join(
        f"  • `{f['package']}=={f['version']}` — {f['vuln_id']} ({f['summary'][:80]})"
        for f in new_criticals[:5]
    )
    msg = {
        "text": (
            f":rotating_light: *{len(new_criticals)} new CRITICAL CVE(s) detected*\n"
            f"{lines}\n"
            f"Run `POST /security/cve-scan` to refresh or see `/security/cve-feed`."
        )
    }
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            await c.post(webhook, json=msg)
    except Exception as exc:
        log.warning("Slack CVE alert failed: %s", exc)


def _update_posture(findings: list[dict]) -> None:
    """Rewrite security_posture.json with updated badge + counts."""
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["severity"] == "HIGH")
    badge    = "RED" if critical >= 4 else ("YELLOW" if critical >= 1 or high >= 5 else "GREEN")

    existing: dict = {}
    if _POSTURE_PATH.exists():
        with contextlib.suppress(Exception):
            existing = json.loads(_POSTURE_PATH.read_text())

    existing.update({
        "badge":            badge,
        "critical_count":   critical,
        "high_count":       high,
        "total_cves":       len(findings),
        "last_updated":     datetime.now(UTC).isoformat(),
    })
    _atomic_write(_POSTURE_PATH, existing)


async def scan_cves(ctx: dict[str, Any]) -> dict[str, Any]:
    """
    ARQ job entrypoint. Scans requirements.txt against OSV, saves report, alerts on new CRITICALs.
    """
    if not _REQ_FILE.exists():
        log.warning("cve_scanner: requirements file not found at %s", _REQ_FILE)
        return {"error": "requirements_not_found", "path": str(_REQ_FILE)}

    packages = _parse_requirements(_REQ_FILE)
    if not packages:
        return {"findings": [], "scanned_packages": 0}

    # Load previous scan for diff
    prev_ids: set[str] = set()
    if _CVE_REPORT_PATH.exists():
        try:
            prev = json.loads(_CVE_REPORT_PATH.read_text())
            prev_ids = {f["vuln_id"] for f in prev.get("findings", [])}
        except Exception:
            pass

    async with httpx.AsyncClient() as client:
        findings = await _batch_osv(packages, client)

    scanned_at = datetime.now(UTC).isoformat()
    report = {
        "scanned_at":      scanned_at,
        "scanned_packages": len(packages),
        "findings":        findings,
    }
    _atomic_write(_CVE_REPORT_PATH, report)
    _update_posture(findings)

    new_criticals = [
        f for f in findings
        if f["severity"] == "CRITICAL" and f["vuln_id"] not in prev_ids
    ]
    await _slack_alert(new_criticals)

    log.info(
        "cve_scanner: scanned=%d findings=%d critical=%d new_critical=%d",
        len(packages), len(findings),
        sum(1 for f in findings if f["severity"] == "CRITICAL"),
        len(new_criticals),
    )
    return {
        "scanned_packages": len(packages),
        "total_findings":   len(findings),
        "new_criticals":    len(new_criticals),
        "scanned_at":       scanned_at,
    }
