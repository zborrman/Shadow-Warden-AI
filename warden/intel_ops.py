"""
warden/intel_ops.py
━━━━━━━━━━━━━━━━━━
Autonomous Threat Intelligence — Dependency CVE Scanner + ArXiv AI Threat Hunter.

Two scan modes:
  scan_dependencies()   → queries Google OSV API for known CVEs in requirements.txt
  hunt_ai_threats()     → monitors ArXiv for new LLM attack-vector research

Results are written atomically to data/intel_report.json and surfaced in the
Settings dashboard tab.  Runs on demand (API trigger or dashboard button) and
optionally on a background schedule (INTEL_OPS_INTERVAL_HRS, default 24h).

Environment variables
─────────────────────
  INTEL_OPS_ENABLED        true|false  (default false — opt-in)
  INTEL_OPS_INTERVAL_HRS   background scan cadence (default 24)
  INTEL_OPS_ARXIV_RESULTS  number of ArXiv results to fetch (default 10)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

log = logging.getLogger("warden.intel_ops")

# ── Config ────────────────────────────────────────────────────────────────────

_ARXIV_RESULTS   = int(os.getenv("INTEL_OPS_ARXIV_RESULTS", "10"))
_REPORT_PATH     = Path(os.getenv("INTEL_OPS_REPORT_PATH", "data/intel_report.json"))
_OSV_URL         = "https://api.osv.dev/v1/query"
_ARXIV_URL       = (
    "https://export.arxiv.org/api/query"
    "?search_query=all:{query}"
    "&sortBy=submittedDate&sortOrder=desc"
    "&max_results={n}"
)
_ARXIV_QUERY     = (
    "%22prompt+injection%22+OR+%22jailbreak%22"
    "+OR+%22agentic+threat%22+OR+%22LLM+attack%22"
    "+OR+%22adversarial+prompt%22"
)

# CVEs that are intentionally accepted / version-locked.
# Format: { package_name: "IG-<reason>" }
_DEFAULT_IGNORED: dict[str, str] = {
    "bcrypt": "IG-compat-passlib-1.7.4",
}


class WardenIntelOps:
    """
    Threat Intelligence scanner for Shadow Warden.

    Usage::

        ops = WardenIntelOps()
        report = await ops.run_audit()          # full scan, saves report
        cves   = await ops.scan_dependencies(client)
        papers = await ops.hunt_ai_threats(client)
    """

    def __init__(
        self,
        project_root: str | Path = ".",
        ignored_vulns: dict[str, str] | None = None,
    ) -> None:
        self.project_root  = Path(project_root)
        self.req_file      = self.project_root / "warden" / "requirements.txt"
        self.ignored_vulns = ignored_vulns if ignored_vulns is not None else dict(_DEFAULT_IGNORED)

    # ── Dependency CVE scan ───────────────────────────────────────────────────

    async def scan_dependencies(self, client: httpx.AsyncClient) -> list[dict]:
        """Query OSV API for every pinned package in requirements.txt."""
        log.info("IntelOps: scanning dependencies via OSV API …")
        alerts: list[dict] = []

        if not self.req_file.exists():
            log.warning("IntelOps: requirements.txt not found at %s", self.req_file)
            return alerts

        lines = self.req_file.read_text(encoding="utf-8").splitlines()
        tasks = []
        packages = []

        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Accept "pkg==1.2.3" — skip ranges / extras
            m = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s;#]+)", line)
            if not m:
                continue
            pkg_name, pkg_version = m.group(1).strip(), m.group(2).strip()
            if pkg_name in self.ignored_vulns:
                log.debug("IntelOps: ignoring %s (%s)", pkg_name, self.ignored_vulns[pkg_name])
                continue
            packages.append((pkg_name, pkg_version))
            tasks.append(self._query_osv(client, pkg_name, pkg_version))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (pkg_name, pkg_version), result in zip(packages, results, strict=True):
            if isinstance(result, BaseException):
                log.warning("IntelOps: OSV error for %s: %s", pkg_name, result)
                continue
            for vuln in result:
                cve_id = (vuln.get("aliases") or ["UNKNOWN"])[0]
                alerts.append({
                    "type":     "dependency_cve",
                    "package":  pkg_name,
                    "version":  pkg_version,
                    "cve":      cve_id,
                    "severity": _osv_severity(vuln),
                    "details":  vuln.get("summary", "No description provided."),
                    "link":     f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
                })
                log.warning(
                    "IntelOps: CVE found — %s %s → %s (%s)",
                    pkg_name, pkg_version, cve_id, vuln.get("summary", "")[:80],
                )

        log.info("IntelOps: dependency scan complete — %d CVE(s) found.", len(alerts))
        return alerts

    async def _query_osv(
        self, client: httpx.AsyncClient, name: str, version: str
    ) -> list[dict]:
        payload = {"version": version, "package": {"name": name, "ecosystem": "PyPI"}}
        try:
            resp = await client.post(_OSV_URL, json=payload)
            resp.raise_for_status()
            return resp.json().get("vulns", [])
        except httpx.HTTPStatusError as exc:
            log.debug("IntelOps: OSV HTTP %s for %s: %s", exc.response.status_code, name, exc)
            return []

    # ── ArXiv AI threat hunt ──────────────────────────────────────────────────

    async def hunt_ai_threats(self, client: httpx.AsyncClient) -> list[dict]:
        """Fetch recent LLM-attack research from ArXiv."""
        log.info("IntelOps: hunting AI threats on ArXiv …")
        alerts: list[dict] = []

        url = _ARXIV_URL.format(query=_ARXIV_QUERY, n=_ARXIV_RESULTS)
        try:
            resp = await client.get(url, timeout=15.0)
            resp.raise_for_status()
            entries = resp.text.split("<entry>")[1:]
            for entry in entries:
                title_m    = re.search(r"<title>(.*?)</title>",   entry, re.DOTALL)
                link_m     = re.search(r"<id>(.*?)</id>",         entry, re.DOTALL)
                summary_m  = re.search(r"<summary>(.*?)</summary>", entry, re.DOTALL)
                pub_m      = re.search(r"<published>(.*?)</published>", entry)
                if not (title_m and link_m):
                    continue
                alerts.append({
                    "type":      "new_threat_intel",
                    "source":    "ArXiv",
                    "title":     title_m.group(1).replace("\n", " ").strip(),
                    "link":      link_m.group(1).strip(),
                    "summary":   (summary_m.group(1).replace("\n", " ").strip()[:300]
                                  if summary_m else ""),
                    "published": pub_m.group(1).strip() if pub_m else "",
                })
        except Exception as exc:
            log.warning("IntelOps: ArXiv fetch error: %s", exc)

        log.info("IntelOps: ArXiv scan complete — %d paper(s) found.", len(alerts))
        return alerts

    # ── Full audit ────────────────────────────────────────────────────────────

    async def run_audit(self) -> list[dict]:
        """Run both scans, persist the combined report, and return all alerts."""
        log.info("IntelOps: starting full audit …")
        scanned_at = datetime.now(UTC).isoformat()

        async with httpx.AsyncClient(timeout=20.0) as client:
            dep_alerts, threat_alerts = await asyncio.gather(
                self.scan_dependencies(client),
                self.hunt_ai_threats(client),
            )

        all_alerts = dep_alerts + threat_alerts

        report: dict = {
            "scanned_at": scanned_at,
            "cve_count":  len(dep_alerts),
            "intel_count": len(threat_alerts),
            "alerts":     all_alerts,
        }

        _save_report(report)
        log.info(
            "IntelOps: audit complete — %d CVE(s), %d research paper(s).",
            len(dep_alerts), len(threat_alerts),
        )
        return all_alerts

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def load_report() -> dict | None:
        """Return the last saved report dict, or None if not found."""
        if not _REPORT_PATH.exists():
            return None
        try:
            return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("IntelOps: failed to load report: %s", exc)
            return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _osv_severity(vuln: dict) -> str:
    """Extract highest CVSS severity from an OSV vuln record."""
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        if isinstance(score, (int, float)):
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"
    return "UNKNOWN"


def _save_report(report: dict) -> None:
    """Atomically write the intel report to disk."""
    _REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(suffix=".json", dir=_REPORT_PATH.parent)
    try:
        import os
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, str(_REPORT_PATH))
    except Exception as exc:
        import contextlib
        with contextlib.suppress(OSError):
            import os as _os
            _os.unlink(tmp)
        log.warning("IntelOps: report save failed: %s", exc)


# ── Background scan loop (called from main.py lifespan) ──────────────────────

async def intel_scan_loop(interval_hrs: float = 24.0) -> None:
    """Periodic background loop — runs a full audit every *interval_hrs* hours."""
    ops = WardenIntelOps()
    interval_s = interval_hrs * 3600
    log.info("IntelOps: background scanner started (interval=%.0fh).", interval_hrs)
    while True:
        await asyncio.sleep(interval_s)
        try:
            await ops.run_audit()
        except Exception as exc:
            log.warning("IntelOps: background audit error: %s", exc)


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio as _asyncio
    _asyncio.run(WardenIntelOps().run_audit())
