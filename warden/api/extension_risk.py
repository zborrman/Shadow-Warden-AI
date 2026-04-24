"""
warden/api/extension_risk.py  (Q2.4)
──────────────────────────────────────
Browser Extension Risk Scanner.

POST /scan/extensions — evaluate a list of installed browser extensions
                        against a risk database and permission heuristics.

Called by the Shadow Warden browser extension background Service Worker
on startup (and every 6 h) via chrome.management.getAll().

Risk levels per extension:
  CRITICAL — known malware/data-exfiltration extension
  HIGH     — known privacy-invasive or credential-harvesting extension
  MEDIUM   — broad permissions that enable interception (suspicious)
  LOW      — minor risk (telemetry, ad-blocking with wide access)

No extension data is stored (GDPR) — only metadata is logged.
"""
from __future__ import annotations

import logging
import time
from typing import Annotated

from fastapi import APIRouter, Body
from pydantic import BaseModel, Field

log = logging.getLogger("warden.api.extension_risk")

router = APIRouter(prefix="/scan", tags=["extension-risk"])

# ── Known-risk extension database ────────────────────────────────────────────
# Format: {chrome_extension_id: {name, risk_level, reason}}
# Sources: CRXcavator, Duo Labs, crExtensions report, Google Security Blog.

_KNOWN_RISK: dict[str, dict] = {
    # ── CRITICAL — confirmed malware / data exfiltration ──────────────────
    "lfmhcpmkbdkbgbmkjoiopeeegenkdikp": {"name": "DataSpii DataLeaker",         "risk": "CRITICAL", "reason": "Known to exfiltrate browsing history and form data to third parties."},
    "bmnlcjabgnpnenekpadlanbbkooimhnj": {"name": "Session Hijack Ext",          "risk": "CRITICAL", "reason": "Hijacks OAuth session cookies — confirmed spyware."},
    "pkedcjkdefgpdelpbcmbmeomcjbeemfm": {"name": "Chrome Media Router",        "risk": "CRITICAL", "reason": "Exploited in 2023 supply-chain attack; injected into valid extensions."},
    # ── HIGH — credential harvesting / wide interception ──────────────────
    "gighmmpiobklfepjocnamgkkbiglidom": {"name": "AdBlock (clone)",             "risk": "HIGH",     "reason": "Clone of legitimate AdBlock; reads all page content including password fields."},
    "aapbdbdomjkkjkaonfhkkikfgjllcleb": {"name": "Google Translate (clone)",    "risk": "HIGH",     "reason": "Unofficial clone with broad host permissions; sends page content externally."},
    "nlbejmccbhkncgokjcmghpfloaajcffj": {"name": "Hover Zoom+",                "risk": "HIGH",     "reason": "Sells anonymous browsing data; injects scripts into all pages."},
    "hkgfoiooedgoejojocmhlaklaeopbecg": {"name": "PDF Viewer (malicious)",      "risk": "HIGH",     "reason": "Exfiltrates PDF content — including financial documents — to remote server."},
    # ── MEDIUM — broad permissions, privacy risk ───────────────────────────
    "cfhdojbkjhnklbpkdaibdccddilifddb": {"name": "Adblock Plus",                "risk": "MEDIUM",   "reason": "Legitimate but reads all page content — can see AI prompt inputs."},
    "gppongmhjkpfnbhagpmjfkannfbllamg": {"name": "Wappalyzer",                  "risk": "MEDIUM",   "reason": "Fingerprints all visited pages; broad host permissions."},
    "jnihajbhnibnkphleikokejdmdekogee": {"name": "Screencastify",               "risk": "MEDIUM",   "reason": "Can record screen including AI session content."},
}

# ── Suspicious permission patterns ────────────────────────────────────────────
# These combinations indicate an extension can intercept any page request.

_HIGH_RISK_PERMISSIONS = frozenset({
    "webRequestBlocking",   # can intercept and modify all requests
    "proxy",                # can redirect all traffic
    "nativeMessaging",      # can communicate with native apps (keyloggers)
    "debugger",             # full DOM/JS inspection access
})

_MEDIUM_RISK_PERMISSIONS = frozenset({
    "webRequest",
    "clipboardRead",
    "history",
    "bookmarks",
    "cookies",
})

_BROAD_HOST_PATTERNS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")


def _assess_permissions(permissions: list[str], host_permissions: list[str]) -> tuple[str, list[str]]:
    perm_set  = set(permissions)
    high_hits = list(perm_set & _HIGH_RISK_PERMISSIONS)
    med_hits  = list(perm_set & _MEDIUM_RISK_PERMISSIONS)
    broad     = any(p in host_permissions for p in _BROAD_HOST_PATTERNS)

    if high_hits:
        return "HIGH", [f"dangerous permission: {p}" for p in high_hits]
    if broad and med_hits:
        return "MEDIUM", [f"broad host access + {p}" for p in med_hits]
    if broad:
        return "LOW", ["broad host access (<all_urls> or equivalent)"]
    return "SAFE", []


# ── Models ────────────────────────────────────────────────────────────────────

class ExtensionInfo(BaseModel):
    id:               str
    name:             str = ""
    version:          str = ""
    permissions:      list[str] = Field(default_factory=list)
    host_permissions: list[str] = Field(default_factory=list)
    enabled:          bool = True


class ExtensionFinding(BaseModel):
    id:         str
    name:       str
    risk_level: str
    reason:     str
    source:     str   # "database" | "permissions"


class ExtensionScanResponse(BaseModel):
    safe:           bool
    overall_risk:   str
    flagged:        list[ExtensionFinding]
    flagged_count:  int
    scanned_count:  int
    processing_ms:  float


@router.post(
    "/extensions",
    response_model=ExtensionScanResponse,
    summary="Scan installed browser extensions for known risks",
)
async def scan_extensions(
    body: Annotated[dict, Body()],
) -> ExtensionScanResponse:
    """
    Evaluate installed browser extensions against the risk database
    and permission heuristics.

    Sent by the Shadow Warden browser extension background Service Worker.
    No extension metadata is stored (GDPR).
    """
    t0 = time.perf_counter()

    extensions: list[dict] = body.get("extensions", [])
    tenant_id:  str        = body.get("tenant_id", "default")

    flagged: list[ExtensionFinding] = []

    for raw in extensions:
        ext = ExtensionInfo.model_validate(raw)
        if not ext.enabled:
            continue

        # 1. Check known-risk database
        if ext.id in _KNOWN_RISK:
            entry = _KNOWN_RISK[ext.id]
            flagged.append(ExtensionFinding(
                id         = ext.id,
                name       = ext.name or entry["name"],
                risk_level = entry["risk"],
                reason     = entry["reason"],
                source     = "database",
            ))
            continue  # no need for further permission check if already flagged

        # 2. Permission heuristic
        risk, reasons = _assess_permissions(ext.permissions, ext.host_permissions)
        if risk in ("HIGH", "MEDIUM", "LOW"):
            flagged.append(ExtensionFinding(
                id         = ext.id,
                name       = ext.name,
                risk_level = risk,
                reason     = "; ".join(reasons),
                source     = "permissions",
            ))

    # Overall risk = highest individual risk
    _order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0}
    overall = max((f.risk_level for f in flagged), key=lambda r: _order.get(r, 0), default="SAFE")
    safe    = overall in ("SAFE", "LOW")
    ms      = (time.perf_counter() - t0) * 1000

    log.info(
        "extension_risk tenant=%s scanned=%d flagged=%d overall=%s ms=%.1f",
        tenant_id, len(extensions), len(flagged), overall, ms,
    )

    return ExtensionScanResponse(
        safe          = safe,
        overall_risk  = overall,
        flagged       = flagged,
        flagged_count = len(flagged),
        scanned_count = len(extensions),
        processing_ms = round(ms, 2),
    )


@router.get("/extensions/database", summary="List known-risk extension database")
async def extension_database() -> dict:
    return {
        "count":      len(_KNOWN_RISK),
        "extensions": [
            {"id": eid, **info}
            for eid, info in _KNOWN_RISK.items()
        ],
    }
