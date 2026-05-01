"""Obsidian note scanner — frontmatter parsing, data classification, secret detection."""
from __future__ import annotations

import re
from typing import Any

_FRONTMATTER_RE = re.compile(r"^---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n", re.DOTALL)

_PHI_KEYWORDS = {"patient", "diagnosis", "prescription", "medical record", "hipaa", "ehr", "clinical"}
_PII_KEYWORDS = {"ssn", "social security", "date of birth", "passport number", "driver license", "national id"}
_FINANCIAL_KEYWORDS = {"account number", "routing number", "credit card", "iban", "swift code", "wire transfer"}

_TAG_CLASS: dict[str, str] = {
    "classified": "CLASSIFIED", "secret": "CLASSIFIED", "confidential": "CLASSIFIED",
    "phi": "PHI", "health": "PHI", "medical": "PHI", "hipaa": "PHI",
    "pii": "PII", "personal": "PII", "gdpr": "PII",
    "financial": "FINANCIAL", "finance": "FINANCIAL", "payment": "FINANCIAL",
}


def _parse_frontmatter(content: str) -> tuple[dict[str, Any], str]:
    m = _FRONTMATTER_RE.match(content)
    if not m:
        return {}, content
    try:
        import yaml  # type: ignore[import-untyped]
        meta = yaml.safe_load(m.group(1)) or {}
    except Exception:
        meta = {}
    return meta, content[m.end():]


def _infer_data_class(meta: dict[str, Any], body: str) -> str:
    if dc := str(meta.get("data_class", "")).strip().upper():
        return dc

    tags = meta.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    for tag in (str(t).lower().strip() for t in (tags or [])):
        if tag in _TAG_CLASS:
            return _TAG_CLASS[tag]

    body_lower = body.lower()
    if any(k in body_lower for k in _PHI_KEYWORDS):
        return "PHI"
    if any(k in body_lower for k in _PII_KEYWORDS):
        return "PII"
    if any(k in body_lower for k in _FINANCIAL_KEYWORDS):
        return "FINANCIAL"

    return "GENERAL"


def scan_note(content: str) -> dict[str, Any]:
    """Scan a markdown note — parse frontmatter, infer data class, detect secrets."""
    meta, body = _parse_frontmatter(content)
    data_class = _infer_data_class(meta, body)

    secrets_found: list[str] = []
    redacted_body = body

    try:
        from warden.secret_redactor import SecretRedactor
        result = SecretRedactor().redact(body)
        redacted_body = result.text
        secrets_found = list({f.kind for f in result.findings})
    except Exception:
        pass

    return {
        "meta": meta,
        "body": body,
        "redacted_body": redacted_body,
        "secrets_found": secrets_found,
        "data_class": data_class,
        "word_count": len(body.split()),
        "has_frontmatter": bool(meta),
    }
