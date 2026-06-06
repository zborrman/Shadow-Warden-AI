"""
warden/communities/doc_converter.py
────────────────────────────────────
MarkItDown wrapper for the community document workflow.

Converts uploaded files (PDF, DOCX, PPTX, XLSX, HTML, images, ZIP, EPUB …)
to Markdown, then runs SecretRedactor before the result enters any community
channel (prompt library, SEP transfer, Obsidian attachment scanner).

markitdown is optional; `DocConverterUnavailable` is raised if not installed.
Install: pip install markitdown
"""
from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("warden.communities.doc_converter")

SUPPORTED_EXTENSIONS = {
    ".pdf", ".docx", ".pptx", ".xlsx", ".xls",
    ".html", ".htm",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".zip", ".epub", ".csv", ".txt", ".md",
    ".mp3", ".wav", ".flac", ".m4a",
}

_PHI_KEYWORDS = {"patient", "diagnosis", "prescription", "medical record", "hipaa", "ehr"}
_PII_KEYWORDS = {"ssn", "social security", "date of birth", "passport number", "national id"}
_FINANCIAL_KEYWORDS = {"account number", "routing number", "credit card", "iban", "wire transfer"}
_CLASSIFIED_KEYWORDS = {"top secret", "classified", "confidential", "restricted"}


class DocConverterUnavailable(RuntimeError):
    """Raised when markitdown is not installed."""


@dataclass
class ConversionResult:
    filename: str
    markdown: str
    data_class: str                     # GENERAL / PHI / PII / FINANCIAL / CLASSIFIED
    secrets_found: list[str] = field(default_factory=list)
    redacted: bool = False
    word_count: int = 0
    char_count: int = 0

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "markdown": self.markdown,
            "data_class": self.data_class,
            "secrets_found": self.secrets_found,
            "redacted": self.redacted,
            "word_count": self.word_count,
            "char_count": self.char_count,
        }


def _infer_data_class(text: str) -> str:
    lower = text.lower()
    if any(k in lower for k in _CLASSIFIED_KEYWORDS):
        return "CLASSIFIED"
    if any(k in lower for k in _PHI_KEYWORDS):
        return "PHI"
    if any(k in lower for k in _PII_KEYWORDS):
        return "PII"
    if any(k in lower for k in _FINANCIAL_KEYWORDS):
        return "FINANCIAL"
    return "GENERAL"


def convert_to_markdown(file_bytes: bytes, filename: str) -> ConversionResult:
    """Convert *file_bytes* to Markdown via MarkItDown, then redact secrets.

    Raises DocConverterUnavailable if markitdown is not installed.
    Raises ValueError for unsupported file extensions.
    """
    try:
        from markitdown import MarkItDown
    except Exception as exc:
        raise DocConverterUnavailable(
            f"markitdown is not available — run: pip install markitdown ({type(exc).__name__}: {exc})"
        ) from exc

    suffix = Path(filename).suffix.lower() or ".tmp"
    if suffix not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {suffix!r}")

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        md_client = MarkItDown()
        result = md_client.convert(tmp_path)
        markdown = result.text_content or ""
    finally:
        os.unlink(tmp_path)

    secrets_found: list[str] = []
    redacted = False
    try:
        from warden.secret_redactor import SecretRedactor
        redact_result = SecretRedactor().redact(markdown)
        if redact_result.findings:
            secrets_found = list({f.kind for f in redact_result.findings})
            markdown = redact_result.text
            redacted = True
    except Exception:
        log.debug("SecretRedactor unavailable — skipping secret scan on converted document")

    return ConversionResult(
        filename=filename,
        markdown=markdown,
        data_class=_infer_data_class(markdown),
        secrets_found=secrets_found,
        redacted=redacted,
        word_count=len(markdown.split()),
        char_count=len(markdown),
    )
