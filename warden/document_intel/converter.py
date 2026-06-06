"""
warden/document_intel/converter.py
────────────────────────────────────
MarkItDown-backed document converter with Redis caching.

Converts any supported file (PDF, DOCX, PPTX, XLSX, HTML, images, ZIP, EPUB,
audio …) to Markdown, then runs SecretRedactor before the result enters the
filter pipeline or community channels.

Config env vars
───────────────
DOC_INTEL_MAX_BYTES     Max file size before rejection (default 50 MB)
DOC_INTEL_TIMEOUT_S     Per-conversion wall-clock timeout (default 30 s)
DOC_INTEL_CACHE_TTL     Fallback cache TTL in seconds (default 3 600 s)
REDIS_URL               Redis connection string (default redis://localhost:6379)

File-type-aware cache TTLs
──────────────────────────
Documents (PDF/DOCX/PPTX/XLSX) → 86 400 s (24 h)  — rarely change
Audio  (MP3/WAV/FLAC/M4A)      → 604 800 s (7 d)  — transcription is expensive
Images (JPG/PNG/GIF/WEBP …)    →   3 600 s (1 h)  — may be updated frequently
Other                          → DOC_INTEL_CACHE_TTL  (default 3 600 s)
"""
from __future__ import annotations

import concurrent.futures as _cf
import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("warden.document_intel.converter")

_MAX_BYTES    = int(os.getenv("DOC_INTEL_MAX_BYTES",  str(50 * 1024 * 1024)))   # 50 MB
_TIMEOUT_S    = float(os.getenv("DOC_INTEL_TIMEOUT_S", "30"))
_DEFAULT_TTL  = int(os.getenv("DOC_INTEL_CACHE_TTL",  "3600"))
_CACHE_PREFIX = "doc_intel:md:"
_STATS_KEY    = "doc_intel:stats"

_FILE_TYPE_TTL: dict[str, int] = {
    ".pdf":  86_400, ".docx": 86_400, ".pptx": 86_400, ".xlsx": 86_400, ".xls": 86_400,
    ".mp3": 604_800, ".wav":  604_800, ".flac": 604_800, ".m4a":  604_800,
    ".jpg":   3_600, ".jpeg":   3_600, ".png":   3_600, ".gif":   3_600,
    ".bmp":   3_600, ".webp":   3_600,
}

SUPPORTED_EXTENSIONS = {
    ".pdf", ".docx", ".pptx", ".xlsx", ".xls",
    ".html", ".htm",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".zip", ".epub", ".csv", ".txt", ".md",
    ".mp3", ".wav", ".flac", ".m4a",
}

_PHI_KEYWORDS       = {"patient", "diagnosis", "prescription", "medical record", "hipaa", "ehr"}
_PII_KEYWORDS       = {"ssn", "social security", "date of birth", "passport number", "national id"}
_FINANCIAL_KEYWORDS = {"account number", "routing number", "credit card", "iban", "wire transfer"}
_CLASSIFIED_KEYWORDS = {"top secret", "classified", "confidential", "restricted"}


class MarkItDownUnavailable(RuntimeError):
    """Raised when markitdown is not installed or fails to import."""


class FileTooLargeError(ValueError):
    """Raised when the file exceeds DOC_INTEL_MAX_BYTES."""


@dataclass
class ConversionResult:
    filename:     str
    markdown:     str
    data_class:   str = "GENERAL"
    secrets_found: list[str] = field(default_factory=list)
    redacted:     bool = False
    word_count:   int  = 0
    char_count:   int  = 0
    from_cache:   bool = False

    def to_dict(self) -> dict:
        return {
            "filename":     self.filename,
            "markdown":     self.markdown,
            "data_class":   self.data_class,
            "secrets_found": self.secrets_found,
            "redacted":     self.redacted,
            "word_count":   self.word_count,
            "char_count":   self.char_count,
            "from_cache":   self.from_cache,
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


def _convert_raw(file_bytes: bytes, filename: str) -> ConversionResult:
    """Core MarkItDown conversion + SecretRedactor pass. No caching, no timeout."""
    try:
        from markitdown import MarkItDown
    except Exception as exc:
        raise MarkItDownUnavailable(
            f"markitdown is not available — run: pip install markitdown ({type(exc).__name__}: {exc})"
        ) from exc

    suffix = Path(filename).suffix.lower() or ".tmp"
    if suffix not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {suffix!r}")

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        md_result = MarkItDown().convert(tmp_path)
        markdown = md_result.text_content or ""
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
        log.debug("SecretRedactor unavailable during document conversion")

    return ConversionResult(
        filename=filename,
        markdown=markdown,
        data_class=_infer_data_class(markdown),
        secrets_found=secrets_found,
        redacted=redacted,
        word_count=len(markdown.split()),
        char_count=len(markdown),
    )


def _convert_with_timeout(file_bytes: bytes, filename: str) -> ConversionResult:
    """Run _convert_raw in an isolated thread with DOC_INTEL_TIMEOUT_S wall-clock limit."""
    with _cf.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_convert_raw, file_bytes, filename)
        try:
            return future.result(timeout=_TIMEOUT_S)
        except _cf.TimeoutError as exc:
            future.cancel()
            raise TimeoutError(
                f"Document conversion timed out after {_TIMEOUT_S:.0f}s"
            ) from exc


class MarkItDownConverter:
    """Thread-safe MarkItDown converter with Redis caching and Prometheus metrics."""

    def __init__(self) -> None:
        self._redis: Any | None = None
        self._redis_checked = False

    def _get_redis(self) -> Any | None:
        if self._redis_checked:
            return self._redis
        self._redis_checked = True
        try:
            import redis as redis_lib
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
            if redis_url.startswith("memory://"):
                return None
            r = redis_lib.Redis.from_url(redis_url, decode_responses=True)
            r.ping()
            self._redis = r
        except Exception:
            self._redis = None
        return self._redis

    @staticmethod
    def _file_hash(file_bytes: bytes) -> str:
        return hashlib.sha256(file_bytes).hexdigest()

    @staticmethod
    def _ttl_for(filename: str) -> int:
        suffix = Path(filename).suffix.lower()
        return _FILE_TYPE_TTL.get(suffix, _DEFAULT_TTL)

    def _cache_get(self, file_hash: str) -> ConversionResult | None:
        r = self._get_redis()
        if not r:
            return None
        try:
            raw = r.get(f"{_CACHE_PREFIX}{file_hash}")
            if raw:
                data = json.loads(raw)
                data["from_cache"] = True
                return ConversionResult(**data)
        except Exception:
            pass
        return None

    def _cache_set(self, file_hash: str, result: ConversionResult, ttl: int) -> None:
        r = self._get_redis()
        if not r:
            return
        try:
            r.setex(f"{_CACHE_PREFIX}{file_hash}", ttl, json.dumps(result.to_dict()))
        except Exception:
            pass

    def _incr_stat(self, field_name: str, amount: int = 1) -> None:
        r = self._get_redis()
        if not r:
            return
        try:
            r.hincrby(_STATS_KEY, field_name, amount)
        except Exception:
            pass

    def convert_bytes(self, file_bytes: bytes, filename: str) -> ConversionResult:
        """Convert raw bytes to Markdown, checking size limit and Redis cache first."""
        ext = Path(filename).suffix.lower()

        if len(file_bytes) > _MAX_BYTES:
            raise FileTooLargeError(
                f"File '{filename}' is {len(file_bytes):,} bytes — "
                f"exceeds DOC_INTEL_MAX_BYTES ({_MAX_BYTES:,} bytes)"
            )

        # ── Cache check ──────────────────────────────────────────────────────
        file_hash = self._file_hash(file_bytes)
        cached = self._cache_get(file_hash)
        if cached:
            log.debug("doc_intel cache hit: %s", filename)
            self._incr_stat("cache_hits")
            try:
                from warden.metrics import DOC_INTEL_CACHE_HITS_TOTAL
                DOC_INTEL_CACHE_HITS_TOTAL.inc()
            except Exception:
                pass
            return cached

        # ── Conversion ───────────────────────────────────────────────────────
        try:
            result = _convert_with_timeout(file_bytes, filename)
        except Exception as exc:
            self._incr_stat("errors")
            try:
                from warden.metrics import DOC_INTEL_CONVERT_ERRORS_TOTAL
                DOC_INTEL_CONVERT_ERRORS_TOTAL.labels(ext=ext, error=type(exc).__name__).inc()
            except Exception:
                pass
            raise

        # ── Store in cache ────────────────────────────────────────────────────
        ttl = self._ttl_for(filename)
        self._cache_set(file_hash, result, ttl)

        # ── Metrics ───────────────────────────────────────────────────────────
        self._incr_stat("total")
        if result.data_class in ("PHI", "PII", "FINANCIAL", "CLASSIFIED"):
            self._incr_stat("sensitive")
        if result.secrets_found:
            self._incr_stat("secrets_found")

        try:
            from warden.metrics import DOC_INTEL_CONVERT_TOTAL
            DOC_INTEL_CONVERT_TOTAL.labels(ext=ext, data_class=result.data_class).inc()
        except Exception:
            pass

        return result

    def convert(self, file_path: str) -> ConversionResult:
        """Convert a file on disk to Markdown, with Redis cache."""
        with open(file_path, "rb") as fh:
            file_bytes = fh.read()
        return self.convert_bytes(file_bytes, Path(file_path).name)

    def convert_batch(self, files: list[dict]) -> list[dict]:
        """Batch convert. Each item: {"file_bytes": bytes, "filename": str} or {"file_path": str}."""
        results = []
        for item in files:
            try:
                if "file_bytes" in item:
                    r = self.convert_bytes(item["file_bytes"], item.get("filename", "unknown"))
                elif "file_path" in item:
                    r = self.convert(item["file_path"])
                else:
                    raise ValueError("Each item must have 'file_bytes' or 'file_path'")
                results.append(r.to_dict())
            except Exception as exc:
                results.append({
                    "filename":     item.get("filename", item.get("file_path", "unknown")),
                    "error":        str(exc),
                    "markdown":     "",
                    "data_class":   "GENERAL",
                    "secrets_found": [],
                    "redacted":     False,
                    "word_count":   0,
                    "char_count":   0,
                    "from_cache":   False,
                })
        return results

    def get_stats(self) -> dict:
        """Return conversion statistics from Redis."""
        r = self._get_redis()
        if not r:
            return {"available": False}
        try:
            raw = r.hgetall(_STATS_KEY)
            return {
                "total":         int(raw.get("total", 0)),
                "cache_hits":    int(raw.get("cache_hits", 0)),
                "errors":        int(raw.get("errors", 0)),
                "sensitive":     int(raw.get("sensitive", 0)),
                "secrets_found": int(raw.get("secrets_found", 0)),
                "available":     True,
            }
        except Exception:
            return {"available": False}


_converter: MarkItDownConverter | None = None


def get_converter() -> MarkItDownConverter:
    """Return the module-level singleton converter (created lazily)."""
    global _converter
    if _converter is None:
        _converter = MarkItDownConverter()
    return _converter
