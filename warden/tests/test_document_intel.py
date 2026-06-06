"""
warden/tests/test_document_intel.py
─────────────────────────────────────
Tests for the Document Intelligence module (FE-50).

All tests mock MarkItDown so the suite runs without the real package.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ── MarkItDown mock ──────────────────────────────────────────────────────────

def _make_md_mock(text: str = "# Test\n\nHello world from converted doc.") -> MagicMock:
    result = MagicMock()
    result.text_content = text
    md_instance = MagicMock()
    md_instance.convert.return_value = result
    md_class = MagicMock(return_value=md_instance)
    mock_module = MagicMock()
    mock_module.MarkItDown = md_class
    return mock_module


# ── Unit tests: converter ────────────────────────────────────────────────────

class TestMarkItDownConverter:
    def test_basic_text_conversion(self):
        mock_mod = _make_md_mock("# Invoice\n\naccount number: 1234567890")
        with patch.dict(sys.modules, {"markitdown": mock_mod}):
            from warden.document_intel.converter import _convert_raw
            result = _convert_raw(b"fake content", "report.pdf")
        assert "Invoice" in result.markdown
        assert result.word_count > 0
        assert result.char_count > 0
        assert result.data_class == "FINANCIAL"
        assert result.from_cache is False

    def test_unsupported_extension_raises(self):
        mock_mod = _make_md_mock()
        with patch.dict(sys.modules, {"markitdown": mock_mod}):
            from warden.document_intel.converter import _convert_raw
            with pytest.raises(ValueError, match="Unsupported file type"):
                _convert_raw(b"data", "file.exe")

    def test_markitdown_unavailable_raises(self):
        # Setting sys.modules entry to None makes `from markitdown import MarkItDown`
        # raise ImportError, which _convert_raw wraps as MarkItDownUnavailable.
        with patch.dict(sys.modules, {"markitdown": None}):
            from warden.document_intel.converter import MarkItDownUnavailable, _convert_raw
            with pytest.raises(MarkItDownUnavailable):
                _convert_raw(b"data", "file.pdf")

    def test_phi_data_class_inferred(self):
        mock_mod = _make_md_mock("Patient diagnosis: severe hipaa violation.")
        with patch.dict(sys.modules, {"markitdown": mock_mod}):
            from warden.document_intel.converter import _convert_raw
            result = _convert_raw(b"x", "notes.docx")
        assert result.data_class == "PHI"

    def test_pii_data_class_inferred(self):
        mock_mod = _make_md_mock("SSN: 123-45-6789 national id present.")
        with patch.dict(sys.modules, {"markitdown": mock_mod}):
            from warden.document_intel.converter import _convert_raw
            result = _convert_raw(b"x", "form.docx")
        assert result.data_class == "PII"

    def test_classified_data_class_inferred(self):
        mock_mod = _make_md_mock("TOP SECRET: classified briefing document.")
        with patch.dict(sys.modules, {"markitdown": mock_mod}):
            from warden.document_intel.converter import _convert_raw
            result = _convert_raw(b"x", "brief.pdf")
        assert result.data_class == "CLASSIFIED"

    def test_redis_cache_miss_then_hit(self):
        mock_mod = _make_md_mock("cached content")
        stored: dict = {}

        def fake_get(key: str):
            return stored.get(key)

        def fake_setex(key: str, ttl: int, value: str):
            stored[key] = value

        mock_redis = MagicMock()
        mock_redis.get.side_effect = fake_get
        mock_redis.setex.side_effect = fake_setex

        with patch.dict(sys.modules, {"markitdown": mock_mod}):
            from warden.document_intel.converter import MarkItDownConverter
            conv = MarkItDownConverter()
            conv._redis = mock_redis
            conv._redis_checked = True

            r1 = conv.convert_bytes(b"hello pdf", "test.pdf")
            r2 = conv.convert_bytes(b"hello pdf", "test.pdf")

        assert r1.from_cache is False
        assert r2.from_cache is True
        assert r1.markdown == r2.markdown

    def test_batch_conversion(self):
        mock_mod = _make_md_mock("batch document content")
        with patch.dict(sys.modules, {"markitdown": mock_mod}):
            from warden.document_intel.converter import MarkItDownConverter
            conv = MarkItDownConverter()
            conv._redis_checked = True  # disable Redis
            results = conv.convert_batch([
                {"file_bytes": b"a", "filename": "a.pdf"},
                {"file_bytes": b"b", "filename": "b.docx"},
            ])
        assert len(results) == 2
        assert all("markdown" in r for r in results)

    def test_batch_error_item_returns_error_field(self):
        mock_mod = _make_md_mock()
        with patch.dict(sys.modules, {"markitdown": mock_mod}):
            from warden.document_intel.converter import MarkItDownConverter
            conv = MarkItDownConverter()
            conv._redis_checked = True
            results = conv.convert_batch([
                {"file_bytes": b"x", "filename": "bad.exe"},  # unsupported
            ])
        assert "error" in results[0]

    def test_empty_markdown_returns_empty(self):
        mock_mod = _make_md_mock("")
        with patch.dict(sys.modules, {"markitdown": mock_mod}):
            from warden.document_intel.converter import _convert_raw
            result = _convert_raw(b"empty", "empty.pdf")
        assert result.markdown == ""
        assert result.word_count == 0


# ── API tests ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    import os
    os.environ.setdefault("WARDEN_API_KEY", "")
    os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
    os.environ.setdefault("REDIS_URL", "memory://")
    from warden.main import app
    return TestClient(app)


@pytest.mark.integration
def test_health_endpoint(client):
    resp = client.get("/document-intel/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "markitdown" in data


@pytest.mark.integration
def test_formats_endpoint(client):
    resp = client.get("/document-intel/formats")
    assert resp.status_code == 200
    data = resp.json()
    assert "supported_extensions" in data
    assert ".pdf" in data["supported_extensions"]
    assert ".docx" in data["supported_extensions"]


@pytest.mark.integration
def test_filter_with_file_base64(client):
    """POST /filter with file_base64 converts the file before filtering."""
    mock_mod = _make_md_mock("Hello from converted document. No threats here.")
    with patch.dict(sys.modules, {"markitdown": mock_mod}):
        file_b64 = base64.b64encode(b"fake pdf bytes").decode()
        resp = client.post("/filter", json={
            "content": "placeholder",
            "file_base64": file_b64,
            "file_filename": "report.pdf",
        })
    assert resp.status_code == 200
    data = resp.json()
    assert "allowed" in data
