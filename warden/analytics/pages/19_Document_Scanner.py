"""
warden/analytics/pages/19_Document_Scanner.py
──────────────────────────────────────────────
Streamlit Document Intelligence page (FE-50).

Upload any file (PDF, DOCX, PPTX, XLSX, HTML, images, audio …),
convert to Markdown via MarkItDown, and run SecretRedactor + SemanticGuard.
"""
from __future__ import annotations

import os

import streamlit as st

st.set_page_config(
    page_title="Document Scanner — Shadow Warden AI",
    page_icon="📄",
    layout="wide",
)

st.title("Document Intelligence Scanner")
st.caption("Convert any file to Markdown and scan it through the Warden security pipeline.")

SUPPORTED = [
    "pdf", "docx", "pptx", "xlsx", "xls",
    "html", "htm",
    "jpg", "jpeg", "png", "gif", "bmp", "webp",
    "zip", "epub", "csv", "txt", "md",
    "mp3", "wav", "flac", "m4a",
]

# ── File upload ───────────────────────────────────────────────────────────────

uploaded = st.file_uploader(
    "Upload a document",
    type=SUPPORTED,
    help="Supported: PDF, DOCX, PPTX, XLSX, HTML, images, ZIP, EPUB, audio",
)

run_scan = st.checkbox("Run full Warden security scan after conversion", value=True)

if uploaded and st.button("Convert & Scan", type="primary"):
    file_bytes = uploaded.read()

    with st.spinner("Converting …"):
        try:
            import sys
            from unittest.mock import MagicMock

            # Use real converter; fall back to unavailable message
            from warden.document_intel.converter import MarkItDownUnavailable, get_converter

            result = get_converter().convert_bytes(file_bytes, uploaded.name)

        except MarkItDownUnavailable as exc:
            st.error(f"MarkItDown not available: {exc}")
            st.stop()
        except ValueError as exc:
            st.error(f"Unsupported file type: {exc}")
            st.stop()
        except Exception as exc:
            st.error(f"Conversion failed: {exc}")
            st.stop()

    # ── Result header ─────────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Words", result.word_count)
    col2.metric("Characters", result.char_count)
    _dc_colours = {"GENERAL": "🟢", "PHI": "🔴", "PII": "🟠", "FINANCIAL": "🟡", "CLASSIFIED": "🔴"}
    col3.metric("Data Class", f"{_dc_colours.get(result.data_class, '⚪')} {result.data_class}")
    cache_label = "Yes" if result.from_cache else "No"
    col4.metric("Cache Hit", cache_label)

    if result.secrets_found:
        st.warning(f"**{len(result.secrets_found)} secret type(s) detected and redacted:** "
                   f"{', '.join(result.secrets_found)}")
    else:
        st.success("No secrets detected in the document.")

    # ── Security scan ─────────────────────────────────────────────────────
    if run_scan and result.markdown.strip():
        with st.spinner("Running security scan …"):
            try:
                from warden.semantic_guard import SemanticGuard
                guard_result = SemanticGuard().analyse(result.markdown[:8_000])
                risk = guard_result.risk_level

                _risk_colour = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "BLOCK": "🔴"}
                st.subheader("Security Scan Result")
                risk_col, flag_col = st.columns(2)
                risk_col.metric("Risk Level", f"{_risk_colour.get(risk, '⚪')} {risk}")
                flag_col.metric("Semantic Flags", len(guard_result.flags))

                if guard_result.flags:
                    st.write("**Flags detected:**")
                    for flag in guard_result.flags:
                        st.write(f"- `{flag}`")
            except Exception as exc:
                st.info(f"Security scan unavailable (fail-open): {exc}")

    # ── Extracted Markdown ────────────────────────────────────────────────
    st.subheader("Extracted Markdown")
    tabs = st.tabs(["Rendered", "Raw"])
    with tabs[0]:
        if result.markdown.strip():
            st.markdown(result.markdown[:20_000])
            if len(result.markdown) > 20_000:
                st.caption(f"… (truncated — {len(result.markdown):,} total characters)")
        else:
            st.info("No text could be extracted from this document.")
    with tabs[1]:
        st.code(result.markdown[:20_000] or "(empty)", language="markdown")

# ── Sidebar: info ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("About")
    st.markdown("""
**Document Intelligence** (FE-50) converts uploaded files to Markdown using
[Microsoft MarkItDown](https://github.com/microsoft/markitdown), then pipes
the extracted text through:

1. **SecretRedactor** — 15 regex patterns + entropy scan
2. **SemanticGuard** — rule-based risk analyser
3. **Data Class Inference** — PHI / PII / FINANCIAL / CLASSIFIED / GENERAL

Converted Markdown is also cached in Redis (TTL: `DOC_INTEL_CACHE_TTL`, default 1 h)
so repeat uploads of the same file are instant.

**Supported formats:**
""")
    st.code(", ".join(f".{e}" for e in SUPPORTED))
    st.markdown("""
**Install:**
```bash
pip install markitdown
```
""")
