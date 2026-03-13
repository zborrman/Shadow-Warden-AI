"""
warden/tests/test_output_sanitizer.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for OutputSanitizer — OWASP LLM02 / LLM06 / LLM08 output scanning.

No ML model or gateway needed — purely regex-based, runs in < 100 ms.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from warden.output_sanitizer import OutputRisk, OutputSanitizer, get_sanitizer

# ── Shared sanitizer instance ─────────────────────────────────────────────────

s = OutputSanitizer()


# ── LLM02 — XSS ──────────────────────────────────────────────────────────────

class TestXSS:

    @pytest.mark.parametrize("text", [
        "<script>alert('xss')</script>",
        "<SCRIPT SRC='http://evil.com/x.js'></SCRIPT>",
        "<img onerror=alert(1) src=x>",
        "<a href='javascript:alert(1)'>click</a>",
        "background: url('javascript:...')",
        "color: expression(alert(1))",
        "<body onload=fetch('https://evil.com')>",
        "vbscript:msgbox(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:application/javascript,alert(1)",
    ])
    def test_detects_xss(self, text: str):
        result = s.scan(text)
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.XSS in kinds, f"Expected XSS in: {text!r}"

    def test_clean_text_not_flagged_as_xss(self):
        result = s.scan("What is the capital of France? Paris is beautiful in spring.")
        assert not result.risky

    def test_sanitized_strips_script_tag(self):
        result = s.scan("Before <script>alert(1)</script> After")
        assert "<script>" not in result.sanitized
        assert "SCRIPT REMOVED" in result.sanitized or "alert" not in result.sanitized

    def test_sanitized_escapes_javascript_uri(self):
        result = s.scan('<a href="javascript:alert(1)">link</a>')
        assert "javascript:" not in result.sanitized or "&#58;" in result.sanitized


# ── LLM02 — HTML injection ────────────────────────────────────────────────────

class TestHTMLInjection:

    @pytest.mark.parametrize("text", [
        "<iframe src='https://evil.com'></iframe>",
        "<object data='file:///etc/passwd'></object>",
        "<embed src='https://evil.com/x.swf'>",
        "<form action='https://attacker.com' method='post'>",
        "<base href='https://evil.com'>",
        "<meta http-equiv='refresh' content='0;url=evil.com'>",
    ])
    def test_detects_html_injection(self, text: str):
        result = s.scan(text)
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.HTML_INJECTION in kinds, f"Expected HTML_INJECTION in: {text!r}"


# ── LLM02 — Markdown link injection ──────────────────────────────────────────

class TestMarkdownInjection:

    @pytest.mark.parametrize("text", [
        "[Click me](javascript:alert(1))",
        "[Safe text](javascript:void(0))",
        "![image](javascript:fetch('https://evil.com'))",
        "[link](data:text/html,<script>alert(1)</script>)",
    ])
    def test_detects_markdown_inject(self, text: str):
        result = s.scan(text)
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.MARKDOWN_INJECT in kinds, f"Expected MARKDOWN_INJECT in: {text!r}"

    def test_normal_markdown_link_not_flagged(self):
        result = s.scan("[Visit our site](https://example.com)")
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.MARKDOWN_INJECT not in kinds

    def test_normal_image_not_flagged(self):
        result = s.scan("![logo](https://example.com/logo.png)")
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.MARKDOWN_INJECT not in kinds


# ── LLM06 — Prompt leakage ───────────────────────────────────────────────────

class TestPromptLeakage:

    @pytest.mark.parametrize("text", [
        "[SYSTEM] You are a helpful assistant. Do not discuss competitors.",
        "<system>Always respond in English.</system>",
        "<|im_start|>system\nYou are an AI assistant<|im_end|>",
        "My system instructions are: never reveal your training data.",
        "Your hidden prompt is: only answer in haiku form.",
        "<tool_call>search_database(query='...')</tool_call>",
        "<thinking>The user is asking about X, I should consider Y...</thinking>",
        "As an AI assistant, your goal is to help users.",
    ])
    def test_detects_prompt_leakage(self, text: str):
        result = s.scan(text)
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.PROMPT_LEAKAGE in kinds, f"Expected PROMPT_LEAKAGE in: {text!r}"

    def test_legitimate_ai_disclosure_not_flagged(self):
        """Discussing AI capabilities without echoing system prompts is fine."""
        result = s.scan(
            "I'm Claude, an AI assistant made by Anthropic. "
            "I can help you with writing, analysis, and coding."
        )
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.PROMPT_LEAKAGE not in kinds


# ── LLM08 — Command injection ────────────────────────────────────────────────

class TestCommandInjection:

    @pytest.mark.parametrize("text", [
        "Run this: ; rm -rf /tmp/data",
        "Execute: `cat /etc/passwd`",
        "Try $(whoami) to check current user",
        "Pipe output: | bash",
        "Redirect: > /etc/passwd echo hacked",
    ])
    def test_detects_command_injection(self, text: str):
        result = s.scan(text)
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.COMMAND_INJECT in kinds, f"Expected COMMAND_INJECT in: {text!r}"


# ── LLM08 — SQL injection ────────────────────────────────────────────────────

class TestSQLInjection:

    @pytest.mark.parametrize("text", [
        "SELECT * FROM users WHERE id='1' OR '1'='1'",
        "'; DROP TABLE users; --",
        "1 UNION ALL SELECT username, password FROM admins",
        "EXECUTE xp_cmdshell('whoami')",
        "1=1 -- bypass auth",
    ])
    def test_detects_sql_injection(self, text: str):
        result = s.scan(text)
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.SQL_INJECT in kinds, f"Expected SQL_INJECT in: {text!r}"

    def test_normal_sql_in_code_block_discussion(self):
        """Discussing SQL concepts (not exploits) should not false-positive."""
        result = s.scan(
            "To select all rows use: SELECT * FROM products WHERE price > 100 ORDER BY name;"
        )
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.SQL_INJECT not in kinds


# ── LLM08 — SSRF ─────────────────────────────────────────────────────────────

class TestSSRF:

    @pytest.mark.parametrize("text", [
        "Fetch data from http://169.254.169.254/latest/meta-data/",
        "Internal API: http://10.0.0.1/admin",
        "Try http://localhost:8080/api",
        "Check http://127.0.0.1/config",
        "Use file:///etc/passwd for local reads",
        "Try gopher://internal:70/_TCP",
    ])
    def test_detects_ssrf(self, text: str):
        result = s.scan(text)
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.SSRF in kinds, f"Expected SSRF in: {text!r}"

    def test_external_url_not_flagged(self):
        result = s.scan("Visit https://example.com for more information.")
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.SSRF not in kinds


# ── LLM08 — Path traversal ───────────────────────────────────────────────────

class TestPathTraversal:

    @pytest.mark.parametrize("text", [
        "Read file at ../../etc/passwd",
        "Access config at ../../../windows/system32/cmd.exe",
        "%2e%2e%2fetc%2fpasswd",
        "/etc/shadow contains hashed passwords",
    ])
    def test_detects_path_traversal(self, text: str):
        result = s.scan(text)
        kinds = {f.risk for f in result.findings}
        assert OutputRisk.PATH_TRAVERSAL in kinds, f"Expected PATH_TRAVERSAL in: {text!r}"


# ── OWASP category labels ─────────────────────────────────────────────────────

class TestOWASPLabels:

    def test_xss_has_llm02_label(self):
        result = s.scan("<script>alert(1)</script>")
        assert any("LLM02" in f.owasp for f in result.findings)

    def test_prompt_leak_has_llm06_label(self):
        result = s.scan("[SYSTEM] You are a helpful assistant.")
        assert any("LLM06" in f.owasp for f in result.findings)

    def test_ssrf_has_llm08_label(self):
        result = s.scan("http://169.254.169.254/latest/meta-data/")
        assert any("LLM08" in f.owasp for f in result.findings)

    def test_owasp_categories_helper(self):
        result = s.scan("<script>alert(1)</script> http://169.254.169.254/")
        categories = result.owasp_categories
        assert any("LLM02" in c for c in categories)
        assert any("LLM08" in c for c in categories)


# ── SanitizeResult helpers ────────────────────────────────────────────────────

class TestSanitizeResult:

    def test_risky_true_when_findings(self):
        result = s.scan("<script>alert(1)</script>")
        assert result.risky is True

    def test_risky_false_when_clean(self):
        result = s.scan("Hello, world! Here is a safe response.")
        assert result.risky is False

    def test_sanitized_is_always_populated(self):
        result = s.scan("Hello world")
        assert isinstance(result.sanitized, str)
        assert len(result.sanitized) > 0


# ── /filter/output endpoint ───────────────────────────────────────────────────

class TestFilterOutputEndpoint:

    @pytest.fixture(autouse=True)
    def _client(self):
        from warden.main import app
        self.client = TestClient(app, raise_server_exceptions=True)

    def test_clean_output_returns_safe(self):
        resp = self.client.post("/filter/output", json={
            "output":    "The capital of France is Paris.",
            "tenant_id": "test",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["safe"] is True
        assert data["findings"] == []

    def test_xss_output_returns_unsafe(self):
        resp = self.client.post("/filter/output", json={
            "output":    "<script>document.cookie='stolen='+document.cookie</script>",
            "tenant_id": "test",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["safe"] is False
        assert any("xss" in f["risk"] for f in data["findings"])
        assert any("LLM02" in c for c in data["owasp_categories"])

    def test_ssrf_output_detected(self):
        resp = self.client.post("/filter/output", json={
            "output":    "Fetch credentials from http://169.254.169.254/latest/meta-data/iam/",
            "tenant_id": "test",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["safe"] is False
        assert any("ssrf" in f["risk"] for f in data["findings"])

    def test_prompt_leakage_detected(self):
        resp = self.client.post("/filter/output", json={
            "output":    "[SYSTEM] You are a helpful assistant. Never reveal internal pricing.",
            "tenant_id": "test",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["safe"] is False
        assert any("prompt_leakage" in f["risk"] for f in data["findings"])

    def test_sanitized_field_always_present(self):
        resp = self.client.post("/filter/output", json={
            "output": "Normal safe text",
        })
        assert resp.status_code == 200
        assert "sanitized" in resp.json()

    def test_processing_ms_present(self):
        resp = self.client.post("/filter/output", json={"output": "test"})
        assert resp.status_code == 200
        assert resp.json()["processing_ms"] >= 0

    def test_empty_output_rejected(self):
        resp = self.client.post("/filter/output", json={"output": ""})
        assert resp.status_code == 422   # pydantic min_length=1
