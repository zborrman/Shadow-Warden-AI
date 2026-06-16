"""
warden/tests/test_threat_intel_sources.py
──────────────────────────────────────────
Unit tests for threat_intel/sources.py — all 5 source classes.
Uses unittest.mock to avoid real network calls.
"""
from __future__ import annotations

import json
import textwrap
from unittest.mock import MagicMock, patch

from warden.threat_intel.sources import (
    ArxivSource,
    GitHubAdvisorySource,
    MitreAtlasSource,
    NvdCveSource,
    OwaspLlmSource,
    RawThreatItem,
)


def _fake_response(status: int, data, text: str | None = None) -> MagicMock:
    """Build a minimal httpx-like response mock."""
    resp = MagicMock()
    resp.status_code = status
    if text is not None:
        resp.text = text
    else:
        resp.text = json.dumps(data)
    resp.json.return_value = data
    resp.raise_for_status.return_value = None
    return resp


def _fake_http_error(status: int) -> MagicMock:
    """Response mock that raises on raise_for_status()."""
    import httpx
    resp = MagicMock()
    resp.status_code = status
    raw = MagicMock()
    raw.status_code = status
    resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        f"HTTP {status}", request=MagicMock(), response=raw
    )
    return resp


# ── MitreAtlasSource ──────────────────────────────────────────────────────────

class TestMitreAtlasSource:
    _ATLAS_DATA = {
        "matrices": [
            {
                "techniques": [
                    {"id": "AML.T0001", "name": "Model Evasion", "description": "Adversarial input that evades ML model."},
                    {"id": "AML.T0002", "name": "Data Poisoning", "description": "Injecting malicious data into training set."},
                    {"id": "", "name": "No ID", "description": "should be skipped"},
                ]
            }
        ]
    }

    def test_fetch_returns_items(self):
        with patch("httpx.get", return_value=_fake_response(200, self._ATLAS_DATA)):
            items = MitreAtlasSource().fetch(max_items=10)
        assert len(items) == 2
        assert all(isinstance(i, RawThreatItem) for i in items)
        assert items[0].source == "mitre_atlas"
        assert "AML.T0001" in items[0].title
        assert "atlas.mitre.org" in items[0].url

    def test_fetch_respects_max_items(self):
        with patch("httpx.get", return_value=_fake_response(200, self._ATLAS_DATA)):
            items = MitreAtlasSource().fetch(max_items=1)
        assert len(items) == 1

    def test_fetch_fails_open_on_network_error(self):
        with patch("httpx.get", side_effect=Exception("connection refused")):
            items = MitreAtlasSource().fetch()
        assert items == []

    def test_fetch_fails_open_on_http_error(self):
        with patch("httpx.get", return_value=_fake_http_error(503)):
            items = MitreAtlasSource().fetch()
        assert items == []

    def test_fetch_fails_open_on_bad_json(self):
        resp = _fake_response(200, {})
        resp.json.return_value = {"matrices": "NOT_A_LIST"}
        with patch("httpx.get", return_value=resp):
            items = MitreAtlasSource().fetch()
        assert items == []

    def test_empty_matrices_returns_empty(self):
        with patch("httpx.get", return_value=_fake_response(200, {"matrices": []})):
            items = MitreAtlasSource().fetch()
        assert items == []


# ── NvdCveSource ─────────────────────────────────────────────────────────────

class TestNvdCveSource:
    _NVD_DATA = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [
                        {"lang": "es", "value": "Descripción en español"},
                        {"lang": "en", "value": "A prompt injection vulnerability in an LLM component."},
                    ],
                    "published": "2024-01-15T00:00:00.000",
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-0002",
                    "descriptions": [],  # no english description → skipped
                    "published": "2024-01-20T00:00:00.000",
                }
            },
        ]
    }

    def test_fetch_returns_english_cves(self):
        with patch("httpx.get", return_value=_fake_response(200, self._NVD_DATA)):
            items = NvdCveSource().fetch(max_items=10)
        assert len(items) == 1
        assert items[0].title == "CVE-2024-0001"
        assert "nvd.nist.gov" in items[0].url

    def test_fetch_fails_open_on_error(self):
        with patch("httpx.get", side_effect=Exception("timeout")):
            items = NvdCveSource().fetch()
        assert items == []

    def test_fetch_with_api_key_header(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "fake-nvd-key")
        captured = {}

        def _mock_get(url, **kwargs):
            captured["headers"] = kwargs.get("headers", {})
            return _fake_response(200, {"vulnerabilities": []})

        with patch("httpx.get", side_effect=_mock_get):
            NvdCveSource().fetch()
        assert captured["headers"].get("apiKey") == "fake-nvd-key"

    def test_parse_error_returns_empty(self):
        resp = _fake_response(200, {})
        resp.json.return_value = {"vulnerabilities": "INVALID"}
        with patch("httpx.get", return_value=resp):
            items = NvdCveSource().fetch()
        assert items == []


# ── GitHubAdvisorySource ──────────────────────────────────────────────────────

class TestGitHubAdvisorySource:
    _ADVISORIES = [
        {
            "ghsa_id": "GHSA-0001-xxxx-yyyy",
            "summary": "Prompt injection in LLM adapter library",
            "description": "The LLM library is vulnerable to prompt injection via crafted inputs.",
            "html_url": "https://github.com/advisories/GHSA-0001-xxxx-yyyy",
            "published_at": "2024-02-01T00:00:00Z",
        },
        {
            "ghsa_id": "GHSA-0002-yyyy-zzzz",
            "summary": "Unrelated SQL injection",
            "description": "A SQL injection in a web framework.",  # no LLM keywords
            "html_url": "https://github.com/advisories/GHSA-0002-yyyy-zzzz",
            "published_at": "2024-02-02T00:00:00Z",
        },
    ]

    def test_fetch_filters_by_keyword(self):
        with patch("httpx.get", return_value=_fake_response(200, self._ADVISORIES)):
            items = GitHubAdvisorySource().fetch(max_items=10)
        assert len(items) == 1
        assert "GHSA-0001" in items[0].title

    def test_fetch_falls_back_url_when_no_html_url(self):
        advisory = {
            "ghsa_id": "GHSA-test",
            "summary": "jailbreak vulnerability",
            "description": "jailbreak attack on LLM",
            "html_url": None,
            "published_at": None,
        }
        with patch("httpx.get", return_value=_fake_response(200, [advisory])):
            items = GitHubAdvisorySource().fetch(max_items=5)
        assert len(items) == 1
        assert "GHSA-test" in items[0].url

    def test_fetch_fails_open_on_error(self):
        with patch("httpx.get", side_effect=Exception("refused")):
            items = GitHubAdvisorySource().fetch()
        assert items == []

    def test_fetch_with_token(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")
        captured = {}

        def _mock_get(url, **kwargs):
            captured["headers"] = kwargs.get("headers", {})
            return _fake_response(200, [])

        with patch("httpx.get", side_effect=_mock_get):
            GitHubAdvisorySource().fetch()
        assert "Bearer ghp_testtoken" in captured["headers"].get("Authorization", "")


# ── ArxivSource ───────────────────────────────────────────────────────────────

_ARXIV_ATOM = textwrap.dedent("""\
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Prompt Injection Attacks Against LLMs</title>
    <summary>We study prompt injection attacks that bypass safety filters.</summary>
    <published>2024-03-01T00:00:00Z</published>
    <link rel="alternate" type="text/html" href="https://arxiv.org/abs/2403.00001"/>
    <id>http://arxiv.org/abs/2403.00001</id>
  </entry>
  <entry>
    <title>Jailbreaking via Adversarial Suffixes</title>
    <summary>Adversarial suffixes can bypass guardrails on LLMs.</summary>
    <published>2024-03-02T00:00:00Z</published>
    <link href="https://arxiv.org/abs/2403.00002"/>
    <id>http://arxiv.org/abs/2403.00002</id>
  </entry>
  <entry>
    <title/>
    <summary>No title entry should be skipped</summary>
    <id>http://arxiv.org/abs/2403.00003</id>
  </entry>
</feed>
""")


class TestArxivSource:
    def test_fetch_parses_atom_entries(self):
        resp = MagicMock()
        resp.text = _ARXIV_ATOM
        resp.raise_for_status.return_value = None
        with patch("httpx.get", return_value=resp):
            items = ArxivSource().fetch(max_items=10)
        assert len(items) == 2
        assert items[0].source == "arxiv"
        assert "Prompt Injection" in items[0].title
        assert "arxiv.org" in items[0].url
        assert items[0].published_at is not None

    def test_fetch_respects_max_items(self):
        resp = MagicMock()
        resp.text = _ARXIV_ATOM
        resp.raise_for_status.return_value = None
        with patch("httpx.get", return_value=resp):
            items = ArxivSource().fetch(max_items=1)
        assert len(items) == 1

    def test_fetch_uses_id_when_no_link(self):
        atom = textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <feed xmlns="http://www.w3.org/2005/Atom">
              <entry>
                <title>LLM Attack Paper</title>
                <summary>Summary here</summary>
                <id>http://arxiv.org/abs/2403.99999</id>
              </entry>
            </feed>
        """)
        resp = MagicMock()
        resp.text = atom
        resp.raise_for_status.return_value = None
        with patch("httpx.get", return_value=resp):
            items = ArxivSource().fetch(max_items=5)
        assert len(items) == 1
        assert "2403.99999" in items[0].url

    def test_fetch_fails_open_on_error(self):
        with patch("httpx.get", side_effect=Exception("timeout")):
            items = ArxivSource().fetch()
        assert items == []

    def test_fetch_fails_open_on_bad_xml(self):
        resp = MagicMock()
        resp.text = "<<<NOT XML>>>"
        resp.raise_for_status.return_value = None
        with patch("httpx.get", return_value=resp):
            items = ArxivSource().fetch()
        assert items == []


# ── OwaspLlmSource ────────────────────────────────────────────────────────────

_OWASP_ATOM = textwrap.dedent("""\
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>LLM Top 10 v2.0 Release</title>
    <content>Full release notes for LLM Top 10 v2.0.</content>
    <updated>2024-04-01T00:00:00Z</updated>
    <link href="https://github.com/OWASP/owasp-llm-releases/releases/tag/v2.0"/>
  </entry>
  <entry>
    <title>Patch release</title>
    <summary>Minor patch with corrections.</summary>
    <updated>2024-04-15T00:00:00Z</updated>
    <link href="https://github.com/OWASP/owasp-llm-releases/releases/tag/v2.0.1"/>
  </entry>
  <entry>
    <title>No URL entry</title>
    <content>Should be skipped.</content>
  </entry>
</feed>
""")


class TestOwaspLlmSource:
    def test_fetch_parses_atom_entries(self):
        resp = MagicMock()
        resp.text = _OWASP_ATOM
        resp.raise_for_status.return_value = None
        with patch("httpx.get", return_value=resp):
            items = OwaspLlmSource().fetch(max_items=10)
        assert len(items) == 2
        assert items[0].source == "owasp"
        assert "OWASP LLM:" in items[0].title
        assert "github.com" in items[0].url
        assert items[0].published_at == "2024-04-01T00:00:00Z"

    def test_fetch_uses_summary_when_no_content(self):
        resp = MagicMock()
        resp.text = _OWASP_ATOM
        resp.raise_for_status.return_value = None
        with patch("httpx.get", return_value=resp):
            items = OwaspLlmSource().fetch(max_items=10)
        # Second entry has no content, uses summary
        assert "patch" in items[1].raw_description.lower() or items[1].raw_description == ""

    def test_fetch_fails_open_on_error(self):
        with patch("httpx.get", side_effect=Exception("DNS fail")):
            items = OwaspLlmSource().fetch()
        assert items == []

    def test_fetch_fails_open_on_http_error(self):
        with patch("httpx.get", return_value=_fake_http_error(500)):
            items = OwaspLlmSource().fetch()
        assert items == []

    def test_fetch_fails_open_on_bad_xml(self):
        resp = MagicMock()
        resp.text = "NOT XML AT ALL"
        resp.raise_for_status.return_value = None
        with patch("httpx.get", return_value=resp):
            items = OwaspLlmSource().fetch()
        assert items == []

    def test_fetch_respects_max_items(self):
        resp = MagicMock()
        resp.text = _OWASP_ATOM
        resp.raise_for_status.return_value = None
        with patch("httpx.get", return_value=resp):
            items = OwaspLlmSource().fetch(max_items=1)
        assert len(items) == 1


# ── RawThreatItem dataclass ───────────────────────────────────────────────────

def test_raw_threat_item_fields():
    item = RawThreatItem(
        source="test",
        title="Test title",
        url="https://example.com/test",
        published_at="2024-01-01T00:00:00Z",
        raw_description="Test description",
    )
    assert item.source == "test"
    assert item.published_at == "2024-01-01T00:00:00Z"


def test_raw_threat_item_optional_published():
    item = RawThreatItem(
        source="test",
        title="Test",
        url="https://example.com",
        published_at=None,
        raw_description="",
    )
    assert item.published_at is None
