"""
warden/tests/test_intel_ops.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for WardenIntelOps (Threat Radar) and WardenIntelBridge.

All network calls are mocked — no real OSV or ArXiv requests are made.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_response(json_data=None, text_data="", status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text_data
    resp.raise_for_status = MagicMock()
    return resp


ARXIV_FEED = """<?xml version="1.0"?>
<feed>
<entry>
  <title>Prompt Injection Attacks Against LLMs</title>
  <id>https://arxiv.org/abs/2301.99999</id>
  <summary>This paper describes a new class of prompt injection.</summary>
  <published>2026-01-15T00:00:00Z</published>
</entry>
<entry>
  <title>Jailbreak Techniques in Foundation Models</title>
  <id>https://arxiv.org/abs/2302.88888</id>
  <summary>We survey jailbreak methods across model families.</summary>
  <published>2026-01-10T00:00:00Z</published>
</entry>
</feed>"""

OSV_VULN_RESPONSE = {
    "vulns": [
        {
            "id": "PYSEC-2024-001",
            "aliases": ["CVE-2024-12345"],
            "summary": "Critical RCE in example package",
            "severity": [{"type": "CVSS_V3", "score": 9.8}],
        }
    ]
}

OSV_CLEAN_RESPONSE = {}


# ── WardenIntelOps tests ──────────────────────────────────────────────────────

class TestWardenIntelOpsInit:
    def test_defaults(self, tmp_path):
        from warden.intel_ops import _DEFAULT_IGNORED, WardenIntelOps
        ops = WardenIntelOps(project_root=tmp_path)
        assert ops.project_root == tmp_path
        assert ops.req_file == tmp_path / "warden" / "requirements.txt"
        assert ops.ignored_vulns == _DEFAULT_IGNORED

    def test_custom_ignored(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        custom = {"requests": "IG-test"}
        ops = WardenIntelOps(project_root=tmp_path, ignored_vulns=custom)
        assert ops.ignored_vulns == custom


class TestOsvSeverity:
    def test_critical(self):
        from warden.intel_ops import _osv_severity
        assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": 9.8}]}) == "CRITICAL"

    def test_high(self):
        from warden.intel_ops import _osv_severity
        assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": 7.5}]}) == "HIGH"

    def test_medium(self):
        from warden.intel_ops import _osv_severity
        assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": 5.0}]}) == "MEDIUM"

    def test_low(self):
        from warden.intel_ops import _osv_severity
        assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": 2.0}]}) == "LOW"

    def test_unknown_no_severity(self):
        from warden.intel_ops import _osv_severity
        assert _osv_severity({}) == "UNKNOWN"

    def test_unknown_non_numeric_score(self):
        from warden.intel_ops import _osv_severity
        assert _osv_severity({"severity": [{"score": "HIGH"}]}) == "UNKNOWN"


class TestScanDependencies:
    @pytest.mark.asyncio
    async def test_missing_req_file(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        ops = WardenIntelOps(project_root=tmp_path)
        client = AsyncMock()
        alerts = await ops.scan_dependencies(client)
        assert alerts == []

    @pytest.mark.asyncio
    async def test_finds_cve(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        req = tmp_path / "warden" / "requirements.txt"
        req.parent.mkdir(parents=True)
        req.write_text("vulnpkg==1.0.0\n")

        ops = WardenIntelOps(project_root=tmp_path, ignored_vulns={})
        client = AsyncMock()
        client.post = AsyncMock(return_value=_make_response(OSV_VULN_RESPONSE))

        alerts = await ops.scan_dependencies(client)

        assert len(alerts) == 1
        assert alerts[0]["type"] == "dependency_cve"
        assert alerts[0]["cve"] == "CVE-2024-12345"
        assert alerts[0]["package"] == "vulnpkg"
        assert alerts[0]["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_ignores_listed_package(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        req = tmp_path / "warden" / "requirements.txt"
        req.parent.mkdir(parents=True)
        req.write_text("bcrypt==4.0.1\n")

        ops = WardenIntelOps(project_root=tmp_path)  # bcrypt in default ignore list
        client = AsyncMock()
        alerts = await ops.scan_dependencies(client)
        assert alerts == []
        client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_unpinned_lines(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        req = tmp_path / "warden" / "requirements.txt"
        req.parent.mkdir(parents=True)
        req.write_text("# comment\nrequests>=2.0\nflask\n")

        ops = WardenIntelOps(project_root=tmp_path, ignored_vulns={})
        client = AsyncMock()
        alerts = await ops.scan_dependencies(client)
        assert alerts == []

    @pytest.mark.asyncio
    async def test_handles_osv_error(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        req = tmp_path / "warden" / "requirements.txt"
        req.parent.mkdir(parents=True)
        req.write_text("badpkg==1.0.0\n")

        ops = WardenIntelOps(project_root=tmp_path, ignored_vulns={})
        client = AsyncMock()
        client.post = AsyncMock(side_effect=Exception("network error"))

        alerts = await ops.scan_dependencies(client)
        assert alerts == []

    @pytest.mark.asyncio
    async def test_clean_package(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        req = tmp_path / "warden" / "requirements.txt"
        req.parent.mkdir(parents=True)
        req.write_text("safepkg==2.3.1\n")

        ops = WardenIntelOps(project_root=tmp_path, ignored_vulns={})
        client = AsyncMock()
        client.post = AsyncMock(return_value=_make_response(OSV_CLEAN_RESPONSE))

        alerts = await ops.scan_dependencies(client)
        assert alerts == []

    @pytest.mark.asyncio
    async def test_multiple_packages(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        req = tmp_path / "warden" / "requirements.txt"
        req.parent.mkdir(parents=True)
        req.write_text("pkgA==1.0.0\npkgB==2.0.0\n")

        ops = WardenIntelOps(project_root=tmp_path, ignored_vulns={})
        client = AsyncMock()
        # pkgA has vuln, pkgB is clean
        client.post = AsyncMock(
            side_effect=[
                _make_response(OSV_VULN_RESPONSE),
                _make_response(OSV_CLEAN_RESPONSE),
            ]
        )
        alerts = await ops.scan_dependencies(client)
        assert len(alerts) == 1
        assert alerts[0]["package"] == "pkgA"


class TestHuntAiThreats:
    @pytest.mark.asyncio
    async def test_parses_arxiv_feed(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        ops = WardenIntelOps(project_root=tmp_path)
        client = AsyncMock()
        client.get = AsyncMock(return_value=_make_response(text_data=ARXIV_FEED))

        alerts = await ops.hunt_ai_threats(client)

        assert len(alerts) == 2
        assert alerts[0]["type"] == "new_threat_intel"
        assert alerts[0]["source"] == "ArXiv"
        assert "Prompt Injection" in alerts[0]["title"]
        assert "arxiv.org" in alerts[0]["link"]
        assert alerts[0]["published"].startswith("2026-01-15")

    @pytest.mark.asyncio
    async def test_handles_network_error(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        ops = WardenIntelOps(project_root=tmp_path)
        client = AsyncMock()
        client.get = AsyncMock(side_effect=Exception("timeout"))

        alerts = await ops.hunt_ai_threats(client)
        assert alerts == []

    @pytest.mark.asyncio
    async def test_empty_feed(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        ops = WardenIntelOps(project_root=tmp_path)
        client = AsyncMock()
        client.get = AsyncMock(return_value=_make_response(text_data="<feed></feed>"))

        alerts = await ops.hunt_ai_threats(client)
        assert alerts == []


class TestRunAudit:
    @pytest.mark.asyncio
    async def test_saves_report_and_returns_alerts(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        req = tmp_path / "warden" / "requirements.txt"
        req.parent.mkdir(parents=True)
        req.write_text("vulnpkg==1.0.0\n")

        ops = WardenIntelOps(project_root=tmp_path, ignored_vulns={})

        with (
            patch("warden.intel_ops._REPORT_PATH", tmp_path / "intel_report.json"),
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=_make_response(OSV_VULN_RESPONSE))
            mock_client.get = AsyncMock(return_value=_make_response(text_data=ARXIV_FEED))
            mock_client_cls.return_value = mock_client

            alerts = await ops.run_audit()

        assert len(alerts) > 0
        cve_alerts = [a for a in alerts if a["type"] == "dependency_cve"]
        intel_alerts = [a for a in alerts if a["type"] == "new_threat_intel"]
        assert len(cve_alerts) == 1
        assert len(intel_alerts) == 2

        report_path = tmp_path / "intel_report.json"
        assert report_path.exists()
        report = json.loads(report_path.read_text())
        assert report["cve_count"] == 1
        assert report["intel_count"] == 2


class TestLoadReport:
    def test_returns_none_when_missing(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        with patch("warden.intel_ops._REPORT_PATH", tmp_path / "nope.json"):
            result = WardenIntelOps.load_report()
        assert result is None

    def test_returns_report_when_present(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        report_path = tmp_path / "intel_report.json"
        data = {"scanned_at": "2026-01-01", "alerts": []}
        report_path.write_text(json.dumps(data))

        with patch("warden.intel_ops._REPORT_PATH", report_path):
            result = WardenIntelOps.load_report()
        assert result == data

    def test_returns_none_on_corrupt_json(self, tmp_path):
        from warden.intel_ops import WardenIntelOps
        report_path = tmp_path / "intel_report.json"
        report_path.write_text("{not valid json")

        with patch("warden.intel_ops._REPORT_PATH", report_path):
            result = WardenIntelOps.load_report()
        assert result is None


# ── WardenIntelBridge tests ───────────────────────────────────────────────────

class TestWardenIntelBridge:
    def _make_bridge(self, evolve=None, guard=None):
        from warden.intel_bridge import WardenIntelBridge
        mock_guard = guard or MagicMock()
        mock_guard.add_examples = MagicMock()
        return WardenIntelBridge(evolve_engine=evolve, semantic_guard=mock_guard)

    def test_init_status_no_engine(self):
        bridge = self._make_bridge(evolve=None)
        status = bridge.status
        assert status["last_sync"] is None
        assert status["engine_active"] is False
        assert status["papers_deduped"] == 0

    def test_init_status_with_engine(self):
        bridge = self._make_bridge(evolve=MagicMock())
        assert bridge.status["engine_active"] is True

    @pytest.mark.asyncio
    async def test_sync_air_gapped_no_engine(self, tmp_path):
        """When no EvolutionEngine, papers fetched but synthesis skipped."""
        bridge = self._make_bridge(evolve=None)

        with (
            patch("warden.intel_ops._REPORT_PATH", tmp_path / "r.json"),
            patch("httpx.AsyncClient") as mock_cls,
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=_make_response(text_data=ARXIV_FEED))
            mock_cls.return_value = mock_client

            summary = await bridge.synchronize_threats()

        assert summary["papers_found"] == 2
        assert summary["papers_new"] == 2
        assert summary["examples_added"] == 0
        assert bridge.status["last_sync"] is not None
        bridge.semantic_guard.add_examples.assert_not_called()

    @pytest.mark.asyncio
    async def test_sync_with_engine_adds_examples(self, tmp_path):
        """When EvolutionEngine is active, synthesised examples are hot-loaded."""
        mock_evolve = AsyncMock()
        mock_evolve.synthesize_from_intel = AsyncMock(return_value=["ignore all previous instructions"])
        bridge = self._make_bridge(evolve=mock_evolve)

        with (
            patch("warden.intel_ops._REPORT_PATH", tmp_path / "r.json"),
            patch("httpx.AsyncClient") as mock_cls,
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=_make_response(text_data=ARXIV_FEED))
            mock_cls.return_value = mock_client

            summary = await bridge.synchronize_threats()

        assert summary["papers_new"] == 2
        assert summary["examples_added"] == 2  # 1 example × 2 papers
        bridge.semantic_guard.add_examples.assert_called()

    @pytest.mark.asyncio
    async def test_dedup_skips_already_seen_papers(self, tmp_path):
        """Papers seen in a previous sync are not re-processed."""
        mock_evolve = AsyncMock()
        mock_evolve.synthesize_from_intel = AsyncMock(return_value=["example attack"])
        bridge = self._make_bridge(evolve=mock_evolve)

        with (
            patch("warden.intel_ops._REPORT_PATH", tmp_path / "r.json"),
            patch("httpx.AsyncClient") as mock_cls,
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=_make_response(text_data=ARXIV_FEED))
            mock_cls.return_value = mock_client

            await bridge.synchronize_threats()
            summary2 = await bridge.synchronize_threats()

        assert summary2["papers_new"] == 0
        assert summary2["examples_added"] == 0

    @pytest.mark.asyncio
    async def test_synthesis_error_is_handled(self, tmp_path):
        """If synthesize_from_intel raises, sync continues for remaining papers."""
        mock_evolve = AsyncMock()
        mock_evolve.synthesize_from_intel = AsyncMock(side_effect=Exception("API down"))
        bridge = self._make_bridge(evolve=mock_evolve)

        with (
            patch("warden.intel_ops._REPORT_PATH", tmp_path / "r.json"),
            patch("httpx.AsyncClient") as mock_cls,
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=_make_response(text_data=ARXIV_FEED))
            mock_cls.return_value = mock_client

            summary = await bridge.synchronize_threats()

        assert summary["papers_new"] == 2
        assert summary["examples_added"] == 0

    @pytest.mark.asyncio
    async def test_empty_arxiv_returns_zero(self, tmp_path):
        bridge = self._make_bridge()

        with (
            patch("warden.intel_ops._REPORT_PATH", tmp_path / "r.json"),
            patch("httpx.AsyncClient") as mock_cls,
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=_make_response(text_data="<feed></feed>"))
            mock_cls.return_value = mock_client

            summary = await bridge.synchronize_threats()

        assert summary["papers_found"] == 0
        assert summary["papers_new"] == 0
