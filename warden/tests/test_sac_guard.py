"""
SAC execution guard tests.

Covers the two enforcement postures:
  • URL screening fail-CLOSED (SSRF/exfil block);
  • secret-path denylist (WARNING, non-blocking);
  • metadata-only GSAM emission (no content, no forbidden field hints);
  • telemetry fail-OPEN (emit exception never breaks screening).

conftest sets NET_GUARD_ALLOW_PRIVATE=true globally, so SSRF tests flip it off
and use raw IPs (no DNS round-trip).
"""
from __future__ import annotations

import pytest

from warden.gsam.schema import FORBIDDEN_FIELD_HINTS
from warden.sac import guard as g


@pytest.fixture
def _enforce_private(monkeypatch):
    monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "false")


def test_metadata_url_blocked(_enforce_private):
    v = g.screen_tool_call(
        "sova", "t1", "visual_diff",
        {"baseline_url": "https://8.8.8.8/ok", "candidate_url": "http://169.254.169.254/latest/meta"},
        url_sensitive=True,
    )
    assert v.blocked is True
    assert v.verdict == g.COMPROMISED
    assert "169.254.169.254" in v.resolved_domains
    assert v.network_calls == 2
    assert "ssrf_blocked" in v.flags


def test_loopback_blocked(_enforce_private):
    v = g.screen_tool_call("sova", "t1", "filter_request", {"url": "http://127.0.0.1:8001/x"})
    assert v.blocked is True and v.verdict == g.COMPROMISED


def test_public_url_clean(_enforce_private):
    # Raw public IP → no DNS, is_public_url True.
    v = g.screen_tool_call("sova", "t1", "visual_assert_page", {"url": "https://8.8.8.8/page"})
    assert v.blocked is False
    assert v.verdict == g.CLEAN
    assert v.resolved_domains == ["8.8.8.8"]


def test_no_urls_clean():
    v = g.screen_tool_call("sova", "t1", "get_health", {"tenant_id": "t1"})
    assert v.verdict == g.CLEAN and v.network_calls == 0


def test_secret_path_warns():
    v = g.screen_tool_call("sova", "t1", "read_file", {"path": "/home/u/.ssh/id_rsa"})
    assert v.blocked is False
    assert v.verdict == g.WARNING
    assert any(f.startswith("secret_path:") for f in v.flags)


def test_path_traversal_warns():
    v = g.screen_tool_call("sova", "t1", "read_file", {"path": "../../etc/hosts"})
    assert v.verdict == g.WARNING
    assert "path_traversal" in v.flags


def test_block_wins_over_warning(_enforce_private):
    v = g.screen_tool_call(
        "sova", "t1", "x",
        {"url": "http://127.0.0.1/", "path": "/root/.ssh/id_rsa"},
    )
    # SSRF block dominates; verdict stays COMPROMISED even with a secret-path flag.
    assert v.blocked is True and v.verdict == g.COMPROMISED


def test_emit_metadata_only(monkeypatch, _enforce_private):
    captured: dict = {}

    def _fake_emit(row: dict) -> None:
        captured.update(row)

    monkeypatch.setattr("warden.gsam.gsam_emit", _fake_emit, raising=True)

    verdict = g.screen_and_emit(
        "sova", "tenant-x", "visual_diff",
        {"candidate_url": "http://169.254.169.254/meta", "note": "secret content here"},
        url_sensitive=True,
    )
    assert verdict.blocked is True
    # Observation shipped, and it is metadata only.
    assert captured, "no observation emitted"
    assert captured["event"] == "tool_call"
    assert captured["payload_kind"] == "visual_diff"
    assert captured["scan_verdict"] == g.COMPROMISED
    assert captured["unauthorized_commands_flag"] == 1
    # No content / forbidden field hints leaked into the row.
    for hint in FORBIDDEN_FIELD_HINTS:
        assert hint not in captured
    assert "secret content here" not in str(captured)


def test_emit_fail_open(monkeypatch, _enforce_private):
    def _boom(row: dict) -> None:
        raise RuntimeError("clickhouse down")

    monkeypatch.setattr("warden.gsam.gsam_emit", _boom, raising=True)
    # Emission raising must NOT propagate — screening still returns a verdict.
    verdict = g.screen_and_emit("sova", "t1", "get_health", {"tenant_id": "t1"})
    assert verdict.verdict == g.CLEAN


def test_iter_strings_walks_nested_list_and_tuple():
    # _iter_strings must flatten strings out of list/tuple containers, not
    # just dict values — otherwise a secret path buried in a list is invisible.
    v = g.screen_tool_call(
        "sova", "t1", "read_files",
        {"paths": ["/home/u/.ssh/id_rsa", ("nested", "/etc/passwd")]},
    )
    assert v.verdict == g.WARNING
    assert any(f == "secret_path:.ssh" for f in v.flags)
    assert any(f == "secret_path:/etc/passwd" for f in v.flags)


def test_screen_tool_call_never_raises_on_iter_strings_failure(monkeypatch):
    # _iter_strings failing must degrade to a clean default verdict, not
    # propagate — screening is documented as "never raises".
    monkeypatch.setattr(
        g, "_iter_strings", lambda value: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    v = g.screen_tool_call("sova", "t1", "any_tool", {"url": "https://example.com"})
    assert v == g.GuardVerdict()


def test_url_sensitive_bare_host_key_screened(_enforce_private):
    # A bare (scheme-less) value under a known URL key is only screened when
    # url_sensitive=True — this exercises the "https://" prefixing branch.
    v = g.screen_tool_call(
        "sova", "t1", "visual_assert_page",
        {"target_url": "169.254.169.254"},
        url_sensitive=True,
    )
    assert v.blocked is True
    assert v.verdict == g.COMPROMISED
    assert "169.254.169.254" in v.resolved_domains
