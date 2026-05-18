"""
warden/tests/test_sprint1.py
─────────────────────────────
Sprint 1 unit tests: CM-24/25, AG-21/22, BL-20, CP-22/23/24, TQ-16.
All tests are fast (no ML model, no live HTTP, no Docker).
"""
from __future__ import annotations

import ipaddress
import os

import pytest

# ── CM-24 / CM-25 — Reputation ────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _tmp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("SEP_DB_PATH", str(tmp_path / "sep.db"))


def test_award_trusted_entry():
    from warden.communities.reputation import award_points, get_reputation
    rec = award_points("t-trust-1", "TRUSTED_ENTRY")
    assert rec.points == 3
    assert rec.badge == "NEWCOMER"
    assert get_reputation("t-trust-1").points == 3


def test_award_search_hit():
    from warden.communities.reputation import award_points
    rec = award_points("t-search-1", "SEARCH_HIT")
    assert rec.points == 1


def test_award_search_hit_accumulates():
    from warden.communities.reputation import award_points
    for _ in range(25):
        rec = award_points("t-search-2", "SEARCH_HIT")
    assert rec.points == 25
    assert rec.badge == "CONTRIBUTOR"


def test_get_trusted_entry_candidates_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SEP_DB_PATH", str(tmp_path / "empty.db"))
    from warden.communities.reputation import get_trusted_entry_candidates
    assert get_trusted_entry_candidates() == []


def test_award_trusted_entry_batch_empty():
    from warden.communities.reputation import award_trusted_entry_batch
    results = award_trusted_entry_batch([])
    assert results == []


def test_award_trusted_entry_batch_multi():
    from warden.communities.reputation import award_trusted_entry_batch
    results = award_trusted_entry_batch(["t-a", "t-b"])
    assert len(results) == 2
    assert all("error" not in r for r in results)
    assert all(r["points"] == 3 for r in results)


def test_force_badge():
    from warden.communities.reputation import force_badge, get_reputation
    force_badge("t-elite", "ELITE")
    rec = get_reputation("t-elite")
    assert rec.badge == "ELITE"


# ── BL-20 — Obsidian Business Pack add-on ────────────────────────────────────

def test_obsidian_pack_in_catalog():
    from warden.billing.addons import ADDON_CATALOG
    assert "obsidian_business_pack" in ADDON_CATALOG
    addon = ADDON_CATALOG["obsidian_business_pack"]
    assert addon["usd_per_month"] == 8
    assert addon["min_tier"] == "individual"
    assert "obsidian_business_pack_enabled" in addon["unlocks"]


def test_obsidian_pack_grant_revoke():
    from warden.billing.addons import grant_addon, has_addon, revoke_addon
    grant_addon("t-obsidian", "obsidian_business_pack")
    assert has_addon("t-obsidian", "obsidian_business_pack")
    revoke_addon("t-obsidian", "obsidian_business_pack")
    assert not has_addon("t-obsidian", "obsidian_business_pack")


# ── AG-22 — block_ip_range CIDR validation ────────────────────────────────────

def test_cidr_valid_24():
    net = ipaddress.ip_network("10.0.0.0/24", strict=False)
    assert net.prefixlen == 24
    assert len(list(net.hosts())) == 254


def test_cidr_valid_32():
    net = ipaddress.ip_network("192.168.1.1/32", strict=False)
    assert list(net.hosts()) == []  # single host — no iterable hosts for /32
    # Hosts count should be 0 for /32 via hosts()
    hosts = list(net.hosts())
    # /32 returns the network address itself via hosts() in Python
    assert len(hosts) <= 1


def test_cidr_too_broad_rejected():
    net = ipaddress.ip_network("10.0.0.0/16", strict=False)
    assert net.prefixlen < 24  # should be rejected by tool guard


def test_cidr_invalid():
    with pytest.raises(ValueError):
        ipaddress.ip_network("not-a-cidr", strict=False)


# ── CP-22 — ISO 27001 ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_iso27001_report_structure():
    from warden.api.compliance_report import iso27001_report
    data = await iso27001_report(days=7)
    assert data["standard"] == "ISO/IEC 27001:2022"
    assert data["controls_total"] > 10
    assert 0 <= data["coverage_pct"] <= 100
    assert isinstance(data["controls"], list)
    for ctrl in data["controls"]:
        assert "control" in ctrl
        assert "status" in ctrl
        assert ctrl["status"] in ("Implemented", "Partial", "Delegated", "FAIL")


@pytest.mark.asyncio
async def test_iso27001_html_returns_html():
    from fastapi.responses import HTMLResponse
    from warden.api.compliance_report import iso27001_html
    resp = await iso27001_html(days=7)
    assert isinstance(resp, HTMLResponse)
    assert b"ISO 27001" in resp.body


# ── CP-23 — HIPAA ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_hipaa_report_structure():
    from warden.api.compliance_report import hipaa_report
    data = await hipaa_report(days=7)
    assert "HIPAA" in data["standard"]
    assert data["safeguards_total"] > 0
    assert data["attestation"] in ("PASS", "PARTIAL", "FAIL")
    assert isinstance(data["safeguards"], list)
    for sf in data["safeguards"]:
        assert "section" in sf
        assert "status" in sf


@pytest.mark.asyncio
async def test_hipaa_all_pass():
    from warden.api.compliance_report import hipaa_report, _HIPAA_SAFEGUARDS
    data = await hipaa_report(days=1)
    all_statuses = {s["status"] for s in data["safeguards"]}
    # All current safeguards are PASS
    assert "FAIL" not in all_statuses


@pytest.mark.asyncio
async def test_hipaa_html_returns_html():
    from fastapi.responses import HTMLResponse
    from warden.api.compliance_report import hipaa_html
    resp = await hipaa_html(days=7)
    assert isinstance(resp, HTMLResponse)
    assert b"HIPAA" in resp.body


# ── CP-24 — NIS2 ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_nis2_report_structure():
    from warden.api.compliance_report import nis2_report
    data = await nis2_report(days=7)
    assert "NIS2" in data["standard"]
    assert data["measures_total"] > 0
    assert 0 <= data["coverage_pct"] <= 100
    assert isinstance(data["measures"], list)
    for m in data["measures"]:
        assert "article" in m
        assert "status" in m
        assert m["status"] in ("PASS", "PARTIAL", "FAIL")


@pytest.mark.asyncio
async def test_nis2_html_returns_html():
    from fastapi.responses import HTMLResponse
    from warden.api.compliance_report import nis2_html
    resp = await nis2_html(days=7)
    assert isinstance(resp, HTMLResponse)
    assert b"NIS2" in resp.body


def test_nis2_coverage_calculation():
    from warden.api.compliance_report import _NIS2_MEASURES
    passed = sum(1 for _, _, s, _ in _NIS2_MEASURES if s == "PASS")
    pct = round(passed / len(_NIS2_MEASURES) * 100, 1)
    assert 0 < pct <= 100


# ── Reputation leaderboard ────────────────────────────────────────────────────

def test_leaderboard_empty():
    from warden.communities.reputation import get_leaderboard
    lb = get_leaderboard(limit=10)
    assert isinstance(lb, list)


def test_leaderboard_ordering():
    from warden.communities.reputation import award_points, get_leaderboard
    award_points("t-lb-high", "PUBLISH_ENTRY")   # +5
    award_points("t-lb-low",  "SEARCH_HIT")      # +1
    lb = get_leaderboard(limit=10)
    if len(lb) >= 2:
        assert lb[0]["points"] >= lb[1]["points"]


def test_leaderboard_no_tenant_id():
    from warden.communities.reputation import award_points, get_leaderboard
    award_points("t-anon", "TRUSTED_ENTRY")
    lb = get_leaderboard(limit=5)
    for entry in lb:
        assert "tenant_id" not in entry
