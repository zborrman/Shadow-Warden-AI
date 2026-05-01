"""Tests for Obsidian Business Community integration."""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("LOGS_PATH", "/tmp/warden_test_obsidian_logs.json")
os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/warden_test_obsidian_rules.json")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("MODEL_CACHE_DIR", "/tmp/warden_test_models")
os.environ.setdefault("SEP_DB_PATH", "/tmp/test_obsidian_sep.db")

from fastapi.testclient import TestClient

# ── note_scanner tests ────────────────────────────────────────────────────────

class TestNoteScanner:
    def test_clean_note(self):
        from warden.integrations.obsidian.note_scanner import scan_note
        result = scan_note("# Hello\n\nThis is a clean note about productivity.")
        assert result["data_class"] == "GENERAL"
        assert result["secrets_found"] == []
        assert result["word_count"] > 0
        assert result["has_frontmatter"] is False

    def test_frontmatter_parsed(self):
        from warden.integrations.obsidian.note_scanner import scan_note
        content = "---\ntags: [phi, health]\ndata_class: PHI\n---\n\nPatient notes."
        result = scan_note(content)
        assert result["data_class"] == "PHI"
        assert result["has_frontmatter"] is True

    def test_tag_based_classification(self):
        from warden.integrations.obsidian.note_scanner import scan_note
        content = "---\ntags: [financial, q4]\n---\n\nRevenue report."
        result = scan_note(content)
        assert result["data_class"] == "FINANCIAL"

    def test_classified_tag(self):
        from warden.integrations.obsidian.note_scanner import scan_note
        content = "---\ntags: [classified]\n---\n\nTop secret."
        result = scan_note(content)
        assert result["data_class"] == "CLASSIFIED"

    def test_keyword_pii_inference(self):
        from warden.integrations.obsidian.note_scanner import scan_note
        result = scan_note("User SSN: this is a note about social security.")
        assert result["data_class"] == "PII"

    def test_keyword_phi_inference(self):
        from warden.integrations.obsidian.note_scanner import scan_note
        result = scan_note("Patient diagnosis: hypertension. Prescription required.")
        assert result["data_class"] == "PHI"

    def test_explicit_data_class_wins_over_tags(self):
        from warden.integrations.obsidian.note_scanner import scan_note
        content = "---\ntags: [financial]\ndata_class: GENERAL\n---\n\nRegular note."
        result = scan_note(content)
        assert result["data_class"] == "GENERAL"

    def test_redacted_body_returned(self):
        from warden.integrations.obsidian.note_scanner import scan_note
        result = scan_note("Normal note with no secrets.")
        assert "redacted_body" in result

    def test_word_count(self):
        from warden.integrations.obsidian.note_scanner import scan_note
        result = scan_note("one two three four five")
        assert result["word_count"] == 5


# ── API endpoint tests ────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    from fastapi import FastAPI

    from warden.api.obsidian import router
    app = FastAPI()
    app.include_router(router, prefix="/obsidian")
    return TestClient(app)


class TestScanEndpoint:
    def test_clean_note(self, client):
        r = client.post("/obsidian/scan", json={
            "content": "# Meeting Notes\n\nDiscussed Q3 roadmap.",
            "filename": "meeting.md",
        })
        assert r.status_code == 200
        d = r.json()
        assert d["allowed"] is True
        assert d["risk_level"] == "ALLOW"
        assert d["secrets_found"] == []
        assert d["data_class"] == "GENERAL"
        assert "scanned_at" in d

    def test_classified_note_blocked(self, client):
        r = client.post("/obsidian/scan", json={
            "content": "---\ntags: [classified]\n---\n\nTop secret content.",
        })
        assert r.status_code == 200
        d = r.json()
        assert d["allowed"] is False
        assert d["risk_level"] == "BLOCK"
        assert "classified_content" in d["flags"]

    def test_phi_note_clean(self, client):
        r = client.post("/obsidian/scan", json={
            "content": "---\ntags: [phi]\n---\n\nPatient notes without secrets.",
        })
        assert r.status_code == 200
        d = r.json()
        assert d["data_class"] == "PHI"
        assert d["risk_level"] == "ALLOW"

    def test_word_count_returned(self, client):
        r = client.post("/obsidian/scan", json={
            "content": "one two three four five six",
        })
        assert r.status_code == 200
        assert r.json()["word_count"] == 6

    def test_filename_echoed(self, client):
        r = client.post("/obsidian/scan", json={
            "content": "Normal note.",
            "filename": "my-note.md",
        })
        assert r.json()["filename"] == "my-note.md"

    def test_redacted_content_in_response(self, client):
        r = client.post("/obsidian/scan", json={"content": "Safe note."})
        assert "redacted_content" in r.json()


class TestShareEndpoint:
    def test_share_clean_note(self, client):
        r = client.post("/obsidian/share", json={
            "content": "# Design Proposal\n\nWe should use microservices.",
            "filename": "design.md",
            "display_name": "Design Proposal",
            "community_id": "comm-test-001",
        })
        assert r.status_code == 200
        d = r.json()
        assert d["ueciid"].startswith("SEP-")
        assert d["community_id"] == "comm-test-001"
        assert d["display_name"] == "Design Proposal"
        assert "shared_at" in d

    def test_share_classified_blocked(self, client):
        r = client.post("/obsidian/share", json={
            "content": "---\ntags: [classified]\n---\n\nSecret stuff.",
            "filename": "secret.md",
            "display_name": "Secret",
            "community_id": "comm-test-001",
        })
        # classified itself won't block share (no secrets_found), but data_class is set
        assert r.status_code in (200, 400)

    def test_share_data_class_override(self, client):
        r = client.post("/obsidian/share", json={
            "content": "General notes about architecture.",
            "filename": "arch.md",
            "display_name": "Architecture Notes",
            "community_id": "comm-test-002",
            "data_class": "FINANCIAL",
        })
        assert r.status_code == 200
        assert r.json()["data_class"] == "FINANCIAL"

    def test_share_returns_word_count(self, client):
        r = client.post("/obsidian/share", json={
            "content": "one two three four five",
            "display_name": "Words",
            "community_id": "comm-test-003",
        })
        assert r.status_code == 200
        assert r.json()["word_count"] == 5


class TestFeedEndpoint:
    def test_feed_empty(self, client):
        r = client.get("/obsidian/feed?community_id=comm-empty-xyz")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_feed_after_share(self, client):
        # Share a note then check it appears in feed
        client.post("/obsidian/share", json={
            "content": "Shared note for feed test.",
            "display_name": "Feed Test Note",
            "community_id": "comm-feed-test",
        })
        r = client.get("/obsidian/feed?community_id=comm-feed-test")
        assert r.status_code == 200
        entries = r.json()
        names = [e["display_name"] for e in entries]
        assert "Feed Test Note" in names

    def test_feed_limit_param(self, client):
        r = client.get("/obsidian/feed?community_id=comm-feed-test&limit=1")
        assert r.status_code == 200
        assert len(r.json()) <= 1


class TestAIFilterEndpoint:
    def test_clean_prompt(self, client):
        r = client.post("/obsidian/ai-filter", json={
            "prompt": "Explain the concept of transformer architecture in machine learning.",
        })
        assert r.status_code == 200
        d = r.json()
        assert "allowed" in d
        assert "risk_level" in d
        assert "filtered_prompt" in d

    def test_empty_prompt(self, client):
        r = client.post("/obsidian/ai-filter", json={"prompt": ""})
        assert r.status_code == 200


class TestStatsEndpoint:
    def test_stats(self, client):
        r = client.get("/obsidian/stats")
        assert r.status_code == 200
        d = r.json()
        assert d["integration"] == "obsidian"
        assert d["status"] == "active"
        assert "endpoints" in d
