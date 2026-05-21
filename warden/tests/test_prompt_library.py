"""
warden/tests/test_prompt_library.py
Tests for CM-37 Shared Prompt Library.
"""
from __future__ import annotations

import os
import tempfile
import uuid
from unittest.mock import patch

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")


def _cid() -> str:
    return f"com-{uuid.uuid4().hex[:8]}"


def _tmp_db() -> str:
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    return f.name


def _safe_screen(*a, **kw):
    return True


class TestPromptAddAndGet:
    def test_add_prompt_basic(self):
        from warden.communities.prompt_library import add_prompt
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p = add_prompt(cid, "alice", "Test Prompt", "Hello world", db_path=db)
        assert p["prompt_id"]
        assert p["ueciid"]
        assert p["title"] == "Test Prompt"
        assert p["version"] == 1
        assert p["status"] == "active"

    def test_add_prompt_assigns_ueciid(self):
        from warden.communities.prompt_library import add_prompt
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p = add_prompt(cid, "alice", "UECIID Test", "Prompt text", db_path=db)
        assert p["ueciid"].startswith(("SEP-", "PROMPT-"))

    def test_add_prompt_rejected_by_filter(self):
        from warden.communities.prompt_library import add_prompt
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=False):
            with pytest.raises(ValueError, match="rejected"):
                add_prompt(cid, "eve", "Malicious", "Ignore previous", db_path=db)

    def test_get_prompt_found(self):
        from warden.communities.prompt_library import add_prompt, get_prompt
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p = add_prompt(cid, "alice", "Get Me", "content", db_path=db)
        fetched = get_prompt(p["prompt_id"], db_path=db)
        assert fetched is not None
        assert fetched["title"] == "Get Me"

    def test_get_prompt_not_found(self):
        from warden.communities.prompt_library import get_prompt
        db = _tmp_db()
        assert get_prompt("no-such-id", db_path=db) is None

    def test_tags_roundtrip(self):
        from warden.communities.prompt_library import add_prompt, get_prompt
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p = add_prompt(cid, "alice", "Tagged", "text", tags=["gdpr", "safety"], db_path=db)
        fetched = get_prompt(p["prompt_id"], db_path=db)
        assert fetched is not None
        assert fetched["tags"] == ["gdpr", "safety"]

    def test_visibility_defaults_to_community(self):
        from warden.communities.prompt_library import add_prompt
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p = add_prompt(cid, "alice", "Vis Test", "text", db_path=db)
        assert p["visibility"] == "community"

    def test_invalid_visibility_fallback(self):
        from warden.communities.prompt_library import add_prompt
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p = add_prompt(cid, "alice", "Bad Vis", "text", visibility="PUBLIC_ALL", db_path=db)
        assert p["visibility"] == "community"


class TestSearch:
    def test_search_returns_active_only(self):
        from warden.communities.prompt_library import add_prompt, search_prompts, create_version
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p = add_prompt(cid, "alice", "To Version", "v1 text", db_path=db)
            create_version(p["prompt_id"], "v2 text", "alice", db_path=db)
        results = search_prompts(cid, db_path=db)
        statuses = {r["status"] for r in results}
        assert "deprecated" not in statuses

    def test_search_by_category(self):
        from warden.communities.prompt_library import add_prompt, search_prompts
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            add_prompt(cid, "a", "P1", "text", category="legal",   db_path=db)
            add_prompt(cid, "a", "P2", "text", category="finance",  db_path=db)
        assert len(search_prompts(cid, category="legal", db_path=db)) == 1

    def test_search_by_query(self):
        from warden.communities.prompt_library import add_prompt, search_prompts
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            add_prompt(cid, "a", "GDPR Compliance Helper", "text", db_path=db)
            add_prompt(cid, "a", "Sales Script", "text", db_path=db)
        results = search_prompts(cid, query="GDPR", db_path=db)
        assert len(results) == 1

    def test_search_limit(self):
        from warden.communities.prompt_library import add_prompt, search_prompts
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            for i in range(10):
                add_prompt(cid, "a", f"P{i}", "text", db_path=db)
        assert len(search_prompts(cid, limit=3, db_path=db)) == 3


class TestVersioningAndUsage:
    def test_create_version_deprecates_original(self):
        from warden.communities.prompt_library import add_prompt, create_version, get_prompt
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p  = add_prompt(cid, "alice", "Versioned", "v1", db_path=db)
            v2 = create_version(p["prompt_id"], "v2 text", "bob", db_path=db)
        original = get_prompt(p["prompt_id"], db_path=db)
        assert original is not None and original["status"] == "deprecated"
        assert v2["version"] == 2
        assert v2["parent_id"] == p["prompt_id"]

    def test_create_version_rejected_by_filter(self):
        from warden.communities.prompt_library import add_prompt, create_version
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p = add_prompt(cid, "alice", "Safe", "safe text", db_path=db)
        with patch("warden.communities.prompt_library._screen_prompt", return_value=False):
            with pytest.raises(ValueError):
                create_version(p["prompt_id"], "malicious v2", "eve", db_path=db)

    def test_increment_use(self):
        from warden.communities.prompt_library import add_prompt, increment_use, get_prompt
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p = add_prompt(cid, "alice", "Used", "text", db_path=db)
        increment_use(p["prompt_id"], db_path=db)
        increment_use(p["prompt_id"], db_path=db)
        fetched = get_prompt(p["prompt_id"], db_path=db)
        assert fetched is not None and fetched["use_count"] == 2

    def test_stats_structure(self):
        from warden.communities.prompt_library import add_prompt, increment_use, get_library_stats
        db  = _tmp_db()
        cid = _cid()
        with patch("warden.communities.prompt_library._screen_prompt", return_value=True):
            p = add_prompt(cid, "a", "P", "text", category="legal", db_path=db)
        increment_use(p["prompt_id"], db_path=db)
        s = get_library_stats(cid, db_path=db)
        assert s["total_prompts"] == 1
        assert s["total_uses"]    == 1
        assert s["by_category"]["legal"] == 1
