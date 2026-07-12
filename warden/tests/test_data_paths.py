"""
Phase 6 — Data-layer path consolidation (WARDEN_DATA_DIR).

Covers warden.config.data_dir / data_path:
  - default base is /tmp (backward-compatible)
  - WARDEN_DATA_DIR relocates every default off /tmp
  - explicit per-module env override always wins
  - non-/tmp base dir is created best-effort
  - filenames are joined under the base
"""
from __future__ import annotations

import importlib
import os

from warden import config as cfg


class TestDataDir:
    def test_default_is_tmp(self, monkeypatch):
        monkeypatch.delenv("WARDEN_DATA_DIR", raising=False)
        assert cfg.data_dir() == "/tmp"

    def test_env_overrides_base(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WARDEN_DATA_DIR", str(tmp_path))
        assert cfg.data_dir() == str(tmp_path)


class TestDataPath:
    def test_default_matches_legacy_tmp(self, monkeypatch):
        monkeypatch.delenv("WARDEN_DATA_DIR", raising=False)
        monkeypatch.delenv("SEP_DB_PATH", raising=False)
        # legacy behaviour: <tmp>/<file> (os-native join; "/tmp/..." on Linux prod)
        assert cfg.data_path("warden_sep.db", "SEP_DB_PATH") == os.path.join("/tmp", "warden_sep.db")

    def test_override_env_wins(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WARDEN_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("SEP_DB_PATH", "/explicit/path/sep.db")
        assert cfg.data_path("warden_sep.db", "SEP_DB_PATH") == "/explicit/path/sep.db"

    def test_relocates_under_data_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WARDEN_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("SEP_DB_PATH", raising=False)
        got = cfg.data_path("warden_sep.db", "SEP_DB_PATH")
        assert got == str(tmp_path / "warden_sep.db")
        assert not got.startswith("/tmp/")

    def test_creates_non_tmp_base(self, monkeypatch, tmp_path):
        base = tmp_path / "nested" / "data"
        monkeypatch.setenv("WARDEN_DATA_DIR", str(base))
        monkeypatch.delenv("GSAM_DB_PATH", raising=False)
        cfg.data_path("warden_gsam.db", "GSAM_DB_PATH")
        assert base.is_dir()

    def test_no_override_env_uses_base(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WARDEN_DATA_DIR", str(tmp_path))
        assert cfg.data_path("plain.db") == str(tmp_path / "plain.db")

    def test_empty_override_env_falls_through(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WARDEN_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("SEP_DB_PATH", "")  # empty → ignored, not used
        assert cfg.data_path("warden_sep.db", "SEP_DB_PATH") == str(tmp_path / "warden_sep.db")


class TestSettingsWiring:
    def test_settings_paths_respect_data_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WARDEN_DATA_DIR", str(tmp_path))
        for var in ("SEP_DB_PATH", "MARKETPLACE_DB_PATH", "GSAM_DB_PATH", "AUTH_DB_PATH"):
            monkeypatch.delenv(var, raising=False)
        # Rebuild the settings snapshot under the patched env.
        reloaded = importlib.reload(cfg)
        try:
            assert reloaded.settings.marketplace_db_path == str(tmp_path / "warden_marketplace.db")
            assert not reloaded.settings.marketplace_db_path.startswith("/tmp/")
        finally:
            # Restore the module to a clean default-env state for other tests.
            monkeypatch.delenv("WARDEN_DATA_DIR", raising=False)
            importlib.reload(cfg)


class TestStaffClusterWiring:
    def test_staff_a2a_db_under_data_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WARDEN_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("STAFF_A2A_DB_PATH", raising=False)
        import warden.staff.a2a as a2a
        reloaded = importlib.reload(a2a)
        try:
            assert str(tmp_path / "warden_staff_a2a.db") == reloaded._DB_PATH
        finally:
            monkeypatch.delenv("WARDEN_DATA_DIR", raising=False)
            importlib.reload(reloaded)
