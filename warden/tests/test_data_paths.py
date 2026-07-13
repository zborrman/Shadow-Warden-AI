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
        # Must no longer sit at the LEGACY hardcoded location. (Don't assert the path
        # isn't under /tmp: on Linux CI pytest's tmp_path is itself /tmp/pytest-of-*.)
        assert got != os.path.join("/tmp", "warden_sep.db")

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
        # Build a FRESH Settings snapshot rather than importlib.reload(cfg): the
        # dataclass re-evaluates its default_factory against the current env, and a
        # reload would mint new class objects (ConfigValidationError, …), breaking
        # pytest.raises/isinstance in test modules that imported them earlier.
        fresh = cfg.Settings()
        assert fresh.marketplace_db_path == str(tmp_path / "warden_marketplace.db")
        # Legacy hardcoded default is gone (see note above re: /tmp on Linux CI).
        assert fresh.marketplace_db_path != os.path.join("/tmp", "warden_marketplace.db")


class TestStaffClusterWiring:
    def test_staff_a2a_db_under_data_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WARDEN_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("STAFF_A2A_DB_PATH", raising=False)
        # a2a snapshots _DB_PATH at import, so resolve through data_path directly
        # instead of reloading the module (reload rebinds its classes session-wide).
        assert cfg.data_path("warden_staff_a2a.db", "STAFF_A2A_DB_PATH") == str(
            tmp_path / "warden_staff_a2a.db"
        )
