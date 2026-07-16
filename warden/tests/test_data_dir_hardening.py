"""
S1 — Secret-bearing SQLite DBs off /tmp.

Two guardrails on the single ``data_dir()`` seam that every module DB shares:

  1. ``data_path()`` creates a non-/tmp base dir with mode 0700 (+ best-effort
     chmod), so a persisted volume holding PII/secret DBs is never world-readable.
  2. ``Settings.validate()`` flags a prod deploy whose ``WARDEN_DATA_DIR`` still
     resolves under /tmp — surfaced as a config problem so ``CONFIG_FAILCLOSED``
     crash-loops the boot instead of serving credentials from ephemeral /tmp.

Dev is unaffected (default ``WARDEN_ENV=dev``): an unset environment behaves
exactly as it did before S1.
"""
from __future__ import annotations

import os
import stat

import pytest

from warden import config as cfg


def _settings(monkeypatch, *, env: str, data_dir: str) -> cfg.Settings:
    """Fresh Settings pinned to a given WARDEN_ENV + data_dir(), no side effects."""
    # Construct under a clean (default) environment so no DB field triggers a
    # makedirs on a real path, then pin the two knobs under test.
    monkeypatch.delenv("WARDEN_DATA_DIR", raising=False)
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    s = cfg.Settings()
    monkeypatch.setattr(s, "warden_env", env)
    monkeypatch.setattr(cfg, "data_dir", lambda: data_dir)
    return s


# ── is_prod helper ────────────────────────────────────────────────────────────

class TestIsProd:
    @pytest.mark.parametrize("env,expected", [
        ("prod", True), ("production", True),
        ("dev", False), ("staging", False), ("", False),
    ])
    def test_is_prod(self, monkeypatch, env, expected):
        s = _settings(monkeypatch, env=env, data_dir="/var/lib/warden")
        assert s.is_prod is expected

    def test_warden_env_normalised(self, monkeypatch):
        monkeypatch.setenv("WARDEN_ENV", "  PRODUCTION  ")
        s = cfg.Settings()
        assert s.warden_env == "production"
        assert s.is_prod is True


# ── validate(): /tmp secret-path assertion ────────────────────────────────────

class TestTmpSecretPathValidation:
    def test_prod_tmp_exact_flagged(self, monkeypatch):
        s = _settings(monkeypatch, env="production", data_dir="/tmp")
        assert any("/tmp" in p and "WARDEN_DATA_DIR" in p for p in s.validate())

    def test_prod_tmp_subdir_flagged(self, monkeypatch):
        s = _settings(monkeypatch, env="production", data_dir="/tmp/warden")
        assert any("/tmp" in p for p in s.validate())

    def test_prod_persisted_volume_ok(self, monkeypatch):
        s = _settings(monkeypatch, env="production", data_dir="/var/lib/warden")
        assert not any("WARDEN_DATA_DIR" in p for p in s.validate())

    def test_dev_tmp_not_flagged(self, monkeypatch):
        # Back-compat: dev on /tmp is exactly the historic default — no problem.
        s = _settings(monkeypatch, env="dev", data_dir="/tmp")
        assert not any("WARDEN_DATA_DIR" in p for p in s.validate())

    def test_validate_or_raise_prod_tmp(self, monkeypatch):
        s = _settings(monkeypatch, env="production", data_dir="/tmp")
        with pytest.raises(cfg.ConfigValidationError, match="/tmp"):
            s.validate_or_raise()


# ── data_path(): mode-0700 dir creation ───────────────────────────────────────

class TestDataDirMode:
    @pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
    def test_non_tmp_base_created_0700(self, monkeypatch, tmp_path):
        base = tmp_path / "warden-data"
        monkeypatch.setenv("WARDEN_DATA_DIR", str(base))
        monkeypatch.delenv("SEP_DB_PATH", raising=False)
        cfg.data_path("warden_sep.db", "SEP_DB_PATH")
        assert base.is_dir()
        mode = stat.S_IMODE(os.stat(base).st_mode)
        assert mode == 0o700, f"expected 0700, got {mode:o}"

    @pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
    def test_pre_existing_loose_dir_tightened(self, monkeypatch, tmp_path):
        base = tmp_path / "loose"
        base.mkdir(mode=0o755)
        os.chmod(base, 0o755)  # ensure loose despite umask
        monkeypatch.setenv("WARDEN_DATA_DIR", str(base))
        monkeypatch.delenv("SEP_DB_PATH", raising=False)
        cfg.data_path("warden_sep.db", "SEP_DB_PATH")
        mode = stat.S_IMODE(os.stat(base).st_mode)
        assert mode == 0o700, f"expected chmod to 0700, got {mode:o}"

    def test_tmp_base_not_chmoded(self, monkeypatch):
        # /tmp is the OS's shared sticky dir — data_path must never chmod it.
        monkeypatch.delenv("WARDEN_DATA_DIR", raising=False)
        called = {"chmod": False}
        real_chmod = os.chmod

        def _spy(path, mode, *a, **k):
            if os.path.abspath(str(path)) == "/tmp":
                called["chmod"] = True
            return real_chmod(path, mode, *a, **k)

        monkeypatch.setattr(os, "chmod", _spy)
        cfg.data_path("warden_sep.db", "SEP_DB_PATH")
        assert called["chmod"] is False
