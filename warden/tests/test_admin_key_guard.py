"""
warden/tests/test_admin_key_guard.py — SR-9.

Three routers guarded their admin endpoints permissively::

    _ADMIN_KEY = os.getenv("ADMIN_KEY", "")          # snapshotted at import
    ...
    if _ADMIN_KEY and provided != _ADMIN_KEY:
        raise HTTPException(403, ...)

With ``ADMIN_KEY`` unset the condition short-circuits to ``False`` and the
endpoint runs for anybody. And ``ADMIN_KEY`` *was* effectively unset in
production: it had no ``docker-compose.yml`` passthrough, and these services
carry no ``env_file``, so a value in ``/opt/shadow-warden/.env`` never reached
any container.

Both halves are pinned here — the guard posture, and the passthrough that makes
the key exist at all.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest
from fastapi import HTTPException

from warden.admin_guard import admin_key_configured, require_admin_key

_REPO = pathlib.Path(__file__).resolve().parents[2]


class TestFailClosed:
    def test_unset_key_denies_with_503(self, monkeypatch):
        """The bug: unset ADMIN_KEY used to mean 'allow everyone'."""
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
        with pytest.raises(HTTPException) as exc:
            require_admin_key("anything")
        assert exc.value.status_code == 503

    def test_empty_string_key_is_treated_as_unset(self, monkeypatch):
        """ADMIN_KEY="" is the exact shape that made the old check vanish."""
        monkeypatch.setenv("ADMIN_KEY", "")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
        with pytest.raises(HTTPException) as exc:
            require_admin_key("")
        assert exc.value.status_code == 503

    def test_correct_key_passes(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "s3cret")
        require_admin_key("s3cret")

    def test_wrong_key_is_403_not_503(self, monkeypatch):
        """403 vs 503 separates 'you are not admin' from 'admin is unconfigured'."""
        monkeypatch.setenv("ADMIN_KEY", "s3cret")
        with pytest.raises(HTTPException) as exc:
            require_admin_key("wrong")
        assert exc.value.status_code == 403

    def test_missing_header_with_key_configured_is_403(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "s3cret")
        with pytest.raises(HTTPException) as exc:
            require_admin_key(None)
        assert exc.value.status_code == 403

    def test_dev_escape_is_opt_in(self, monkeypatch):
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")
        require_admin_key(None)  # must not raise

    def test_dev_escape_does_not_downgrade_a_configured_key(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "s3cret")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")
        with pytest.raises(HTTPException) as exc:
            require_admin_key("wrong")
        assert exc.value.status_code == 403

    def test_key_is_read_fresh_not_snapshotted(self, monkeypatch):
        """The three broken routers bound ADMIN_KEY at import and never re-read it."""
        monkeypatch.setenv("ADMIN_KEY", "first")
        require_admin_key("first")
        monkeypatch.setenv("ADMIN_KEY", "second")
        require_admin_key("second")
        with pytest.raises(HTTPException):
            require_admin_key("first")

    def test_comparison_is_constant_time(self):
        import inspect

        from warden import admin_guard
        assert "compare_digest" in inspect.getsource(admin_guard.require_admin_key)

    def test_admin_key_configured_reports_reality(self, monkeypatch):
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        assert admin_key_configured() is False
        monkeypatch.setenv("ADMIN_KEY", "x")
        assert admin_key_configured() is True


class TestNoFailOpenShapesRemain:
    """Ratchet: the `if key and provided != key` shape must not come back.

    Uses the AST rather than a text scan. A regex over source lines matches the
    prose in this repo that *describes* the old shape (docstrings in
    admin_guard.py and marketplace/api.py explaining what was fixed), so a text
    ratchet either fails on documentation or has to be loosened until it stops
    catching real code. The AST sees only the executable expression.
    """

    @staticmethod
    def _fail_open_guards(tree: ast.AST) -> list[int]:
        """Line numbers of `if <admin-ish> and <comparison>:` statements."""
        hits: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            test = node.test
            if not isinstance(test, ast.BoolOp) or not isinstance(test.op, ast.And):
                continue
            first = test.values[0]
            # bare truthiness check on something admin-key shaped
            if isinstance(first, ast.Name):
                name = first.id
            elif isinstance(first, ast.Attribute):
                name = first.attr
            else:
                continue
            if "admin" not in name.lower() or "key" not in name.lower():
                continue
            if any(isinstance(v, ast.Compare) for v in test.values[1:]):
                hits.append(node.lineno)
        return hits

    def test_no_fail_open_admin_guard_in_api_code(self):
        offenders = []
        for path in (_REPO / "warden").rglob("*.py"):
            rel = path.relative_to(_REPO).as_posix()
            if "/tests/" in rel or "analytics/pages" in rel:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            offenders += [f"{rel}:{ln}" for ln in self._fail_open_guards(tree)]
        assert not offenders, (
            "Fail-open admin-key guard(s) found — an unset ADMIN_KEY would skip the "
            "check entirely. Use warden.admin_guard.require_admin_key():\n  "
            + "\n  ".join(offenders)
        )

    def test_the_ratchet_detects_the_shape_it_is_meant_to_catch(self):
        """A ratchet that cannot fail is theatre."""
        bad = ast.parse(
            "def f(provided):\n"
            "    if _ADMIN_KEY and provided != _ADMIN_KEY:\n"
            "        raise Exception()\n"
        )
        assert self._fail_open_guards(bad) == [2]

    def test_the_ratchet_ignores_the_correct_shape(self):
        good = ast.parse(
            "def f(provided):\n"
            "    if not admin_key or provided != admin_key:\n"
            "        raise Exception()\n"
        )
        assert self._fail_open_guards(good) == []


class TestComposePassthrough:
    """The root cause: no passthrough meant the key never reached any container."""

    def _warden_env_block(self) -> str:
        text = (_REPO / "docker-compose.yml").read_text(encoding="utf-8")
        start = text.index("\n  warden:")
        end = text.index("\n  arq-worker:", start)
        return text[start:end]

    def test_admin_key_is_passed_through_to_warden(self):
        assert "ADMIN_KEY=${ADMIN_KEY" in self._warden_env_block(), (
            "docker-compose.yml must pass ADMIN_KEY into warden. These services have "
            "no env_file, so a value in .env silently never reaches the container — "
            "fail-open guards get bypassed and fail-closed ones deny unconditionally."
        )

    def test_passthrough_defaults_to_empty_not_a_literal(self):
        """A default must never bake a usable key into the repo."""
        block = self._warden_env_block()
        m = re.search(r"- ADMIN_KEY=\$\{ADMIN_KEY:?-?([^}]*)\}", block)
        assert m is not None, "ADMIN_KEY passthrough not found"
        assert m.group(1).strip() == "", f"ADMIN_KEY default must be empty, got {m.group(1)!r}"
