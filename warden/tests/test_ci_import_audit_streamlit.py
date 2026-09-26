"""
`scripts/ci_import_audit.py` names real import failures. It reported
`warden.analytics.dashboard -> KeyError: 'ts'` on every CI run, and that row was
false: the module is a `streamlit run` entry script that executes its page on
import, and outside the Streamlit runtime `st.stop()` is a no-op, so with no
log entries it falls through into `df["ts"]` on an empty frame.

The logger writes every field the dashboard reads, `ts` included, so there was
no production defect -- only a diagnostic that cried wolf, in the one report
whose value is that its errors are real. It was scheduled as a bug to fix.

These tests pin the classifier that now skips entry scripts, and -- the half
that matters -- that it does not skip the Streamlit *libraries* beside them,
which must still be audited.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci_import_audit.py"


@pytest.fixture(scope="module")
def audit_mod():
    spec = importlib.util.spec_from_file_location("ci_import_audit", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("name", [
    "warden.analytics.dashboard",
    "warden.analytics.msp_dashboard",
])
def test_entry_scripts_are_skipped(audit_mod, name: str):
    assert audit_mod._is_streamlit_entry_script(name)


@pytest.mark.parametrize("name", [
    "warden.analytics.auth",
    "warden.analytics.components",
    "warden.analytics.accessibility",
    "warden.analytics.logger",
    "warden.marketplace.api",
])
def test_libraries_are_still_audited(audit_mod, name: str):
    """A rule of "imports streamlit" would have skipped the first three. They
    are helpers, not pages, and a real import bug in them must still surface."""
    assert not audit_mod._is_streamlit_entry_script(name)


def test_the_logger_still_writes_what_the_dashboard_reads():
    """The reason the skip is safe: the fields are written. If a future logger
    change drops one, this fails here rather than on the live page."""
    import inspect
    import re

    from warden.analytics.logger import build_entry

    reads = set(re.findall(
        r'df\["([a-z_]+)"\]',
        (Path(__file__).resolve().parents[1] / "analytics" / "dashboard.py").read_text(encoding="utf-8"),
    ))
    derived = {"hour", "date", "bucket", "count"}   # computed by the page itself
    sig = inspect.signature(build_entry)
    args = {n: ([] if n in ("flags", "secrets_found") else (True if n == "allowed" else "x"))
            for n, p in sig.parameters.items() if p.default is inspect._empty}
    for n in ("payload_len", "payload_tokens"):
        if n in args:
            args[n] = 1
    if "elapsed_ms" in args:
        args["elapsed_ms"] = 1.0
    written = set(build_entry(**args))
    assert reads - derived <= written, sorted(reads - derived - written)


def test_the_marker_is_parsed_not_matched(audit_mod, tmp_path, monkeypatch):
    """Two cases a text test gets wrong in opposite directions.

    A call written `st.set_page_config (` with a space is a real entry script
    the audit would then import and run. A library that merely *mentions* the
    name in a docstring or string is not one, and skipping it would hide a real
    import bug -- the outcome this whole file exists to prevent.
    """
    import importlib.util as _u
    import sys

    cases = {
        "spaced_entry": ("import streamlit as st\nst.set_page_config (page_title='x')\n", True),
        "mentions_only": ('"""Docs: call st.set_page_config() in the entry script."""\n'
                          'MARKER = "st.set_page_config("\n', False),
        "guarded_call": ("import streamlit as st\n"
                         "def main():\n    st.set_page_config(page_title='x')\n", False),
    }
    for name, (src, expected) in cases.items():
        f = tmp_path / f"{name}.py"
        f.write_text(src, encoding="utf-8")
        spec = _u.spec_from_file_location(name, f)
        mod = _u.module_from_spec(spec)
        sys.modules[name] = mod          # find_spec resolves from sys.modules
        try:
            assert audit_mod._is_streamlit_entry_script(name) is expected, name
        finally:
            sys.modules.pop(name, None)
