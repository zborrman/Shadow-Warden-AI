"""
DE-7 — Chromium launch-flag hardening for the browser tool.

BrowserSandbox needs a real Chromium binary (absent from the CI image), so the launch is
not exercised end-to-end here — only the pure flag builder. The security-relevant property
is that `--no-sandbox` (which disables Chromium's renderer sandbox) is present by default
for backward-compat but can be dropped via BROWSER_ENABLE_SANDBOX once the runtime provides
a real sandbox, while the always-on defence-in-depth flags never disappear.

End-to-end launch under the seccomp profile is validated on a real Playwright host — see
docs/browser-sandbox-hardening.md.
"""
from __future__ import annotations

from warden.tools.browser import _browser_launch_args

_ALWAYS_ON = {
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-features=MediaRouter",
}


class TestDefaultBehaviour:
    def test_no_sandbox_present_by_default(self, monkeypatch):
        monkeypatch.delenv("BROWSER_ENABLE_SANDBOX", raising=False)
        assert "--no-sandbox" in _browser_launch_args()

    def test_defence_in_depth_flags_always_present(self, monkeypatch):
        monkeypatch.delenv("BROWSER_ENABLE_SANDBOX", raising=False)
        args = set(_browser_launch_args())
        assert args >= _ALWAYS_ON


class TestSandboxEnabled:
    def test_env_true_drops_no_sandbox(self, monkeypatch):
        monkeypatch.setenv("BROWSER_ENABLE_SANDBOX", "true")
        args = _browser_launch_args()
        assert "--no-sandbox" not in args
        # hardening flags survive with the sandbox on
        assert set(args) >= _ALWAYS_ON

    def test_explicit_param_overrides_env(self, monkeypatch):
        monkeypatch.setenv("BROWSER_ENABLE_SANDBOX", "false")
        assert "--no-sandbox" not in _browser_launch_args(enable_sandbox=True)
        monkeypatch.setenv("BROWSER_ENABLE_SANDBOX", "true")
        assert "--no-sandbox" in _browser_launch_args(enable_sandbox=False)

    def test_env_is_case_insensitive_and_strict(self, monkeypatch):
        monkeypatch.setenv("BROWSER_ENABLE_SANDBOX", "TRUE")
        assert "--no-sandbox" not in _browser_launch_args()
        # anything that is not "true" keeps the legacy escape hatch
        for val in ("1", "yes", "on", "", "false"):
            monkeypatch.setenv("BROWSER_ENABLE_SANDBOX", val)
            assert "--no-sandbox" in _browser_launch_args(), val
