# Browser tool process isolation (DE-7)

`warden/tools/browser.py::BrowserSandbox` drives a headless Chromium for the SOVA visual
tools (`visual_assert_page`, `visual_diff`) and the nightly `sova_visual_patrol`. Chromium
was launched with **`--no-sandbox`**, which turns off its own multi-process renderer
sandbox. That flag is the single biggest isolation gap for the browser tool: if a
malicious page achieves RCE in the renderer, it runs with **no OS-level containment**.

`--no-sandbox` was on unconditionally because the container could not satisfy the kernel
requirements for the real sandbox (unprivileged user namespaces + a permissive-enough
seccomp profile). This document is the operator path to close that gap.

## What changed in code

`_browser_launch_args()` builds the flag list:

- **Always on** (defence-in-depth, safe everywhere, no effect on launch success):
  `--disable-dev-shm-usage`, `--disable-gpu`, `--disable-extensions`,
  `--disable-background-networking`, `--disable-sync`, `--no-first-run`,
  `--no-default-browser-check`, `--disable-features=MediaRouter`.
- **`--no-sandbox` is now conditional.** With `BROWSER_ENABLE_SANDBOX=true` it is
  **dropped**, restoring the renderer sandbox. Default is `false`, so existing
  deployments — and the trusted internal visual-patrol — are unchanged. This is opt-in
  hardening, not a forced behaviour change.

## Enabling the sandbox (operator)

Two requirements, both about giving Chromium a kernel it can sandbox in:

1. **Run as a non-root user.** The Playwright image already uses a non-root user
   (UID/GID 10001, see `warden/Dockerfile`). Chromium's sandbox refuses to engage as root
   — which is *why* `--no-sandbox` existed.

2. **Allow the syscalls the sandbox needs.** Chromium's sandbox uses `clone` with
   `CLONE_NEWUSER` (unprivileged user namespaces) and `unshare`, which Docker's default
   seccomp profile restricts. Mount a Chromium-aware seccomp profile:

   ```yaml
   # docker-compose.override.yml — for the service that runs the browser (admin / arq-worker)
   services:
     admin:
       environment:
         - BROWSER_ENABLE_SANDBOX=true
       security_opt:
         - seccomp=./docker/seccomp/chrome.json
   ```

   Use the **canonical, upstream Chromium seccomp profile** rather than a hand-rolled one:
   <https://github.com/jessfraz/dotfiles/blob/master/etc/docker/seccomp/chrome.json> (the
   profile referenced by the Chromium/Docker docs). Do **not** substitute
   `--cap-add=SYS_ADMIN` — that hands the container broad host privileges and is strictly
   worse than `--no-sandbox`.

   On hosts that forbid unprivileged user namespaces entirely
   (`kernel.unprivileged_userns_clone=0`, common on hardened/Debian hosts), enable them for
   the container host or keep `BROWSER_ENABLE_SANDBOX=false`.

## Verification

`BrowserSandbox` needs a real Chromium binary, which the CI image does not carry, so the
flag **logic** is covered by a pure unit test (`warden/tests/test_browser_sandbox_args.py`)
— asserting `--no-sandbox` is present by default, absent when enabled, and that the
defence-in-depth flags are always present. End-to-end launch under the seccomp profile must
be validated on a real Playwright host: run `sova_visual_patrol` (or any `visual_*` tool)
with `BROWSER_ENABLE_SANDBOX=true` and confirm Chromium starts and the page renders.

## Non-goals

Full VM/Kata/gVisor isolation of the browser (the SAC spec's aspiration) is out of scope —
this is the realistic, in-container hardening: real renderer sandbox + reduced surface.
