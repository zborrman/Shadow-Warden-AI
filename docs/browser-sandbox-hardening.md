# Browser tool process isolation (DE-7 / S4)

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

   The base `docker-compose.yml` already carries this wiring **commented** on the
   `arq-worker` service (the one that drives Chromium via `sova_visual_patrol` / the
   `visual_*` tools): add `BROWSER_ENABLE_SANDBOX=true` to its `environment:` block and
   uncomment its `security_opt:` block.

   ```yaml
   # arq-worker (already UID 10001 non-root)
   environment:
     - BROWSER_ENABLE_SANDBOX=true      # add to the existing block
   security_opt:
     - seccomp=./docker/seccomp/chrome.json
   ```

   The profile itself is **not committed** — it is a security-critical ~800-line syscall
   allowlist that must be the exact upstream artifact, so `docker/seccomp/README.md` is the
   authoritative source + checksum-pin procedure (fetch the **canonical, upstream Chromium
   seccomp profile**, don't hand-roll one). On a modern host Docker's *default* seccomp
   already permits Chromium's user-namespace syscalls, so the profile is often unnecessary —
   non-root + `kernel.unprivileged_userns_clone=1` is enough. Do **not** substitute
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

## In-process tool resource + timeout budget (S4)

The renderer sandbox contains a *compromised page*; it does nothing about a tool that
simply **hangs or runs away** in the gateway process. Most SOVA / MasterAgent tools are
thin HTTP calls to `localhost:8001`, bounded by the httpx timeout — but the browser visual
tools (`visual_assert_page`, `visual_diff`) run **in-process**: they launch Chromium and
call the Anthropic vision API inside the event loop, with no such boundary. A wedged page
load or a stalled upstream call would block the dispatch coroutine indefinitely, and a
burst of visual-tool calls could spawn unbounded concurrent Chromium processes.

`warden/agent/tool_budget.py` wraps **every** dispatch through `traced_dispatch`:

- **Timeout budget** (`asyncio.wait_for`): a handler that overruns its wall-clock budget is
  cancelled and the caller gets a structured `{"error": "tool_timeout", …}` result instead
  of a hang. Cancelling the coroutine runs `BrowserSandbox.__aexit__`, so Chromium is torn
  down rather than leaked. Defaults: `SOVA_TOOL_TIMEOUT_S=60`, `SOVA_BROWSER_TOOL_TIMEOUT_S=120`.
- **Concurrency budget**: an `asyncio.Semaphore` caps simultaneous in-process browser-tool
  runs (`SOVA_BROWSER_MAX_CONCURRENCY=2`), so a burst can't exhaust host memory / handles.

This is **fail-safe, not fail-open** — exceeding a budget is a bounded, logged denial, never
a silent pass. Covered by `warden/tests/test_tool_budget.py` (no Chromium / network needed).

## Non-goals

Full VM/Kata/gVisor isolation of the browser (the SAC spec's aspiration) is out of scope —
this is the realistic, in-container hardening: real renderer sandbox + reduced surface +
a resource/timeout budget on the in-process tools.
