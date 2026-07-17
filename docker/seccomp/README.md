# Chromium seccomp profile — `docker/seccomp/chrome.json`

This directory is the mount point for the Chromium seccomp profile referenced by the
browser-running service in `docker-compose.yml` (see the commented `security_opt` block on
`arq-worker`) and by `docs/browser-sandbox-hardening.md`.

The profile is **not committed to the repo**. It is a large (~800-line) syscall allowlist
that is a security-critical artifact — it must be the exact, unmodified upstream profile,
not a hand-edited copy. Committing a transcribed version risks silently drifting from the
canonical one. Instead, fetch it at deploy time and pin it by checksum.

## Why a profile at all

Chromium's renderer sandbox uses `clone(CLONE_NEWUSER)` / `unshare` for unprivileged user
namespaces. Docker's *default* seccomp profile permits these on a modern host, so on many
deployments **no custom profile is needed** — running as the non-root UID 10001 (already
the case) plus a host with `kernel.unprivileged_userns_clone=1` is enough to drop
`--no-sandbox`. Mount this profile only when the host or platform ships a more restrictive
seccomp default that blocks those syscalls.

## Obtaining the profile

Use the canonical Chromium-in-Docker seccomp profile (the one the Chromium/Docker docs
point at):

```bash
cd docker/seccomp
curl -fsSLo chrome.json \
  https://raw.githubusercontent.com/jessfraz/dotfiles/master/etc/docker/seccomp/chrome.json
# Pin it: record the checksum on first fetch, then verify it on every subsequent deploy.
sha256sum chrome.json | tee chrome.json.sha256
# On later deploys, verify instead of blindly re-fetching:
#   sha256sum -c chrome.json.sha256
```

Do **not** substitute `--cap-add=SYS_ADMIN` for the profile — that grants the container
broad host privileges and is strictly worse than the `--no-sandbox` it would replace.

## Enabling

1. Fetch `chrome.json` here (above).
2. In `docker-compose.yml`, add `BROWSER_ENABLE_SANDBOX=true` to the `arq-worker`
   `environment:` block and uncomment its `security_opt:` block.
3. Redeploy and validate a real launch: run a `visual_*` tool / `sova_visual_patrol` and
   confirm Chromium starts and the page renders (the sandbox flag logic itself is unit-
   tested in `warden/tests/test_browser_sandbox_args.py`, but an end-to-end launch under
   the profile must be checked on the Playwright host).
