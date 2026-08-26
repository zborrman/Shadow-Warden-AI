#!/usr/bin/env python3
"""
scripts/check_env_duplicates.py — fail on shadowed keys in an env file.

Docker Compose reads an env file top to bottom and the **last** definition of a
key wins. Every earlier one is silently discarded: no warning, no log line, and
the file still reads as though the first value is the configured one.

Measured on production 2026-08-23, `/opt/shadow-warden/.env` held four
duplicated keys:

    NTFY_URL          x2   same topic, different title/priority
    ONNX_MODEL_PATH   x2   identical, harmless
    SUPER_ADMIN_KEY   x2   two DIFFERENT 64-char credentials
    NVIDIA_API_KEY    x3   three different keys

The last of those is why this script exists. The winning NVIDIA key was 24
characters and answered HTTP 403 — indistinguishable from a bogus credential —
while the real 70-character key sat twelve lines above it, shadowed and
unreachable. NVIDIA/Nemotron had been failing in production for as long as the
duplicate existed, and nothing anywhere reported it, because from the file's
point of view the key was present and looked right.

Values are never printed. Duplicates are reported by key, line number and which
one actually takes effect, so this is safe to run on a host and paste into a
ticket.

Usage:
    python scripts/check_env_duplicates.py                  # ./.env
    python scripts/check_env_duplicates.py /opt/shadow-warden/.env
    python scripts/check_env_duplicates.py --warn-identical  # also flag exact dupes

Exit codes:
    0  no duplicates (or only identical ones, unless --warn-identical)
    1  duplicate keys with differing values — a shadowed setting
    2  the file could not be read
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

#: A key assignment. Leading `export ` is accepted because hand-edited env files
#: pick it up from shell habit, and Compose tolerates it.
_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def parse(path: Path) -> dict[str, list[tuple[int, str]]]:
    """Map each key to every (line_number, value) it is assigned at."""
    seen: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _ASSIGN.match(raw)
        if m:
            seen[m.group(1)].append((n, raw.split("=", 1)[1]))
    return seen


def missing_trailing_newline(path: Path) -> str | None:
    """Return the last key name if the file does not end in a newline.

    An env file whose final line has no newline is a loaded gun. Any append —
    ``echo K=V >> .env``, a provisioning script, an operator in a hurry —
    concatenates onto the last key's *value* instead of starting a line:

        NVIDIA_API_KEY=nvapi-xxxxEXAMPLEWARDEN_TRACE_MIDDLEWARE=true

    (The value above is synthetic. The first draft of this docstring carried the
    real key's last seven characters, copied from the incident, and gitleaks
    caught it on a public repository — a partial credential is still a
    credential. Illustrate with a fake one.)

    That is one line, so it is one key. The credential is silently corrupted and
    the appended key does not exist at all. Nothing warns: the file parses, the
    key is "present", and compose forwards a value that is wrong at the end.

    Hit on production 2026-08-26 doing exactly that. Recovered from a backup
    taken seconds earlier; without one, a live API key would have been destroyed
    with no record of its original value.

    Reported by key name and length only — never the value.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if not raw or raw.endswith(b"\n"):
        return None
    last = raw.splitlines()[-1].decode("utf-8", "replace")
    if not last.strip() or last.lstrip().startswith("#") or "=" not in last:
        return "<final line>"
    return last.split("=", 1)[0].strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("path", nargs="?", default=".env", help="env file (default: .env)")
    ap.add_argument(
        "--warn-identical",
        action="store_true",
        help="also fail on duplicates whose values match (tidiness, not a defect)",
    )
    args = ap.parse_args()

    path = Path(args.path)
    try:
        keys = parse(path)
    except OSError as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return 2

    differing: list[str] = []
    identical: list[str] = []
    for key, hits in sorted(keys.items()):
        if len(hits) < 2:
            continue
        (identical if len({v for _, v in hits}) == 1 else differing).append(key)

    unterminated = missing_trailing_newline(path)

    if not differing and not (identical and args.warn_identical) and not unterminated:
        extra = f" ({len(identical)} identical duplicate(s) ignored)" if identical else ""
        print(f"OK — no shadowed keys in {path}{extra}")
        return 0

    if unterminated:
        print(f"no trailing newline: {path} ends mid-line on {unterminated}")
        print(
            "    The next `>> .env` will concatenate onto that key's value rather "
            "than adding a line, corrupting it silently. Fix with: echo >> "
            f"{path}"
        )
        if not differing and not (identical and args.warn_identical):
            return 1

    for key in differing + (identical if args.warn_identical else []):
        hits = keys[key]
        winner = hits[-1][0]
        kind = "IDENTICAL" if key in identical else "SHADOWED"
        print(f"{kind}: {key} defined {len(hits)}x in {path}")
        for line, value in hits:
            mark = "  <-- this one wins" if line == winner else ""
            # Length only. Never the value: these are credentials.
            print(f"    line {line:>5}  len={len(value)}{mark}")

    if differing:
        print(
            "\nCompose uses the LAST definition; every earlier one is discarded "
            "silently.\nDelete the shadowed lines, or move the value you want to "
            "the end of the file.",
            file=sys.stderr,
        )
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
