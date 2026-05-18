#!/usr/bin/env python3
"""
scripts/warden_github_scan.py  (IN-15)
───────────────────────────────────────
GitHub Actions scan script.

Collects diff text from the current PR/push and sends it to the
Shadow Warden AI /filter endpoint.  Writes a JSON result to --out.

Usage:
  python scripts/warden_github_scan.py \
    --event push --sha abc123 --repo owner/name --pr 42 --out scan_result.json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def get_diff() -> str:
    """Return the unified diff of the current HEAD vs its parent."""
    try:
        result = subprocess.run(
            ["git", "diff", "HEAD~1", "--unified=0", "--no-color"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout[:8_000]   # truncate to 8 KB
    except Exception:
        return ""


def scan(content: str, api_url: str, api_key: str, tenant_id: str = "github-ci") -> dict:
    try:
        import httpx
        resp = httpx.post(
            f"{api_url.rstrip('/')}/filter",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            json={"content": content, "tenant_id": tenant_id, "context": "github_ci"},
            timeout=30.0,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        return {
            "verdict": "ERROR",
            "risk_level": "UNKNOWN",
            "flags": [],
            "error": str(exc),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event",   default="push")
    parser.add_argument("--sha",     default="")
    parser.add_argument("--repo",    default="")
    parser.add_argument("--pr",      default="")
    parser.add_argument("--content", default="")
    parser.add_argument("--out",     default="scan_result.json")
    args = parser.parse_args()

    api_url = os.getenv("WARDEN_API_URL", "https://api.shadow-warden-ai.com")
    api_key = os.getenv("WARDEN_API_KEY", "")

    content = args.content or get_diff()
    if not content.strip():
        content = f"GitHub {args.event} event on {args.repo}@{args.sha}"

    result = scan(content, api_url, api_key)
    result["_meta"] = {
        "event":  args.event,
        "sha":    args.sha,
        "repo":   args.repo,
        "pr":     args.pr,
        "scanned_bytes": len(content),
    }

    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Warden scan: verdict={result.get('verdict')} risk={result.get('risk_level')}")

    if result.get("verdict") == "BLOCK":
        sys.exit(1)


if __name__ == "__main__":
    main()
