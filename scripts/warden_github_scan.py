#!/usr/bin/env python3
"""
scripts/warden_github_scan.py  (IN-15)
───────────────────────────────────────
Shadow Warden AI — GitHub Actions & pre-commit scan driver.

Two modes
─────────
  ci           Default. Scans commit message + changed files (per-file diff
               chunks) against the Shadow Warden /filter API.  Writes a JSON
               result file and optionally a GitHub step-summary markdown table.

  pre-commit   Called by the local git pre-commit hook. Scans staged diff +
               commit message draft. Exits 1 on BLOCK to abort the commit.

Usage
─────
  # GitHub Actions
  python scripts/warden_github_scan.py \\
    --event push \\
    --sha   $SHA \\
    --repo  owner/repo \\
    --pr    $PR_NUMBER \\
    --fail-on BLOCK \\
    --out   scan_result.json \\
    --summary-file "$GITHUB_STEP_SUMMARY"

  # Pre-commit hook
  python scripts/warden_github_scan.py --mode pre-commit

Environment variables
─────────────────────
  WARDEN_API_URL   Base URL of the Shadow Warden gateway (default: https://api.shadow-warden-ai.com)
  WARDEN_API_KEY   X-API-Key header value (required for Pro+ plans)
  WARDEN_TENANT_ID Tenant ID forwarded with every /filter call (default: github-ci)
  WARDEN_FAIL_ON   Override --fail-on from environment (BLOCK or HIGH)
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# ── Skip patterns ─────────────────────────────────────────────────────────────

_SKIP_EXTENSIONS = frozenset({
    ".lock", ".min.js", ".min.css", ".pb", ".pyc", ".pyo",
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".br",
    ".bin", ".exe", ".dll", ".so", ".dylib",
})

_SKIP_NAMES = frozenset({
    "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock",
    "composer.lock", "Gemfile.lock", "go.sum",
})

_SKIP_PATH_PREFIXES = ("dist/", "build/", "vendor/", "node_modules/", ".git/")

MAX_BYTES_PER_FILE = 6_000   # per-file diff cap
MAX_FILES          = 30      # scan at most this many files per run
MAX_COMMIT_MSG     = 2_000

# ── Risk ordering ─────────────────────────────────────────────────────────────

_RISK_ORDER = {"ALLOW": 0, "PASS": 0, "LOW": 1, "MEDIUM": 2,
               "FLAG": 2, "HIGH": 3, "BLOCK": 4}


def risk_num(v: str) -> int:
    return _RISK_ORDER.get(v.upper(), 0)


def aggregate_verdict(verdicts: list[str]) -> str:
    """Return the highest-severity verdict from a list."""
    if not verdicts:
        return "ALLOW"
    return max(verdicts, key=lambda v: risk_num(v))


# ── Git helpers ───────────────────────────────────────────────────────────────

def _git(*args: str, check: bool = False) -> str:
    r = subprocess.run(["git", *args], capture_output=True, text=True, check=check)
    return r.stdout.strip()


def get_commit_message(sha: str = "HEAD") -> str:
    msg = _git("log", "-1", "--format=%B", sha)
    return msg[:MAX_COMMIT_MSG]


def get_changed_files(base: str = "HEAD~1", head: str = "HEAD") -> list[str]:
    out = _git("diff", base, head, "--name-only")
    return [f for f in out.splitlines() if f.strip()]


def get_file_diff(filename: str, base: str = "HEAD~1", head: str = "HEAD") -> str:
    return _git("diff", base, head, "--unified=3", "--no-color", "--", filename)[:MAX_BYTES_PER_FILE]


def get_staged_diff() -> str:
    return _git("diff", "--cached", "--unified=3", "--no-color")[:MAX_BYTES_PER_FILE * 2]


def get_staged_commit_msg() -> str:
    git_dir = _git("rev-parse", "--git-dir") or ".git"
    msg_file = Path(git_dir) / "COMMIT_EDITMSG"
    if msg_file.exists():
        return msg_file.read_text(encoding="utf-8", errors="replace")[:MAX_COMMIT_MSG]
    return ""


def should_skip(filename: str) -> bool:
    p = Path(filename)
    if p.name in _SKIP_NAMES:
        return True
    if p.suffix.lower() in _SKIP_EXTENSIONS:
        return True
    return any(filename.startswith(prefix) for prefix in _SKIP_PATH_PREFIXES)


# ── Warden API ────────────────────────────────────────────────────────────────

def scan_text(
    content: str,
    label:   str,
    api_url: str,
    api_key: str,
    tenant_id: str = "github-ci",
    context: str = "github_ci",
) -> dict:
    if not content.strip():
        return {"label": label, "verdict": "SKIP", "risk_level": "SKIP",
                "flags": [], "secrets_found": [], "processing_ms": 0}
    if not api_key:
        return {"label": label, "verdict": "SKIP", "risk_level": "SKIP",
                "flags": [], "secrets_found": [], "processing_ms": 0,
                "note": "WARDEN_API_KEY not configured — scan skipped"}
    try:
        import httpx
        resp = httpx.post(
            f"{api_url.rstrip('/')}/filter",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            json={
                "content":   content,
                "tenant_id": tenant_id,
                "context":   context,
            },
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        data["label"] = label
        data.setdefault("verdict",     data.get("risk_level", "ALLOW"))
        data.setdefault("flags",       [])
        data.setdefault("secrets_found", [])
        return data
    except Exception as exc:
        return {
            "label":        label,
            "verdict":      "ERROR",
            "risk_level":   "UNKNOWN",
            "flags":        [],
            "secrets_found": [],
            "error":        str(exc),
        }


# ── Output helpers ────────────────────────────────────────────────────────────

_ICON = {"BLOCK": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "FLAG": "🟡",
         "LOW": "🟢", "ALLOW": "🟢", "PASS": "🟢", "SKIP": "⚪", "ERROR": "❌"}


def _icon(v: str) -> str:
    return _ICON.get(v.upper(), "⚪")


def build_step_summary(results: list[dict], agg: str) -> str:
    lines = [
        f"## {_icon(agg)} Shadow Warden AI — {agg}",
        "",
        "| Item | Verdict | Flags | Secrets | Latency |",
        "| ---- | ------- | ----- | ------- | ------- |",
    ]
    for r in results:
        v       = r.get("verdict", "?")
        flags   = ", ".join(r.get("flags", [])[:3]) or "—"
        secrets = ", ".join(r.get("secrets_found", [])[:2]) or "—"
        ms      = f"{r.get('processing_ms', 0):.1f}ms" if r.get("processing_ms") else "—"
        label   = f"`{r['label']}`"
        lines.append(f"| {label} | {_icon(v)} {v} | {flags} | {secrets} | {ms} |")

    high  = sum(1 for r in results if risk_num(r.get("verdict","")) >= risk_num("HIGH"))
    block = sum(1 for r in results if r.get("verdict","").upper() == "BLOCK")
    lines += [
        "",
        f"> **{len(results)} items scanned · {block} BLOCK · {high} HIGH**",
        "",
        "_Powered by [Shadow Warden AI](https://shadow-warden-ai.com)_",
    ]
    return "\n".join(lines)


def build_pr_comment(results: list[dict], agg: str, meta: dict) -> str:
    lines = [
        f"## {_icon(agg)} Shadow Warden AI — {agg}",
        "",
        f"**Commit:** `{meta.get('sha','')[:12]}`  "
        f"**Repo:** `{meta.get('repo','')}`  "
        f"**Event:** `{meta.get('event','')}`",
        "",
        "| Item | Verdict | Flags | Secrets |",
        "| ---- | ------- | ----- | ------- |",
    ]
    for r in results:
        v       = r.get("verdict", "?")
        flags   = ", ".join(f"`{f}`" for f in r.get("flags", [])[:3]) or "—"
        secrets = ", ".join(f"`{s}`" for s in r.get("secrets_found", [])[:2]) or "—"
        lines.append(f"| `{r['label']}` | {_icon(v)} **{v}** | {flags} | {secrets} |")

    block   = sum(1 for r in results if r.get("verdict","").upper() == "BLOCK")
    high    = sum(1 for r in results if risk_num(r.get("verdict","")) >= risk_num("HIGH"))
    total_s = sum(r.get("secrets_found",[]) != [] for r in results)

    lines += [
        "",
        f"> **{len(results)} items** · {block} BLOCK · {high} HIGH · {total_s} with secrets",
        "",
        "<details><summary>Raw JSON</summary>",
        "",
        "```json",
        json.dumps({"aggregate": agg, "results": results}, indent=2)[:4000],
        "```",
        "",
        "</details>",
        "",
        "_[Shadow Warden AI](https://shadow-warden-ai.com) · IN-15_",
    ]
    return "\n".join(lines)


# ── SARIF (GitHub Code Scanning) ──────────────────────────────────────────────

# Map Warden verdicts to SARIF levels. SARIF only has error/warning/note/none;
# BLOCK/HIGH → error, MEDIUM/FLAG → warning, everything else → note.
_SARIF_LEVEL = {"BLOCK": "error", "HIGH": "error", "MEDIUM": "warning",
                "FLAG": "warning", "LOW": "note", "ALLOW": "note",
                "PASS": "note", "SKIP": "none", "ERROR": "warning"}


def _sarif_level(verdict: str) -> str:
    return _SARIF_LEVEL.get(verdict.upper(), "note")


def build_sarif(results: list[dict], meta: dict) -> dict:
    """Render scan results as a SARIF 2.1.0 log for the GitHub Security tab.

    One `result` per scanned item whose verdict is at or above MEDIUM — clean
    items are omitted so the Code Scanning view shows only actionable findings.
    The commit_message item maps to the repo root; file items map to their path.
    """
    sarif_results = []
    rule_ids: dict[str, dict] = {}
    for r in results:
        verdict = r.get("verdict", "ALLOW")
        if risk_num(verdict) < risk_num("MEDIUM"):
            continue
        label = r.get("label", "scan")
        # A file item's label IS its repo path; these two are logical, not files.
        uri = ".github/warden-scan" if label in ("commit_message", "staged_diff") else label
        flags = r.get("flags", [])
        secrets = r.get("secrets_found", [])
        rule_id = f"warden/{verdict.lower()}"
        rule_ids.setdefault(rule_id, {
            "id": rule_id,
            "name": f"Warden{verdict.title()}Finding",
            "shortDescription": {"text": f"Shadow Warden {verdict} verdict"},
            "defaultConfiguration": {"level": _sarif_level(verdict)},
        })
        detail = ", ".join(flags[:5]) or "policy violation"
        if secrets:
            detail += f" · secrets: {', '.join(secrets[:3])}"
        sarif_results.append({
            "ruleId": rule_id,
            "level": _sarif_level(verdict),
            "message": {"text": f"[{verdict}] {label}: {detail}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ShadowWardenAI",
                "informationUri": "https://shadow-warden-ai.com",
                "version": "1.0.0",
                "rules": list(rule_ids.values()),
            }},
            "results": sarif_results,
            "properties": {"commit": meta.get("sha", ""), "repo": meta.get("repo", "")},
        }],
    }


# ── CI mode ───────────────────────────────────────────────────────────────────

def run_ci(args: argparse.Namespace, api_url: str, api_key: str, tenant_id: str) -> int:
    results: list[dict] = []

    # 1. Commit message
    commit_msg = args.content or get_commit_message(args.sha or "HEAD")
    if commit_msg.strip():
        r = scan_text(commit_msg, "commit_message", api_url, api_key, tenant_id, "github_commit_message")
        results.append(r)
        print(f"  commit_message -> {r.get('verdict','?')}")

    # 2. Changed files (skip generated/binary)
    try:
        files = get_changed_files()
    except Exception:
        files = []

    scannable = [f for f in files if not should_skip(f)][:MAX_FILES]
    skipped   = len(files) - len(scannable)
    if skipped > 0:
        print(f"  skipped {skipped} generated/binary files")

    for filename in scannable:
        diff = get_file_diff(filename)
        if not diff.strip():
            continue
        r = scan_text(diff, filename, api_url, api_key, tenant_id, "github_diff")
        results.append(r)
        print(f"  {filename} -> {r.get('verdict','?')}")

    # Aggregate
    agg = aggregate_verdict([r.get("verdict","ALLOW") for r in results])
    print(f"\nAggregate verdict: {agg}")

    # Write result file
    meta = {"event": args.event, "sha": args.sha, "repo": args.repo, "pr": args.pr}
    output = {
        "aggregate_verdict": agg,
        "aggregate_risk":    agg,
        "results":           results,
        "files_scanned":     len(scannable),
        "files_skipped":     skipped,
        "_meta":             meta,
    }
    Path(args.out).write_text(json.dumps(output, indent=2), encoding="utf-8")

    # GitHub step summary
    if args.summary_file:
        summary = build_step_summary(results, agg)
        try:
            with open(args.summary_file, "a", encoding="utf-8") as f:
                f.write(summary + "\n")
        except Exception as e:
            print(f"Warning: could not write step summary: {e}", file=sys.stderr)

    # PR comment body file (for github-script action to read)
    if args.pr and args.pr != "":
        comment = build_pr_comment(results, agg, meta)
        Path("warden_pr_comment.md").write_text(comment, encoding="utf-8")

    # SARIF for the GitHub Code Scanning tab (always emit, even if empty —
    # upload-sarif needs a valid file to clear stale alerts on a clean run)
    if args.sarif:
        sarif = build_sarif(results, meta)
        Path(args.sarif).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        print(f"  wrote SARIF ({len(sarif['runs'][0]['results'])} findings) -> {args.sarif}")

    fail_on = (args.fail_on or os.getenv("WARDEN_FAIL_ON", "BLOCK")).upper()
    if risk_num(agg) >= risk_num(fail_on):
        print(f"\n✖ Warden scan FAILED (verdict={agg} ≥ fail_on={fail_on})", file=sys.stderr)
        return 1

    print(f"\nOK Warden scan PASSED (verdict={agg})")
    return 0


# ── Pre-commit mode ───────────────────────────────────────────────────────────

def run_pre_commit(args: argparse.Namespace, api_url: str, api_key: str, tenant_id: str) -> int:
    results: list[dict] = []

    commit_msg = get_staged_commit_msg()
    if commit_msg.strip():
        r = scan_text(commit_msg, "commit_message", api_url, api_key, tenant_id, "git_pre_commit_message")
        results.append(r)

    staged_diff = get_staged_diff()
    if staged_diff.strip():
        r = scan_text(staged_diff, "staged_diff", api_url, api_key, tenant_id, "git_pre_commit_diff")
        results.append(r)

    if not results:
        return 0

    agg = aggregate_verdict([r.get("verdict","ALLOW") for r in results])
    fail_on = (args.fail_on or os.getenv("WARDEN_FAIL_ON", "BLOCK")).upper()

    for r in results:
        v      = r.get("verdict", "ALLOW")
        flags  = r.get("flags", [])
        icon   = "🚫" if v == "BLOCK" else "⛔" if v == "HIGH" else "⚠" if v == "MEDIUM" else "✅"
        detail = f" — {', '.join(flags[:3])}" if flags else ""
        print(f"{icon} Shadow Warden [{r['label']}]: {v}{detail}")

    if risk_num(agg) >= risk_num(fail_on):
        print(f"\n✖ Commit blocked by Shadow Warden (verdict={agg}, threshold={fail_on})")
        print("  Review the flagged content above and retry, or set WARDEN_FAIL_ON=HIGH to allow MEDIUM findings.")
        return 1

    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Shadow Warden AI GitHub/git scanner")
    parser.add_argument("--mode",         default="ci",   choices=["ci", "pre-commit"])
    parser.add_argument("--event",        default="push")
    parser.add_argument("--sha",          default="")
    parser.add_argument("--repo",         default="")
    parser.add_argument("--pr",           default="")
    parser.add_argument("--content",      default="",  help="Override text to scan")
    parser.add_argument("--fail-on",      default="",  help="BLOCK or HIGH (default: BLOCK)")
    parser.add_argument("--out",          default="scan_result.json")
    parser.add_argument("--sarif",        default="",  help="Path to write SARIF 2.1.0 for Code Scanning")
    parser.add_argument("--summary-file", default="",  help="Path to append GitHub step summary")
    args = parser.parse_args()

    api_url   = os.getenv("WARDEN_API_URL",    "https://api.shadow-warden-ai.com")
    api_key   = os.getenv("WARDEN_API_KEY",    "")
    tenant_id = os.getenv("WARDEN_TENANT_ID",  "github-ci")

    if not api_key:
        print("Warning: WARDEN_API_KEY not set — all items will be SKIP (no API call made)", file=sys.stderr)

    rc = run_pre_commit(args, api_url, api_key, tenant_id) \
        if args.mode == "pre-commit" \
        else run_ci(args, api_url, api_key, tenant_id)

    sys.exit(rc)


if __name__ == "__main__":
    main()
