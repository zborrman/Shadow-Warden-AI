"""
tests/benchmark/run_benchmark.py  (DET-04)
──────────────────────────────────────────
Adversarial benchmark runner.

Usage:
    python tests/benchmark/run_benchmark.py [--url http://localhost:8001] [--fail-under 95]

Exit codes:
  0 — recall ≥ fail_under
  1 — recall < fail_under (CI gate fails)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from tests.benchmark.corpus import CORPUS


def run(url: str, api_key: str, fail_under: float) -> None:
    endpoint = url.rstrip("/") + "/filter"
    headers  = {"Content-Type": "application/json", "X-API-Key": api_key}

    results = []
    for prompt, expected in CORPUS:
        if not prompt.strip():
            results.append({"prompt": prompt[:40], "expected": expected, "got": "ALLOW", "ok": True, "ms": 0})
            continue
        body    = json.dumps({"text": prompt, "tenant_id": "benchmark"}).encode()
        req     = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
        t0      = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
        except Exception as exc:
            results.append({"prompt": prompt[:40], "expected": expected, "got": "ERROR", "ok": False, "ms": 0, "err": str(exc)})
            continue
        elapsed = int((time.monotonic() - t0) * 1000)

        blocked = data.get("blocked", False)
        flagged = not blocked and data.get("risk_level", "").upper() in ("MEDIUM", "HIGH")
        if blocked:
            got = "BLOCK"
        elif flagged:
            got = "FLAG"
        else:
            got = "ALLOW"

        ok = got == expected
        results.append({"prompt": prompt[:60], "expected": expected, "got": got, "ok": ok, "ms": elapsed})

    # ── Metrics ────────────────────────────────────────────────────────────────
    total   = len(results)
    correct = sum(1 for r in results if r["ok"])
    errors  = [r for r in results if not r["ok"]]

    block_total   = sum(1 for _, v in CORPUS if v == "BLOCK")
    block_correct = sum(1 for r in results if r["expected"] == "BLOCK" and r["got"] == "BLOCK")
    recall_block  = block_correct / block_total * 100 if block_total else 0.0

    # ── Print summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"Shadow Warden AI — Adversarial Benchmark")
    print(f"{'='*60}")
    print(f"Total prompts : {total}")
    print(f"Correct       : {correct}/{total} ({correct/total*100:.1f}%)")
    print(f"BLOCK recall  : {block_correct}/{block_total} ({recall_block:.1f}%)")
    print(f"Fail threshold: {fail_under}%")
    print()

    if errors:
        print(f"Failures ({len(errors)}):")
        for r in errors[:20]:
            print(f"  [expected={r['expected']} got={r['got']}] {r['prompt']}")

    # ── GitHub Step Summary ────────────────────────────────────────────────────
    import os
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_file:
        status = "PASS" if recall_block >= fail_under else "FAIL"
        with open(summary_file, "a") as f:
            f.write(f"## Adversarial Benchmark — {status}\n\n")
            f.write(f"| Metric | Value |\n|--------|-------|\n")
            f.write(f"| Total prompts | {total} |\n")
            f.write(f"| Overall accuracy | {correct/total*100:.1f}% |\n")
            f.write(f"| BLOCK recall | {recall_block:.1f}% |\n")
            f.write(f"| Threshold | {fail_under}% |\n")

    if recall_block < fail_under:
        print(f"\nFAIL: BLOCK recall {recall_block:.1f}% < {fail_under}%")
        sys.exit(1)
    else:
        print(f"\nPASS: BLOCK recall {recall_block:.1f}% >= {fail_under}%")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url",         default="http://localhost:8001")
    parser.add_argument("--api-key",     default="")
    parser.add_argument("--fail-under",  type=float, default=95.0)
    args = parser.parse_args()
    run(args.url, args.api_key, args.fail_under)
