#!/usr/bin/env python3
"""
warden/tests/adversarial/run_adversarial.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Standalone adversarial test runner.

Fails (exit code > 0) if:
  • any known jailbreak passes through as SAFE
  • any benign prompt is blocked as UNSAFE

Run from project root::

    cd warden
    python tests/adversarial/run_adversarial.py

Or via pytest marker::

    pytest -m adversarial warden/tests/
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path so `warden` is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import os
os.environ.setdefault("ANTHROPIC_API_KEY", "")  # disable evolution in test
os.environ.setdefault("SEMANTIC_THRESHOLD", "0.72")

from warden.semantic_guard import SemanticGuard  # noqa: E402

guard = SemanticGuard()

_HERE = Path(__file__).parent
jailbreaks = [
    l.strip() for l in (_HERE / "jailbreaks.txt").read_text().splitlines()
    if l.strip() and not l.startswith("#")
]
benign = [
    l.strip() for l in (_HERE / "benign.txt").read_text().splitlines()
    if l.strip() and not l.startswith("#")
]

failed = 0
total = len(jailbreaks) + len(benign)

print(f"\n{'─'*60}")
print(f"  Shadow Warden Adversarial Test Suite")
print(f"  {len(jailbreaks)} jailbreaks · {len(benign)} benign prompts")
print(f"{'─'*60}\n")

# ── Jailbreak tests: must be BLOCKED ──────────────────────────────────────────
miss_count = 0
for prompt in jailbreaks:
    result = guard.analyse(prompt)
    if result.safe_for(strict=False):
        print(f"  [MISS]  {prompt[:80]!r}")
        miss_count += 1
        failed += 1

if miss_count == 0:
    print(f"  ✓ All {len(jailbreaks)} jailbreaks blocked")
else:
    print(f"  ✗ {miss_count}/{len(jailbreaks)} jailbreaks MISSED")

# ── Benign tests: must be ALLOWED ─────────────────────────────────────────────
fp_count = 0
for prompt in benign:
    result = guard.analyse(prompt)
    if not result.safe_for(strict=False):
        print(f"  [FP]    {prompt[:80]!r}")
        fp_count += 1
        failed += 1

if fp_count == 0:
    print(f"  ✓ All {len(benign)} benign prompts allowed")
else:
    print(f"  ✗ {fp_count}/{len(benign)} false positives")

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{'─'*60}")
miss_rate = miss_count / len(jailbreaks) * 100 if jailbreaks else 0
fp_rate   = fp_count  / len(benign)     * 100 if benign     else 0
print(f"  Miss rate (jailbreaks): {miss_rate:.1f}%")
print(f"  False positive rate:    {fp_rate:.1f}%")
print(f"\n  {'PASS ✓' if not failed else 'FAIL ✗'} — {failed}/{total} issues found")
print(f"{'─'*60}\n")

sys.exit(failed)
