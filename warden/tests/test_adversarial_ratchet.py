"""
warden/tests/test_adversarial_ratchet.py — Stage 3b adversarial ratchet.

Runs the adversarial corpus through the FULL /filter pipeline (all 9 stages,
not SemanticGuard alone) via the FastAPI TestClient and enforces a committed
baseline: the number of missed jailbreaks and false positives may only DROP,
never rise. This makes adversarial coverage a blocking gate that can only
improve — without demanding an unrealistic zero-miss single run.

Baseline lives in warden/tests/adversarial/baseline.json. To tighten it after
a genuine detection improvement:

    UPDATE_ADV_BASELINE=1 pytest warden/tests/test_adversarial_ratchet.py

The regeneration writes the *current* (lower) numbers back — it can only be
committed if the numbers improved, since a worse run fails before it can write.

Marked `adversarial` so the existing fast unit gate still excludes it; a
dedicated CI step runs it blocking.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

_HERE = Path(__file__).parent / "adversarial"
_BASELINE = _HERE / "baseline.json"


def _load(name: str) -> list[str]:
    return [
        ln.strip()
        for ln in (_HERE / name).read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]


@pytest.mark.adversarial
@pytest.mark.slow
def test_adversarial_ratchet():
    from fastapi.testclient import TestClient

    from warden.main import app

    jailbreaks = _load("jailbreaks.txt")
    benign = _load("benign.txt")

    def verdict_blocked(client: TestClient, text: str) -> bool:
        r = client.post("/filter", json={"content": text})
        if r.status_code != 200:
            return False
        body = r.json()
        # A jailbreak is "caught" if blocked, or scored HIGH/BLOCK risk.
        if body.get("blocked"):
            return True
        risk = str(body.get("risk_level", body.get("risk", ""))).upper()
        return risk in ("HIGH", "BLOCK", "CRITICAL")

    # Enter the client context so the FastAPI lifespan runs — that publishes the
    # FilterPipeline orchestrator to the runtime container. Without it every
    # /filter call raises PipelineUnavailableError.
    with TestClient(app) as client:
        missed = [t for t in jailbreaks if not verdict_blocked(client, t)]
        false_pos = [t for t in benign if verdict_blocked(client, t)]

    current = {"missed": len(missed), "false_positives": len(false_pos),
               "jailbreaks": len(jailbreaks), "benign": len(benign)}

    if os.getenv("UPDATE_ADV_BASELINE") == "1" or not _BASELINE.exists():
        _BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        if os.getenv("UPDATE_ADV_BASELINE") == "1":
            pytest.skip(f"baseline regenerated: {current}")

    base = json.loads(_BASELINE.read_text(encoding="utf-8"))

    assert current["missed"] <= base["missed"], (
        f"Jailbreak miss count regressed: {current['missed']} > baseline "
        f"{base['missed']}. Newly-missed:\n  " + "\n  ".join(missed[:20]) +
        "\nA detection layer weakened. If intentional, regenerate: "
        "UPDATE_ADV_BASELINE=1 pytest warden/tests/test_adversarial_ratchet.py"
    )
    assert current["false_positives"] <= base["false_positives"], (
        f"False-positive count regressed: {current['false_positives']} > "
        f"baseline {base['false_positives']}. Newly-blocked benign:\n  "
        + "\n  ".join(false_pos[:20])
    )
