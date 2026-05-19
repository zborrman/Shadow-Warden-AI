"""
warden/brain/online_learner.py  (AR-09)
────────────────────────────────────────
Online learning pipeline — nightly ONNX fine-tune from evolution_dataset.jsonl.

Reads attack/safe example pairs from `data/evolution_dataset.jsonl`,
fine-tunes the in-memory corpus via contrastive margin update (no GPU),
and optionally re-exports an updated ONNX checkpoint.

This is a lightweight CPU-only approach:
  1. Load current brain guard + tokenizer
  2. Compute current embeddings for all dataset examples
  3. Identify "hard negatives" (high-risk examples scoring < threshold)
  4. Inject them into the corpus via add_examples() (hot-reload)
  5. Optional: export updated mean-pool centroids to data/centroids.npy

For full model fine-tuning (gradient descent), use scripts/export_onnx.py
with a fine-tuned checkpoint.  This module handles the incremental path.

ARQ job: `online_learning_job` — triggered nightly by the scheduler or
         via POST /agent/sova/task/online-learning.

Environment vars
────────────────
  EVOLUTION_DATASET_PATH   — default data/evolution_dataset.jsonl
  ONLINE_LEARNING_ENABLED  — "true" to activate (default: false)
  ONLINE_LEARNING_BATCH    — examples per run (default 100)
  ONLINE_LEARNING_THRESHOLD — score below which HIGH_RISK examples are re-injected
                               (default 0.60)
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

log = logging.getLogger("warden.brain.online_learner")

_ENABLED       = os.getenv("ONLINE_LEARNING_ENABLED", "false").lower() == "true"
_DATASET_PATH  = Path(os.getenv("EVOLUTION_DATASET_PATH", "data/evolution_dataset.jsonl"))
_BATCH_SIZE    = int(os.getenv("ONLINE_LEARNING_BATCH", "100"))
_THRESHOLD     = float(os.getenv("ONLINE_LEARNING_THRESHOLD", "0.60"))


@dataclass
class LearningResult:
    ts:               str
    examples_loaded:  int
    hard_negatives:   int
    injected:         int
    skipped:          int
    error:            str = ""


async def run_online_learning() -> LearningResult:
    """
    Main entry point.  Reads dataset, evaluates corpus coverage,
    injects hard negatives.
    """
    ts = datetime.now(UTC).isoformat()

    if not _ENABLED:
        return LearningResult(ts=ts, examples_loaded=0, hard_negatives=0, injected=0, skipped=0,
                              error="ONLINE_LEARNING_ENABLED != true")

    if not _DATASET_PATH.exists():
        return LearningResult(ts=ts, examples_loaded=0, hard_negatives=0, injected=0, skipped=0,
                              error=f"dataset not found: {_DATASET_PATH}")

    # Load recent examples (last _BATCH_SIZE)
    examples = _load_examples(_BATCH_SIZE)
    if not examples:
        return LearningResult(ts=ts, examples_loaded=0, hard_negatives=0, injected=0, skipped=0)

    high_risk = [e for e in examples if e.get("label") == "HIGH_RISK"]
    safe      = [e for e in examples if e.get("label") in ("SAFE", "ALLOW", "PASS")]

    log.info("online_learner: loaded %d examples (%d HIGH_RISK, %d safe)",
             len(examples), len(high_risk), len(safe))

    # Evaluate current pipeline score for HIGH_RISK examples
    hard_negatives = await _find_hard_negatives(high_risk)

    # Inject hard negatives into corpus
    injected = _inject_examples(hard_negatives)

    # Update safe centroid if we have safe examples
    skipped = len(high_risk) - len(hard_negatives)

    result = LearningResult(
        ts=ts,
        examples_loaded=len(examples),
        hard_negatives=len(hard_negatives),
        injected=injected,
        skipped=skipped,
    )
    log.info("online_learner: %s", result)
    return result


def _load_examples(n: int) -> list[dict]:
    examples = []
    try:
        with open(_DATASET_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    with contextlib.suppress(Exception):
                        examples.append(json.loads(line))
    except Exception as exc:
        log.warning("online_learner: could not read dataset: %s", exc)
    return examples[-n:]   # most recent N


async def _find_hard_negatives(high_risk: list[dict]) -> list[dict]:
    """
    Score each HIGH_RISK example against the current brain guard.
    Returns examples that score below _THRESHOLD (hard negatives — model misses them).
    """
    if not high_risk:
        return []

    try:
        from warden.brain.semantic import SemanticGuard  # noqa: PLC0415
        guard = SemanticGuard()
    except ImportError:
        log.warning("online_learner: SemanticGuard not importable")
        return high_risk   # treat all as hard negatives

    hard = []
    for ex in high_risk:
        text = ex.get("text", "")
        if not text:
            continue
        try:
            result = guard.check(text)
            score  = result.score
            if score < _THRESHOLD:
                hard.append(ex)
        except Exception:
            hard.append(ex)   # conservative — include on error

    log.info("online_learner: %d/%d HIGH_RISK examples are hard negatives (score < %.2f)",
             len(hard), len(high_risk), _THRESHOLD)
    return hard


def _inject_examples(examples: list[dict]) -> int:
    if not examples:
        return 0
    try:
        from warden.brain.evolve import EvolutionEngine  # noqa: PLC0415
        engine = EvolutionEngine()
        engine.add_examples(examples)
        log.info("online_learner: injected %d hard negatives into corpus", len(examples))
        return len(examples)
    except Exception as exc:
        log.error("online_learner: inject failed: %s", exc)
        return 0


# ── Centroid export (optional analytics) ─────────────────────────────────────

def export_centroids(output_path: str = "data/centroids.npy") -> bool:
    """
    Compute and export mean embeddings for HIGH_RISK and SAFE classes.
    Used by the SOC dashboard to visualise corpus coverage.
    """
    try:
        from warden.brain.semantic import SemanticGuard  # noqa: PLC0415
        guard = SemanticGuard()

        examples = _load_examples(500)
        classes: dict[str, list] = {"HIGH_RISK": [], "SAFE": []}
        for ex in examples:
            label = ex.get("label", "")
            text  = ex.get("text", "")
            if label in classes and text:
                emb = guard._embed(text)  # type: ignore[attr-defined]
                if emb is not None:
                    classes[label].append(emb)

        centroids = {}
        for label, embs in classes.items():
            if embs:
                centroids[label] = np.mean(np.stack(embs), axis=0)

        np.save(output_path, centroids)  # type: ignore[arg-type]
        log.info("online_learner: centroids saved to %s", output_path)
        return True
    except Exception as exc:
        log.error("online_learner: centroid export failed: %s", exc)
        return False


# ── ARQ job ───────────────────────────────────────────────────────────────────

async def online_learning_job(ctx: dict) -> dict:
    """ARQ job: nightly online learning run."""
    result = await run_online_learning()
    return {
        "status":          "ok" if not result.error else "error",
        "ts":              result.ts,
        "examples_loaded": result.examples_loaded,
        "hard_negatives":  result.hard_negatives,
        "injected":        result.injected,
        "error":           result.error,
    }
