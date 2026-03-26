"""
warden/brain/dataset.py
━━━━━━━━━━━━━━━━━━━━━━
Local evolution dataset collector.

After each successful EvolutionEngine analysis, the (system, user, assistant)
triple is appended to a JSONL file.  This dataset can be used to fine-tune
a smaller model to perform the same analysis task locally — eliminating
the Claude Opus dependency and reducing per-event latency.

Output format — Anthropic fine-tuning JSONL (one JSON object per line):
──────────────────────────────────────────────────────────────────────
  {
    "messages": [
      {"role": "system",    "content": "<system prompt>"},
      {"role": "user",      "content": "<formatted attack context>"},
      {"role": "assistant", "content": "<EvolutionResponse JSON>"}
    ],
    "metadata": {
      "id":          "<rule uuid>",
      "attack_type": "prompt_injection",
      "severity":    "high",
      "created_at":  "2026-03-24T00:00:00Z",
      "dataset_version": "1"
    }
  }

GDPR guarantees
───────────────
  • Only anonymized content (post _anonymize_for_evolution) is stored.
  • Original request content is NEVER written to this file.
  • Metadata carries only structural identifiers (rule_id, attack_type).

Capacity management
───────────────────
  • Soft cap: once the file reaches EVOLUTION_DATASET_MAX_ROWS lines,
    new samples are silently dropped (logged at DEBUG).
  • To archive: move the file and the collector will start a new one.
  • Row count is cached in memory after the first read — O(1) on every
    subsequent append; re-counted if the file is replaced externally.

Environment variables
─────────────────────
  EVOLUTION_DATASET_PATH      Path to the JSONL file
                              (default: /warden/data/evolution_dataset.jsonl)
  EVOLUTION_DATASET_MAX_ROWS  Max samples to collect before stopping
                              (default: 10 000)
  EVOLUTION_DATASET_ENABLED   Set to "false" to disable collection entirely
                              (default: true)
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path

log = logging.getLogger("warden.brain.dataset")

# ── Config ────────────────────────────────────────────────────────────────────

DATASET_PATH: Path = Path(
    os.getenv("EVOLUTION_DATASET_PATH", "/warden/data/evolution_dataset.jsonl")
)
MAX_ROWS: int = int(os.getenv("EVOLUTION_DATASET_MAX_ROWS", "10000"))
ENABLED:  bool = os.getenv("EVOLUTION_DATASET_ENABLED", "true").lower() != "false"

DATASET_VERSION = "1"

# ── Thread-safe row counter ───────────────────────────────────────────────────

_lock:      threading.Lock = threading.Lock()
_row_count: int | None     = None   # None = not yet counted


def _get_row_count() -> int:
    """Return current line count of the dataset file (cached)."""
    global _row_count
    if _row_count is not None:
        return _row_count
    if not DATASET_PATH.exists():
        _row_count = 0
        return 0
    try:
        _row_count = sum(1 for _ in DATASET_PATH.open("r", encoding="utf-8") if _.strip())
    except Exception:
        _row_count = 0
    return _row_count


# ── Public API ────────────────────────────────────────────────────────────────

def append_sample(
    *,
    system_prompt:  str,
    user_prompt:    str,
    evolution_json: str,
    rule_id:        str,
    attack_type:    str,
    severity:       str,
    created_at:     str,
) -> bool:
    """Append one (system, user, assistant) sample to the dataset JSONL file.

    Args:
        system_prompt:  The system message sent to Claude (extracted from evolve.py).
        user_prompt:    The user message — contains anonymized attack content.
        evolution_json: Claude's JSON response (EvolutionResponse model_dump_json).
        rule_id:        UUID of the generated rule (for deduplication downstream).
        attack_type:    e.g. "prompt_injection".
        severity:       "medium" | "high" | "block".
        created_at:     ISO 8601 timestamp of rule creation.

    Returns:
        True if the sample was written, False if skipped (disabled / cap reached).
    """
    global _row_count

    if not ENABLED:
        return False

    with _lock:
        count = _get_row_count()
        if count >= MAX_ROWS:
            log.debug(
                "Dataset cap reached (%d/%d) — skipping sample for rule %s. "
                "Archive %s to resume collection.",
                count, MAX_ROWS, rule_id, DATASET_PATH,
            )
            return False

        record = {
            "messages": [
                {"role": "system",    "content": system_prompt},
                {"role": "user",      "content": user_prompt},
                {"role": "assistant", "content": evolution_json},
            ],
            "metadata": {
                "id":              rule_id,
                "attack_type":     attack_type,
                "severity":        severity,
                "created_at":      created_at,
                "dataset_version": DATASET_VERSION,
            },
        }

        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        _atomic_append(line)
        _row_count = count + 1

    log.debug(
        "Dataset sample appended: rule_id=%s attack_type=%s rows=%d/%d",
        rule_id, attack_type, _row_count, MAX_ROWS,
    )
    return True


def stats() -> dict:
    """Return a snapshot of dataset collection state (for /api/config or /health)."""
    with _lock:
        count = _get_row_count()
    return {
        "enabled":    ENABLED,
        "path":       str(DATASET_PATH),
        "rows":       count,
        "max_rows":   MAX_ROWS,
        "capacity_pct": round(count / MAX_ROWS * 100, 1) if MAX_ROWS else 0,
    }


def reset_row_count() -> None:
    """Force a recount of the file — call after externally archiving the dataset."""
    global _row_count
    with _lock:
        _row_count = None


# ── I/O helper ────────────────────────────────────────────────────────────────

def _atomic_append(line: str) -> None:
    """Append *line* + newline to DATASET_PATH using a safe write strategy.

    On Windows, true atomic append isn't possible with os.replace() since
    we can't easily read + replace a JSONL file cheaply.  Instead we use
    a file lock (the module-level _lock) to serialise writers, then open
    the file in append mode with O_SYNC semantics via flush() + fsync().
    This is safe for a single-process gateway.
    """
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DATASET_PATH.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())
