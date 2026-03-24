#!/usr/bin/env python3
"""
scripts/finetune_evolution.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Fine-tuning pipeline for the Shadow Warden Evolution Engine.

Takes the JSONL dataset collected by warden/brain/dataset.py and submits
a fine-tuning job to the Anthropic API.  The resulting model can replace
claude-opus-4-6 in evolve.py — same task, lower latency, lower cost.

Pipeline stages
───────────────
  1. Validate   — parse every JSONL line; report malformed rows
  2. Inspect    — print stats (rows, attack type distribution, severity mix)
  3. Split      — train / validation split (default 90/10)
  4. Upload     — POST both splits to the Anthropic Files API
  5. Submit     — create a fine-tuning job
  6. Poll       — wait for completion, printing status every 30 s
  7. Report     — print the fine-tuned model ID + suggested .env update

Usage
─────
  # Dry run — validate + inspect only, no API calls:
  python scripts/finetune_evolution.py --dry-run

  # Full pipeline with defaults:
  ANTHROPIC_API_KEY=sk-ant-... python scripts/finetune_evolution.py

  # Custom dataset path, more epochs:
  python scripts/finetune_evolution.py \\
      --dataset data/evolution_dataset.jsonl \\
      --epochs 4 \\
      --val-split 0.15

  # Skip polling (fire and forget):
  python scripts/finetune_evolution.py --no-poll

Prerequisites
─────────────
  pip install anthropic>=0.40 rich

Environment variables
─────────────────────
  ANTHROPIC_API_KEY          Required (unless --dry-run)
  EVOLUTION_DATASET_PATH     Overrides --dataset default
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

# ── Optional rich for prettier output ─────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    console = Console()
    def _print(msg: str, style: str = "") -> None:
        console.print(msg, style=style or "default")
    def _rule(title: str) -> None:
        console.rule(f"[bold]{title}")
except ImportError:
    def _print(msg: str, style: str = "") -> None:  # type: ignore[misc]
        print(msg)
    def _rule(title: str) -> None:  # type: ignore[misc]
        print(f"\n{'─' * 60}")
        print(f"  {title}")
        print('─' * 60)

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_DATASET = os.getenv(
    "EVOLUTION_DATASET_PATH",
    "data/evolution_dataset.jsonl",
)
DEFAULT_BASE_MODEL = "claude-haiku-4-5-20251001"   # fast + cheap; same family
MIN_TRAIN_ROWS     = 10    # Anthropic fine-tuning minimum
POLL_INTERVAL_S    = 30


# ── Stage 1 — Validate ────────────────────────────────────────────────────────

def validate(path: Path) -> list[dict]:
    """Parse every line; return valid records.  Print a summary of errors."""
    _rule("Stage 1 — Validate")
    if not path.exists():
        _print(f"[red]Dataset not found: {path}")
        _print("Run the warden gateway under load to collect samples first.")
        sys.exit(1)

    records: list[dict] = []
    errors:  list[tuple[int, str]] = []

    with path.open("r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError as exc:
                errors.append((lineno, f"JSON parse error: {exc}"))
                continue

            msgs = rec.get("messages", [])
            if len(msgs) != 3:
                errors.append((lineno, f"Expected 3 messages, got {len(msgs)}"))
                continue
            roles = [m.get("role") for m in msgs]
            if roles != ["system", "user", "assistant"]:
                errors.append((lineno, f"Bad roles: {roles}"))
                continue

            # Verify assistant content is valid JSON (EvolutionResponse)
            try:
                json.loads(msgs[2]["content"])
            except (json.JSONDecodeError, KeyError) as exc:
                errors.append((lineno, f"Assistant content not valid JSON: {exc}"))
                continue

            records.append(rec)

    _print(f"  Valid rows  : [green]{len(records)}")
    if errors:
        _print(f"  Errors      : [red]{len(errors)}")
        for lineno, msg in errors[:10]:
            _print(f"    line {lineno}: {msg}", style="red")
        if len(errors) > 10:
            _print(f"    ... and {len(errors) - 10} more", style="red")
    else:
        _print("  Errors      : [green]none")

    if len(records) < MIN_TRAIN_ROWS:
        _print(
            f"\n[red]Insufficient data: {len(records)} valid rows "
            f"(minimum {MIN_TRAIN_ROWS} for fine-tuning).",
        )
        _print("Collect more samples or lower MIN_TRAIN_ROWS in this script.")
        sys.exit(1)

    return records


# ── Stage 2 — Inspect ─────────────────────────────────────────────────────────

def inspect_dataset(records: list[dict]) -> None:
    _rule("Stage 2 — Inspect")

    attack_counts: Counter = Counter()
    severity_counts: Counter = Counter()
    versions: Counter = Counter()

    for rec in records:
        meta = rec.get("metadata", {})
        attack_counts[meta.get("attack_type", "unknown")] += 1
        severity_counts[meta.get("severity", "unknown")] += 1
        versions[meta.get("dataset_version", "?")] += 1

    _print(f"  Total samples       : {len(records)}")
    _print(f"  Dataset version(s)  : {dict(versions)}")

    try:
        table = Table(title="Attack Type Distribution", show_header=True)
        table.add_column("Attack Type", style="cyan")
        table.add_column("Count", justify="right")
        table.add_column("Pct", justify="right")
        for atype, count in attack_counts.most_common():
            pct = f"{count / len(records) * 100:.1f}%"
            table.add_row(atype, str(count), pct)
        console.print(table)
    except NameError:
        _print("\n  Attack types:")
        for atype, count in attack_counts.most_common():
            _print(f"    {atype:30s} {count:4d} ({count / len(records) * 100:.1f}%)")

    _print(f"\n  Severity mix: {dict(severity_counts)}")


# ── Stage 3 — Split ───────────────────────────────────────────────────────────

def split(records: list[dict], val_frac: float) -> tuple[list[dict], list[dict]]:
    _rule("Stage 3 — Split")
    shuffled = records.copy()
    random.shuffle(shuffled)
    n_val   = max(1, int(len(shuffled) * val_frac))
    n_train = len(shuffled) - n_val
    train, val = shuffled[n_val:], shuffled[:n_val]
    _print(f"  Train : {n_train} rows")
    _print(f"  Val   : {n_val} rows  ({val_frac * 100:.0f}%)")
    return train, val


def _write_jsonl(records: list[dict], path: Path) -> None:
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False, separators=(",", ":"))
                  for r in records) + "\n",
        encoding="utf-8",
    )


# ── Stage 4 — Upload ──────────────────────────────────────────────────────────

def upload_files(
    client,
    train: list[dict],
    val: list[dict],
    tmp_dir: str,
) -> tuple[str, str]:
    _rule("Stage 4 — Upload")
    train_path = Path(tmp_dir) / "train.jsonl"
    val_path   = Path(tmp_dir) / "val.jsonl"
    _write_jsonl(train, train_path)
    _write_jsonl(val,   val_path)

    _print("  Uploading train split…")
    with train_path.open("rb") as f:
        train_file = client.beta.files.upload(
            file=("train.jsonl", f, "application/jsonl"),
        )
    _print(f"  [green]Train file ID: {train_file.id}")

    _print("  Uploading validation split…")
    with val_path.open("rb") as f:
        val_file = client.beta.files.upload(
            file=("val.jsonl", f, "application/jsonl"),
        )
    _print(f"  [green]Val file ID:   {val_file.id}")

    return train_file.id, val_file.id


# ── Stage 5 — Submit ──────────────────────────────────────────────────────────

def submit_job(
    client,
    train_file_id: str,
    val_file_id: str,
    base_model: str,
    n_epochs: int,
) -> str:
    _rule("Stage 5 — Submit")
    job = client.fine_tuning.jobs.create(
        model          = base_model,
        training_file  = train_file_id,
        validation_file= val_file_id,
        hyperparameters= {"n_epochs": n_epochs},
    )
    _print(f"  Job ID     : [cyan]{job.id}")
    _print(f"  Status     : {job.status}")
    _print(f"  Base model : {base_model}")
    _print(f"  Epochs     : {n_epochs}")
    return job.id


# ── Stage 6 — Poll ────────────────────────────────────────────────────────────

def poll_job(client, job_id: str) -> str:
    _rule("Stage 6 — Poll")
    _print(f"  Polling every {POLL_INTERVAL_S}s … (Ctrl-C to stop, job continues)")
    terminal = {"succeeded", "failed", "cancelled"}
    while True:
        job = client.fine_tuning.jobs.retrieve(job_id)
        _print(f"  [{time.strftime('%H:%M:%S')}] status={job.status}")
        if job.status in terminal:
            if job.status == "succeeded":
                return job.fine_tuned_model
            _print(f"[red]Job ended with status={job.status}")
            _print(f"Check dashboard: https://console.anthropic.com/fine-tuning/{job_id}")
            sys.exit(1)
        time.sleep(POLL_INTERVAL_S)


# ── Stage 7 — Report ──────────────────────────────────────────────────────────

def report(model_id: str) -> None:
    _rule("Stage 7 — Report")
    _print(f"\n  [bold green]Fine-tuned model ID: {model_id}\n")
    _print("  To activate in Shadow Warden:")
    _print(f"    1. Add to .env:  EVOLUTION_MODEL={model_id}")
    _print("    2. Restart the warden container:")
    _print("         docker compose up -d --no-deps warden")
    _print("    3. Verify in /api/config response: evolution_model field")
    _print("\n  To revert to Claude Opus:")
    _print("         EVOLUTION_MODEL=claude-opus-4-6")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Fine-tune a Shadow Warden Evolution Engine model.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--dataset",    default=DEFAULT_DATASET,
                   help=f"Path to JSONL dataset (default: {DEFAULT_DATASET})")
    p.add_argument("--base-model", default=DEFAULT_BASE_MODEL,
                   help=f"Base model to fine-tune (default: {DEFAULT_BASE_MODEL})")
    p.add_argument("--epochs",     type=int, default=3,
                   help="Training epochs (default: 3)")
    p.add_argument("--val-split",  type=float, default=0.10,
                   help="Validation fraction 0–1 (default: 0.10)")
    p.add_argument("--seed",       type=int, default=42,
                   help="Random seed for train/val split (default: 42)")
    p.add_argument("--dry-run",    action="store_true",
                   help="Validate and inspect only — no API calls")
    p.add_argument("--no-poll",    action="store_true",
                   help="Submit job but do not wait for completion")
    p.add_argument("--job-id",
                   help="Skip to polling an existing job ID")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    random.seed(args.seed)

    dataset_path = Path(args.dataset)

    # Stage 1 + 2 always run
    records = validate(dataset_path)
    inspect_dataset(records)

    if args.dry_run:
        _print("\n[yellow]--dry-run: stopping before API calls.")
        return

    # Require API key for live stages
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        _print("[red]ANTHROPIC_API_KEY not set.  Export it or use --dry-run.")
        sys.exit(1)

    try:
        import anthropic
    except ImportError:
        _print("[red]anthropic package not installed.  Run: pip install anthropic>=0.40")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    # Stage 6 only — resume polling an existing job
    if args.job_id:
        _print(f"\n  Resuming poll for job {args.job_id}")
        model_id = poll_job(client, args.job_id)
        report(model_id)
        return

    # Stage 3 — split
    train, val = split(records, args.val_split)

    # Stages 4 + 5 — upload + submit inside a temp dir
    with tempfile.TemporaryDirectory() as tmp_dir:
        train_id, val_id = upload_files(client, train, val, tmp_dir)

    job_id = submit_job(
        client,
        train_file_id = train_id,
        val_file_id   = val_id,
        base_model    = args.base_model,
        n_epochs      = args.epochs,
    )

    if args.no_poll:
        _print(f"\n[yellow]--no-poll: job {job_id} submitted. Resume with:")
        _print(f"  python scripts/finetune_evolution.py --job-id {job_id}")
        return

    # Stage 6 + 7
    model_id = poll_job(client, job_id)
    report(model_id)


if __name__ == "__main__":
    main()
