#!/usr/bin/env python3
"""
scripts/impact_analysis.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
CLI entry point for the Shadow Warden AI Dollar Impact Calculator.

Usage examples
──────────────
  # Estimate from traffic volume (no live data needed)
  python scripts/impact_analysis.py --industry fintech --requests 5000000

  # Use live data from logs.json + Redis
  python scripts/impact_analysis.py --live

  # Export to JSON
  python scripts/impact_analysis.py --industry healthcare --export report.json

  # Interactive mode — prompts for all parameters
  python scripts/impact_analysis.py --interactive

  # Change LLM cost assumption
  python scripts/impact_analysis.py --industry saas --cost 0.005
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Ensure the warden package is importable when run from repo root
_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="impact_analysis",
        description="Shadow Warden AI — Dollar Impact Calculator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--industry", "-i",
        choices=["fintech", "healthcare", "ecommerce", "saas", "government", "education", "legal"],
        default="saas",
        help="Industry sector (default: saas)",
    )
    parser.add_argument(
        "--requests", "-r",
        type=int,
        default=None,
        help="Monthly request volume (default: auto-detect from logs, or 1M if not available)",
    )
    parser.add_argument(
        "--cost", "-c",
        type=float,
        default=0.002,
        metavar="USD",
        help="Average LLM inference cost per request in USD (default: 0.002)",
    )
    parser.add_argument(
        "--live", "-l",
        action="store_true",
        help="Load live metrics from logs.json + Redis + Prometheus",
    )
    parser.add_argument(
        "--logs-path",
        default=None,
        metavar="PATH",
        help="Override LOGS_PATH env var for logs.json location",
    )
    parser.add_argument(
        "--export", "-e",
        metavar="FILE",
        default=None,
        help="Export full impact report to a JSON file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of the ASCII report",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Interactive mode — prompt for all parameters",
    )
    parser.add_argument(
        "--years",
        type=int,
        default=3,
        help="Projection horizon in years (default: 3)",
    )
    return parser.parse_args()


def _interactive_prompts() -> argparse.Namespace:
    """Prompt user for all parameters and return a Namespace."""
    print("\n╔══════════════════════════════════════════════════╗")
    print("║  Shadow Warden AI — Dollar Impact Calculator     ║")
    print("╚══════════════════════════════════════════════════╝\n")

    industries = ["fintech", "healthcare", "ecommerce", "saas", "government", "education", "legal"]
    print("Industries: " + ", ".join(industries))
    industry = input("Industry [saas]: ").strip().lower() or "saas"
    if industry not in industries:
        industry = "saas"

    requests_str = input("Monthly requests [1000000]: ").strip()
    try:
        requests = int(requests_str) if requests_str else None
    except ValueError:
        requests = None

    cost_str = input("Avg LLM cost per request USD [0.002]: ").strip()
    try:
        cost = float(cost_str) if cost_str else 0.002
    except ValueError:
        cost = 0.002

    live_str = input("Load live data from logs/Redis? [y/N]: ").strip().lower()
    live = live_str in ("y", "yes")

    export_str = input("Export JSON to file? (leave blank to skip): ").strip()
    export = export_str or None

    ns = argparse.Namespace(
        industry=industry,
        requests=requests,
        cost=cost,
        live=live,
        logs_path=None,
        export=export,
        json=False,
        interactive=False,
        years=3,
    )
    return ns


def main() -> None:
    args = _parse_args()

    if args.interactive:
        args = _interactive_prompts()

    # Override logs path if provided
    if args.logs_path:
        os.environ["LOGS_PATH"] = args.logs_path

    from warden.financial.impact_calculator import DollarImpactCalculator, Industry
    from warden.financial.metrics_reader import MetricsReader

    try:
        ind = Industry(args.industry)
    except ValueError:
        ind = Industry.SAAS

    calc = DollarImpactCalculator(
        industry=ind,
        monthly_requests=args.requests or 1_000_000,
        avg_inference_cost=args.cost,
    )

    if args.live:
        try:
            reader = MetricsReader()
            calc.load_live_metrics(reader)
            if calc.monthly_requests == 0:
                calc.estimate_from_traffic()
            print(f"[live] Loaded data: {reader.monthly_requests():,} requests, "
                  f"{reader.shadow_banned_count()} shadow-banned entities")
        except Exception as exc:
            print(f"[warn] Live data unavailable ({exc}), using traffic estimate")
            calc.estimate_from_traffic()
    else:
        calc.estimate_from_traffic()

    if args.json:
        impact = calc.calculate_total_impact(years=args.years)
        print(json.dumps(impact, indent=2))
    else:
        print(calc.generate_report())

    if args.export:
        calc.export_json(args.export)
        print(f"\n✓ Report exported to: {args.export}")


if __name__ == "__main__":
    main()
