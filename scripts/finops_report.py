#!/usr/bin/env python3
"""
FinOps report — unit economics and node capacity in one place (FM-7).

Three sections, all computed from the code's own source of truth (no numbers
typed into this script):

  1. UNIT ECONOMICS — per tier: list price, included quota, revenue per request,
     the derived monthly LLM allowance, and the per-request cost ceiling that
     still clears the margin floor.
  2. MODEL COST — what one representative agent turn costs on each model, and
     how many such turns each tier's allowance buys.
  3. NODE CAPACITY — committed container memory vs. the node's RAM, and the
     sustainable request rate from the M/G/1 queueing model.

Usage
─────
    python scripts/finops_report.py
    python scripts/finops_report.py --node-ram-mb 8192 --service-ms 12
    python scripts/finops_report.py --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from warden.billing.feature_gate import FeatureGate  # noqa: E402
from warden.billing.pricing import (  # noqa: E402
    TARGET_GROSS_MARGIN,
    TIER_PRICE_USD_MONTH,
    annual_price_usd,
)
from warden.finops.capacity import (  # noqa: E402
    audit_mem_limits,
    capacity_ceiling,
    parse_compose_mem_limits,
)
from warden.finops.llm_budget import tier_llm_budget_usd  # noqa: E402
from warden.finops.margin import (  # noqa: E402
    DEFAULT_FLOOR_MARGIN,
    pricing_floor_usd,
    tier_revenue_per_request,
)
from warden.finops.rating import rate_usage  # noqa: E402

_TIERS = ("starter", "individual", "community_business", "pro", "enterprise")
_MODELS = ("claude-haiku-4-5-20251001", "claude-sonnet-4-6", "claude-opus-4-8")

# One representative agent turn: a cached system+tools prefix, a small fresh
# prompt, and a short answer. Deliberately modest — a MasterAgent fan-out is
# several of these.
_TURN = {"input_tokens": 2_000, "output_tokens": 800, "cached_tokens": 20_000}


def unit_economics() -> list[dict]:
    rows = []
    for tier in _TIERS:
        gate = FeatureGate.for_tier(tier)
        quota = gate.quota_req_per_month()
        rev = tier_revenue_per_request(tier)
        rows.append({
            "tier": tier,
            "usd_per_month": TIER_PRICE_USD_MONTH[tier],
            "usd_per_year": annual_price_usd(tier),
            "req_per_month": quota,
            "revenue_per_request_usd": rev,
            "llm_budget_usd_month": tier_llm_budget_usd(tier),
            "cost_ceiling_per_request_usd": None if rev is None else pricing_floor_usd(rev),
        })
    return rows


def model_costs() -> list[dict]:
    rows = []
    for model in _MODELS:
        cost = rate_usage(model, **_TURN)
        rows.append({
            "model": model,
            "usd_per_turn": round(cost.total_usd, 6),
            "cache_savings_usd": round(cost.cache_savings_usd, 6),
            "turns_per_tier": {
                tier: (None if (b := tier_llm_budget_usd(tier)) is None
                       else int(b / cost.total_usd) if cost.total_usd else None)
                for tier in _TIERS
            },
        })
    return rows


def node_capacity(compose: str, node_ram_mb: float, service_ms: float,
                  target_ms: float, cv2: float) -> dict:
    limits = parse_compose_mem_limits(compose)
    mem = audit_mem_limits(limits, node_ram_mb=node_ram_mb)
    cap = capacity_ceiling(service_ms / 1000.0, target_ms / 1000.0, service_cv2=cv2)
    return {
        "compose_file": compose,
        "services_with_limits": len(limits),
        "committed_mb": mem.committed_mb,
        "node_ram_mb": mem.node_ram_mb,
        "available_mb": mem.available_mb,
        "headroom_mb": mem.headroom_mb,
        "over_committed": mem.over_committed,
        "largest_services": sorted(limits.items(), key=lambda kv: -kv[1])[:5],
        "max_rps": round(cap.max_rps, 1),
        "max_rps_utilization": round(cap.max_rps_utilization, 1),
        "max_rps_latency": round(cap.max_rps_latency, 1),
        "requests_per_month_at_ceiling": int(cap.max_rps * 86_400 * 30),
    }


def _usd(v: float | None, places: int = 2) -> str:
    return "-" if v is None else f"${v:,.{places}f}"


def render(report: dict) -> str:
    out: list[str] = []
    add = out.append

    add("=== UNIT ECONOMICS ===")
    add(f"{'tier':<20}{'$/mo':>10}{'$/yr':>12}{'req/mo':>12}{'$/req':>12}"
        f"{'LLM budget':>13}{'max $/req':>12}")
    for r in report["unit_economics"]:
        quota = "unlimited" if not r["req_per_month"] else f"{r['req_per_month']:,}"
        add(f"{r['tier']:<20}{_usd(r['usd_per_month']):>10}{_usd(r['usd_per_year']):>12}"
            f"{quota:>12}{_usd(r['revenue_per_request_usd'], 6):>12}"
            f"{_usd(r['llm_budget_usd_month']):>13}"
            f"{_usd(r['cost_ceiling_per_request_usd'], 6):>12}")
    add(f"\ntarget gross margin {TARGET_GROSS_MARGIN:.0%} | "
        f"per-request margin floor {DEFAULT_FLOOR_MARGIN:.0%}")

    add("\n=== MODEL COST - one agent turn "
        f"({_TURN['input_tokens']:,} in / {_TURN['output_tokens']:,} out / "
        f"{_TURN['cached_tokens']:,} cached) ===")
    add(f"{'model':<30}{'$/turn':>10}{'cache saved':>13}   turns affordable per month")
    for r in report["model_costs"]:
        turns = "  ".join(
            f"{t.split('_')[0]}="
            f"{'unlimited' if r['turns_per_tier'][t] is None else r['turns_per_tier'][t]:>9}"
            for t in _TIERS
        )
        add(f"{r['model']:<30}{_usd(r['usd_per_turn'], 4):>10}"
            f"{_usd(r['cache_savings_usd'], 4):>13}   {turns}")

    cap = report["node_capacity"]
    add("\n=== NODE CAPACITY ===")
    add(f"container memory committed : {cap['committed_mb']:>10,.0f} MB "
        f"across {cap['services_with_limits']} services")
    add(f"schedulable RAM            : {cap['available_mb']:>10,.0f} MB "
        f"(node {cap['node_ram_mb']:,.0f} MB less OS reserve)")
    verdict = "OVER-COMMITTED" if cap["over_committed"] else "ok"
    add(f"headroom                   : {cap['headroom_mb']:>10,.0f} MB   [{verdict}]")
    add("largest limits             : " + ", ".join(
        f"{name} {mb:,.0f}M" for name, mb in cap["largest_services"]))
    add(f"sustainable rate           : {cap['max_rps']:>10,.1f} req/s "
        f"(~{cap['requests_per_month_at_ceiling']:,} req/mo)")
    add(f"  ceiling from utilisation : {cap['max_rps_utilization']:,.1f} req/s")
    add(f"  ceiling from latency     : {cap['max_rps_latency']:,.1f} req/s")
    if cap["over_committed"]:
        add("\nNOTE: summed container limits exceed schedulable RAM. Under load the "
            "kernel OOM-killer, not the scheduler, decides which service dies.")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--compose", default=str(_REPO_ROOT / "docker-compose.yml"))
    ap.add_argument("--node-ram-mb", type=float, default=8192.0)
    ap.add_argument("--service-ms", type=float, default=12.0,
                    help="mean /filter service time in ms")
    ap.add_argument("--target-ms", type=float, default=50.0,
                    help="target mean response time in ms")
    ap.add_argument("--cv2", type=float, default=1.0,
                    help="squared coefficient of variation of service time")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    report = {
        "unit_economics": unit_economics(),
        "model_costs": model_costs(),
        "node_capacity": node_capacity(
            args.compose, args.node_ram_mb, args.service_ms, args.target_ms, args.cv2
        ),
    }
    print(json.dumps(report, indent=2, default=str) if args.json else render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
