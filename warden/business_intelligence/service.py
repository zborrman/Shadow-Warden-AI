"""
warden/business_intelligence/service.py  (CM-39)
─────────────────────────────────────────────────
BusinessIntelligenceService — aggregates data from all SMB governance
modules into actionable analytics for the Business Community Platform.

Data sources (all read-only):
  - logs.json (filter events)
  - warden_sep.db (incidents, training, prompts, supplier risk)
  - warden_vendor.db (vendor registry + DPA records)
  - warden_costs.db (cost allocations + budget caps)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from datetime import UTC, datetime, timedelta

from warden.business_intelligence.benchmarking import build_benchmarks
from warden.business_intelligence.predictive import predict_incidents
from warden.business_intelligence.repository import cache_get, cache_set

log = logging.getLogger("warden.business_intelligence.service")

_SEP_DB   = os.getenv("SEP_DB_PATH",      "/tmp/warden_sep.db")
_VENDOR_DB = os.getenv("VENDOR_GOV_DB_PATH", "/tmp/warden_vendor.db")
_COST_DB  = os.getenv("COST_ALLOC_DB_PATH",  "/tmp/warden_costs.db")
_LOGS_PATH = os.getenv("LOGS_PATH",           "/tmp/warden_logs.json")


def _open(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    return con


def _cache_key(*parts: str) -> str:
    raw = ":".join(parts)
    return hashlib.sha1(raw.encode()).hexdigest()[:24]


# ── AI Usage Analytics ─────────────────────────────────────────────────────────

def get_usage_summary(tenant_id: str, period_month: str | None = None) -> dict:
    if not period_month:
        period_month = datetime.now(UTC).strftime("%Y-%m")
    key = _cache_key("usage", tenant_id, period_month)
    cached = cache_get(key)
    if cached:
        return cached

    total = blocked = 0
    latencies: list[float] = []
    categories: dict[str, int] = {}
    daily: dict[str, int] = {}

    try:
        with open(_LOGS_PATH) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if ev.get("tenant_id", "") not in ("", tenant_id):
                    continue
                ts = ev.get("timestamp", "")
                if not ts.startswith(period_month):
                    continue
                total += 1
                verdict = ev.get("verdict", "ALLOW")
                if verdict in ("BLOCK", "HIGH"):
                    blocked += 1
                ms = ev.get("processing_ms", 0.0)
                if isinstance(ms, (int, float)):
                    latencies.append(float(ms))
                cat = ev.get("category") or ev.get("type", "unknown")
                categories[cat] = categories.get(cat, 0) + 1
                day = ts[:10] if len(ts) >= 10 else "unknown"
                daily[day] = daily.get(day, 0) + 1
    except FileNotFoundError:
        pass

    avg_ms = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    block_rate = round(blocked / total * 100, 2) if total else 0.0
    top_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]
    daily_trend = [{"date": d, "count": c} for d, c in sorted(daily.items())]

    result: dict = {
        "tenant_id": tenant_id,
        "period_month": period_month,
        "total_requests": total,
        "blocked_requests": blocked,
        "allowed_requests": total - blocked,
        "avg_latency_ms": avg_ms,
        "block_rate_pct": block_rate,
        "top_categories": [{"category": k, "count": v} for k, v in top_cats],
        "daily_trend": daily_trend,
    }
    cache_set(key, tenant_id, "usage", result)
    return result


# ── Threat Intelligence Dashboard ─────────────────────────────────────────────

def get_threat_summary(tenant_id: str, period_days: int = 30) -> dict:
    key = _cache_key("threats", tenant_id, str(period_days))
    cached = cache_get(key)
    if cached:
        return cached

    since = (datetime.now(UTC) - timedelta(days=period_days)).isoformat()
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    daily: dict[str, int] = {}
    resolve_times: list[float] = []

    try:
        con = _open(_SEP_DB)
        rows = con.execute(
            "SELECT severity, category, status, created_at, resolved_at "
            "FROM ai_incidents WHERE tenant_id=? AND created_at>=?",
            (tenant_id, since),
        ).fetchall()
        con.close()
        for row in rows:
            by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
            by_category[row["category"]] = by_category.get(row["category"], 0) + 1
            day = row["created_at"][:10]
            daily[day] = daily.get(day, 0) + 1
            if row["resolved_at"] and row["created_at"]:
                try:
                    t1 = datetime.fromisoformat(row["created_at"])
                    t2 = datetime.fromisoformat(row["resolved_at"])
                    resolve_times.append((t2 - t1).total_seconds() / 3600)
                except Exception:
                    pass
    except Exception:
        pass

    total = sum(by_severity.values())
    mttr = round(sum(resolve_times) / len(resolve_times), 2) if resolve_times else 0.0
    top_vectors = [k for k, _ in sorted(by_category.items(), key=lambda x: x[1], reverse=True)[:3]]
    trend = [{"date": d, "count": c} for d, c in sorted(daily.items())]

    result: dict = {
        "tenant_id": tenant_id,
        "period_days": period_days,
        "total_threats": total,
        "by_severity": by_severity,
        "by_category": by_category,
        "top_attack_vectors": top_vectors,
        "incident_trend": trend,
        "mttr_hours": mttr,
    }
    cache_set(key, tenant_id, "threats", result)
    return result


# ── Vendor Performance & Risk ──────────────────────────────────────────────────

def get_vendor_scorecards(tenant_id: str) -> list[dict]:
    key = _cache_key("vendors", tenant_id)
    cached = cache_get(key)
    if cached:
        return cached.get("scorecards", [])

    scorecards: list[dict] = []
    try:
        vcon = _open(_VENDOR_DB)
        vendors = vcon.execute(
            "SELECT vendor_id, display_name, risk_tier FROM ai_vendors WHERE tenant_id=? AND status='active'",
            (tenant_id,),
        ).fetchall()
        for v in vendors:
            vid = v["vendor_id"]
            dpa_row = vcon.execute(
                "SELECT expires_at FROM vendor_dpa_records WHERE vendor_id=? AND status='active' ORDER BY expires_at DESC LIMIT 1",
                (vid,),
            ).fetchone()
            compliance = "unknown"
            expiring_soon = False
            if dpa_row and dpa_row["expires_at"]:
                try:
                    exp = datetime.fromisoformat(dpa_row["expires_at"])
                    now = datetime.now(UTC)
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=UTC)
                    days_left = (exp - now).days
                    compliance = "active"
                    expiring_soon = days_left <= 30
                except Exception:
                    compliance = "active"
            spend = 0.0
            try:
                ccon = _open(_COST_DB)
                row = ccon.execute(
                    "SELECT SUM(amount_usd) FROM cost_allocations WHERE vendor_id=?", (vid,)
                ).fetchone()
                ccon.close()
                spend = float(row[0] or 0.0)
            except Exception:
                pass
            incidents = 0
            try:
                scon = _open(_SEP_DB)
                inc_row = scon.execute(
                    "SELECT COUNT(*) FROM ai_incidents WHERE vendor_id=? AND tenant_id=?",
                    (vid, tenant_id),
                ).fetchone()
                scon.close()
                incidents = int(inc_row[0] or 0)
            except Exception:
                pass
            score = 0.5
            try:
                scon2 = _open(_SEP_DB)
                sc_row = scon2.execute(
                    "SELECT composite_score FROM supplier_risk_assessments WHERE vendor_id=? ORDER BY assessed_at DESC LIMIT 1",
                    (vid,),
                ).fetchone()
                scon2.close()
                if sc_row:
                    score = float(sc_row["composite_score"])
            except Exception:
                pass
            scorecards.append({
                "vendor_id": vid,
                "display_name": v["display_name"],
                "risk_tier": v["risk_tier"],
                "composite_score": round(score, 3),
                "compliance_status": compliance,
                "dpa_expiring_soon": expiring_soon,
                "monthly_spend_usd": round(spend, 2),
                "incident_count": incidents,
                "last_assessed": "",
            })
        vcon.close()
    except Exception:
        pass

    cache_set(key, tenant_id, "vendors", {"scorecards": scorecards})
    return scorecards


# ── Cost Optimization Insights ─────────────────────────────────────────────────

def get_cost_insights(tenant_id: str, months: int = 3) -> dict:
    key = _cache_key("costs", tenant_id, str(months))
    cached = cache_get(key)
    if cached:
        return cached

    dept_spend: dict[str, float] = {}
    vendor_spend: dict[str, float] = {}
    monthly: dict[str, float] = {}
    total = 0.0

    try:
        ccon = _open(_COST_DB)
        now = datetime.now(UTC)
        since_month = (now - timedelta(days=months * 31)).strftime("%Y-%m")
        rows = ccon.execute(
            "SELECT department, vendor_id, period_month, amount_usd FROM cost_allocations "
            "WHERE tenant_id=? AND period_month>=?",
            (tenant_id, since_month),
        ).fetchall()
        ccon.close()
        for r in rows:
            dept = r["department"] or "default"
            dept_spend[dept] = dept_spend.get(dept, 0.0) + r["amount_usd"]
            vid = r["vendor_id"] or "unknown"
            vendor_spend[vid] = vendor_spend.get(vid, 0.0) + r["amount_usd"]
            m = r["period_month"]
            monthly[m] = monthly.get(m, 0.0) + r["amount_usd"]
            total += r["amount_usd"]
    except Exception:
        pass

    top_depts = sorted(dept_spend.items(), key=lambda x: x[1], reverse=True)[:5]
    top_vendors = sorted(vendor_spend.items(), key=lambda x: x[1], reverse=True)[:5]

    # Simple anomaly: flag dept if its spend > 2x the avg dept spend
    avg_dept = sum(dept_spend.values()) / len(dept_spend) if dept_spend else 0.0
    anomalies = [d for d, s in dept_spend.items() if s > avg_dept * 2 and avg_dept > 0]

    result: dict = {
        "tenant_id": tenant_id,
        "months_analyzed": months,
        "total_spend_usd": round(total, 2),
        "by_department": [{"department": k, "amount_usd": round(v, 2)} for k, v in top_depts],
        "by_vendor": [{"vendor_id": k, "amount_usd": round(v, 2)} for k, v in top_vendors],
        "monthly_trend": [{"month": m, "amount_usd": round(v, 2)} for m, v in sorted(monthly.items())],
        "anomalous_departments": anomalies,
        "optimization_tips": _cost_tips(dept_spend, vendor_spend, total),
    }
    cache_set(key, tenant_id, "costs", result)
    return result


def _cost_tips(dept: dict, vendor: dict, total: float) -> list[str]:
    tips: list[str] = []
    if len(vendor) == 1:
        tips.append("Single-vendor dependency detected — consider diversifying AI providers to reduce lock-in risk.")
    if total > 0 and max(dept.values(), default=0) / total > 0.6:
        tips.append("One department accounts for >60% of AI spend — review their usage policies.")
    if len(dept) > 5:
        tips.append("Many cost centres tracked — consolidate low-spend departments to reduce overhead.")
    return tips


# ── Compliance Posture Scoring ─────────────────────────────────────────────────

def get_compliance_score(tenant_id: str, community_id: str = "") -> dict:
    key = _cache_key("compliance", tenant_id, community_id)
    cached = cache_get(key)
    if cached:
        return cached

    # Training compliance
    training_pct = 0.0
    try:
        scon = _open(_SEP_DB)
        row = scon.execute(
            "SELECT COUNT(DISTINCT employee_id) as passed, "
            "(SELECT COUNT(DISTINCT employee_id) FROM ai_training_completions WHERE community_id=?) as total "
            "FROM ai_training_completions WHERE community_id=? AND passed=1",
            (community_id, community_id),
        ).fetchone()
        scon.close()
        if row and row["total"] and row["total"] > 0:
            training_pct = row["passed"] / row["total"]
    except Exception:
        pass

    # Vendor DPA coverage
    dpa_pct = 0.0
    try:
        vcon = _open(_VENDOR_DB)
        total_vendors = vcon.execute(
            "SELECT COUNT(*) FROM ai_vendors WHERE tenant_id=? AND status='active'", (tenant_id,)
        ).fetchone()[0]
        if total_vendors > 0:
            covered = vcon.execute(
                "SELECT COUNT(DISTINCT vendor_id) FROM vendor_dpa_records "
                "WHERE tenant_id=? AND status='active'",
                (tenant_id,),
            ).fetchone()[0]
            dpa_pct = covered / total_vendors
        vcon.close()
    except Exception:
        pass

    # Incident closure rate (resolved or closed)
    inc_closure_pct = 0.0
    try:
        scon = _open(_SEP_DB)
        total_inc = scon.execute(
            "SELECT COUNT(*) FROM ai_incidents WHERE tenant_id=?", (tenant_id,)
        ).fetchone()[0]
        if total_inc > 0:
            closed = scon.execute(
                "SELECT COUNT(*) FROM ai_incidents WHERE tenant_id=? AND status IN ('resolved','closed')",
                (tenant_id,),
            ).fetchone()[0]
            inc_closure_pct = closed / total_inc
        scon.close()
    except Exception:
        pass

    # Budget adherence
    budget_pct = 1.0
    try:
        ccon = _open(_COST_DB)
        caps = ccon.execute(
            "SELECT cap_id, department, cap_usd FROM budget_caps WHERE tenant_id=? AND status='active'",
            (tenant_id,),
        ).fetchall()
        if caps:
            month = datetime.now(UTC).strftime("%Y-%m")
            within = 0
            for cap in caps:
                row = ccon.execute(
                    "SELECT SUM(amount_usd) FROM cost_allocations WHERE tenant_id=? AND department=? AND period_month=?",
                    (tenant_id, cap["department"], month),
                ).fetchone()
                spend = float(row[0] or 0.0)
                if spend <= cap["cap_usd"]:
                    within += 1
            budget_pct = within / len(caps)
        ccon.close()
    except Exception:
        pass

    overall = (
        training_pct * 0.30
        + dpa_pct * 0.30
        + inc_closure_pct * 0.20
        + budget_pct * 0.20
    )
    grade = _score_grade(overall)

    result: dict = {
        "tenant_id": tenant_id,
        "community_id": community_id,
        "overall_score": round(overall, 3),
        "grade": grade,
        "training_pct": round(training_pct * 100, 1),
        "vendor_dpa_pct": round(dpa_pct * 100, 1),
        "incident_closure_pct": round(inc_closure_pct * 100, 1),
        "budget_adherence_pct": round(budget_pct * 100, 1),
        "breakdown": {
            "training": round(training_pct, 3),
            "vendor_dpa": round(dpa_pct, 3),
            "incident_closure": round(inc_closure_pct, 3),
            "budget_adherence": round(budget_pct, 3),
        },
    }
    cache_set(key, tenant_id, "compliance", result)
    return result


def _score_grade(score: float) -> str:
    if score >= 0.90:
        return "A"
    if score >= 0.80:
        return "B"
    if score >= 0.70:
        return "C"
    if score >= 0.60:
        return "D"
    return "F"


# ── Community Benchmarking ─────────────────────────────────────────────────────

def get_benchmarks(tenant_id: str, community_id: str = "") -> list[dict]:
    key = _cache_key("benchmarks", tenant_id, community_id)
    cached = cache_get(key)
    if cached:
        return cached.get("benchmarks", [])

    compliance = get_compliance_score(tenant_id, community_id)
    tenant_metrics = {
        "compliance_score": compliance["overall_score"],
        "training_pct": compliance["training_pct"] / 100,
        "vendor_dpa_pct": compliance["vendor_dpa_pct"] / 100,
        "incident_closure_pct": compliance["incident_closure_pct"] / 100,
    }
    # Synthetic peer distribution — in production, aggregated from opted-in communities
    import random
    rng = random.Random(hash(community_id or "global") % 2**32)
    peer_list = [
        {k: max(0.0, min(1.0, v + rng.gauss(0, 0.1))) for k, v in tenant_metrics.items()}
        for _ in range(20)
    ]
    results = build_benchmarks(tenant_id, tenant_metrics, peer_list)
    cache_set(key, tenant_id, "benchmarks", {"benchmarks": results})
    return results


# ── Predictive Incident Analytics ─────────────────────────────────────────────

def get_incident_prediction(tenant_id: str, horizon_days: int = 30) -> dict:
    key = _cache_key("prediction", tenant_id, str(horizon_days))
    cached = cache_get(key)
    if cached:
        return cached

    # Build daily incident counts for the past 90 days
    since = (datetime.now(UTC) - timedelta(days=90)).isoformat()
    daily: dict[str, int] = {}
    try:
        scon = _open(_SEP_DB)
        rows = scon.execute(
            "SELECT created_at FROM ai_incidents WHERE tenant_id=? AND created_at>=?",
            (tenant_id, since),
        ).fetchall()
        scon.close()
        for row in rows:
            day = row["created_at"][:10]
            daily[day] = daily.get(day, 0) + 1
    except Exception:
        pass

    counts = [daily.get((datetime.now(UTC) - timedelta(days=i)).strftime("%Y-%m-%d"), 0)
              for i in range(89, -1, -1)]

    pred = predict_incidents(counts, horizon_days=horizon_days)

    # Risk factors
    risk_factors: list[str] = []
    if pred["trend_direction"] == "rising":
        risk_factors.append("Incident rate is trending upward over the past 90 days.")
    total_open = 0
    try:
        scon = _open(_SEP_DB)
        total_open = scon.execute(
            "SELECT COUNT(*) FROM ai_incidents WHERE tenant_id=? AND status='open'",
            (tenant_id,),
        ).fetchone()[0]
        scon.close()
    except Exception:
        pass
    if total_open > 5:
        risk_factors.append(f"{total_open} incidents currently open — unresolved backlog.")

    recs: list[str] = []
    if pred["trend_direction"] == "rising":
        recs.append("Review recent HIGH/CRITICAL incidents for root cause patterns.")
    if total_open > 5:
        recs.append("Prioritise closing open incidents to reduce overall risk posture.")
    if pred["confidence"] < 0.3:
        recs.append("More historical data needed for accurate predictions — log incidents consistently.")

    result: dict = {
        "tenant_id": tenant_id,
        "horizon_days": horizon_days,
        **pred,
        "risk_factors": risk_factors,
        "recommendations": recs,
    }
    cache_set(key, tenant_id, "prediction", result)
    return result


# ── Custom Report Builder ──────────────────────────────────────────────────────

def build_report(
    tenant_id: str,
    community_id: str = "",
    report_type: str = "full",
    period_months: int = 3,
    include_sections: list[str] | None = None,
) -> dict:
    sections = include_sections or []
    all_sections = (not sections) or report_type == "full"

    report: dict = {
        "tenant_id": tenant_id,
        "community_id": community_id,
        "report_type": report_type,
        "period_months": period_months,
        "generated_at": datetime.now(UTC).isoformat(),
        "sections": {},
    }

    period_month = datetime.now(UTC).strftime("%Y-%m")

    if all_sections or "usage" in sections or report_type in ("executive", "full"):
        report["sections"]["usage"] = get_usage_summary(tenant_id, period_month)

    if all_sections or "threats" in sections or report_type in ("executive", "full"):
        report["sections"]["threats"] = get_threat_summary(tenant_id, period_months * 30)

    if all_sections or "vendors" in sections or report_type in ("vendor", "full"):
        report["sections"]["vendors"] = get_vendor_scorecards(tenant_id)

    if all_sections or "costs" in sections or report_type in ("cost", "full"):
        report["sections"]["costs"] = get_cost_insights(tenant_id, period_months)

    if all_sections or "compliance" in sections or report_type in ("compliance", "executive", "full"):
        report["sections"]["compliance"] = get_compliance_score(tenant_id, community_id)

    if all_sections or "benchmarks" in sections or report_type in ("executive", "full"):
        report["sections"]["benchmarks"] = get_benchmarks(tenant_id, community_id)

    if all_sections or "predictions" in sections or report_type == "full":
        report["sections"]["predictions"] = get_incident_prediction(tenant_id)

    return report
