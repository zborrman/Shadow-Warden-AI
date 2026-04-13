"""
warden/financial/impact_calculator.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Dollar Impact Calculator — Shadow Warden AI v2.3

Calculates the concrete financial value delivered by Shadow Warden AI:
  • LLM inference cost saved via shadow banning (zero LLM calls for banned attackers)
  • Prevented security incident costs (IBM Cost of Data Breach 2024 benchmarks)
  • Compliance automation savings (audit hours + GDPR fine risk reduction)
  • SecOps efficiency gains (automated triage vs. manual alert review)
  • Reputational value / customer churn prevention

Inputs come from two sources:
  1. Live production data — via MetricsReader (reads logs.json + Redis ERS)
  2. Business parameters — industry sector, request volume, LLM pricing

Outputs:
  • generate_report() — ASCII table report for CLI / API
  • to_dict()         — structured dict for JSON API responses
  • export_json()     — write report to file

Usage::

    from warden.financial.impact_calculator import DollarImpactCalculator, Industry
    from warden.financial.metrics_reader import MetricsReader

    reader = MetricsReader()
    calc   = DollarImpactCalculator(industry=Industry.FINTECH,
                                    monthly_requests=reader.monthly_requests())
    calc.load_live_metrics(reader)
    print(calc.generate_report())
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

log = logging.getLogger("warden.financial.impact_calculator")


# ── Industry profiles ──────────────────────────────────────────────────────────

class Industry(StrEnum):
    FINTECH     = "fintech"
    HEALTHCARE  = "healthcare"
    ECOMMERCE   = "ecommerce"
    SAAS        = "saas"
    GOVERNMENT  = "government"
    EDUCATION   = "education"
    LEGAL                   = "legal"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"


class ThreatCategory(StrEnum):
    PROMPT_INJECTION    = "prompt_injection"
    JAILBREAK           = "jailbreak"
    PII_LEAKAGE         = "pii_leakage"
    API_ABUSE           = "api_abuse"
    TOOL_ABUSE          = "tool_abuse"
    DATA_EXFILTRATION   = "data_exfiltration"
    SERVICE_DENIAL      = "service_denial"
    COMPLIANCE_VIOLATION = "compliance_violation"


# ── Incident cost tables (IBM Cost of Data Breach 2024) ───────────────────────
# Costs per fully-realised incident (direct + recovery + legal + reputational).
# Values in USD.

@dataclass(frozen=True)
class IncidentCost:
    direct_cost:        float
    recovery_cost:      float
    legal_cost:         float
    reputational_cost:  float
    operational_cost:   float

    @property
    def total(self) -> float:
        return (self.direct_cost + self.recovery_cost + self.legal_cost
                + self.reputational_cost + self.operational_cost)


# Default costs shared across industries (non-specific)
_DEFAULT_COSTS: dict[ThreatCategory, IncidentCost] = {
    ThreatCategory.PROMPT_INJECTION: IncidentCost(
        direct_cost=100_000, recovery_cost=50_000,
        legal_cost=75_000, reputational_cost=150_000, operational_cost=50_000,
    ),
    ThreatCategory.JAILBREAK: IncidentCost(
        direct_cost=150_000, recovery_cost=75_000,
        legal_cost=100_000, reputational_cost=200_000, operational_cost=75_000,
    ),
    ThreatCategory.PII_LEAKAGE: IncidentCost(
        direct_cost=300_000, recovery_cost=150_000,
        legal_cost=250_000, reputational_cost=400_000, operational_cost=100_000,
    ),
    ThreatCategory.API_ABUSE: IncidentCost(
        direct_cost=250_000, recovery_cost=125_000,
        legal_cost=150_000, reputational_cost=350_000, operational_cost=100_000,
    ),
    ThreatCategory.TOOL_ABUSE: IncidentCost(
        direct_cost=200_000, recovery_cost=100_000,
        legal_cost=125_000, reputational_cost=250_000, operational_cost=75_000,
    ),
    ThreatCategory.DATA_EXFILTRATION: IncidentCost(
        direct_cost=500_000, recovery_cost=250_000,
        legal_cost=350_000, reputational_cost=700_000, operational_cost=150_000,
    ),
    ThreatCategory.SERVICE_DENIAL: IncidentCost(
        direct_cost=75_000, recovery_cost=50_000,
        legal_cost=25_000, reputational_cost=100_000, operational_cost=50_000,
    ),
    ThreatCategory.COMPLIANCE_VIOLATION: IncidentCost(
        direct_cost=500_000, recovery_cost=200_000,
        legal_cost=300_000, reputational_cost=600_000, operational_cost=150_000,
    ),
}

# Industry-specific multipliers (risk amplification relative to default)
_INDUSTRY_MULTIPLIERS: dict[Industry, dict[ThreatCategory, float]] = {
    Industry.FINTECH: {
        ThreatCategory.PII_LEAKAGE:          2.2,  # Higher fines, litigation
        ThreatCategory.COMPLIANCE_VIOLATION:  3.5,  # GDPR €20M, PCI-DSS
        ThreatCategory.DATA_EXFILTRATION:     2.5,
        ThreatCategory.API_ABUSE:             1.8,
    },
    Industry.HEALTHCARE: {
        ThreatCategory.PII_LEAKAGE:          3.5,  # HIPAA $100K–$1.9M per violation
        ThreatCategory.COMPLIANCE_VIOLATION:  4.0,
        ThreatCategory.DATA_EXFILTRATION:     3.0,
    },
    Industry.GOVERNMENT: {
        ThreatCategory.DATA_EXFILTRATION:     4.0,  # State secrets
        ThreatCategory.SERVICE_DENIAL:        3.0,  # Critical infrastructure
        ThreatCategory.COMPLIANCE_VIOLATION:  2.5,
    },
    Industry.ECOMMERCE: {
        ThreatCategory.API_ABUSE:             2.5,
        ThreatCategory.PII_LEAKAGE:          1.8,
        ThreatCategory.SERVICE_DENIAL:        2.0,  # Revenue impact
    },
    Industry.LEGAL: {
        ThreatCategory.DATA_EXFILTRATION:     3.0,
        ThreatCategory.PII_LEAKAGE:          2.5,
        ThreatCategory.COMPLIANCE_VIOLATION:  3.0,
    },
    Industry.CRITICAL_INFRASTRUCTURE: {
        ThreatCategory.DATA_EXFILTRATION:     3.5,  # NERC CIP / ICS-CERT incident costs
        ThreatCategory.SERVICE_DENIAL:        3.5,  # Operational shutdown + safety incident
        ThreatCategory.COMPLIANCE_VIOLATION:  3.5,  # NERC CIP fines up to $1M/day
        ThreatCategory.PII_LEAKAGE:          2.5,  # Operator PII + OT network topology
        ThreatCategory.PROMPT_INJECTION:      2.0,  # OT-targeted injection severity
    },
}

# Attack rate as fraction of total requests (industry-specific)
_INDUSTRY_ATTACK_RATES: dict[Industry, float] = {
    Industry.FINTECH:                   0.08,
    Industry.HEALTHCARE:                0.07,
    Industry.ECOMMERCE:                 0.12,
    Industry.SAAS:                      0.05,
    Industry.GOVERNMENT:                0.15,
    Industry.EDUCATION:                 0.03,
    Industry.LEGAL:                     0.06,
    Industry.CRITICAL_INFRASTRUCTURE:   0.18,  # Highest — nation-state APT targeting
}

# How attacks distribute across threat categories
_ATTACK_DISTRIBUTION: dict[ThreatCategory, float] = {
    ThreatCategory.PROMPT_INJECTION:    0.25,
    ThreatCategory.JAILBREAK:           0.20,
    ThreatCategory.API_ABUSE:           0.15,
    ThreatCategory.PII_LEAKAGE:        0.10,
    ThreatCategory.TOOL_ABUSE:          0.10,
    ThreatCategory.DATA_EXFILTRATION:   0.07,
    ThreatCategory.SERVICE_DENIAL:      0.07,
    ThreatCategory.COMPLIANCE_VIOLATION: 0.06,
}


# ── Pricing tiers (for proposal generation) ───────────────────────────────────

PRICING: dict[str, dict] = {
    "developer": {
        "monthly_usd": 0,
        "annual_usd":  0,
        "requests":    100_000,
        "label":       "Developer (Free)",
    },
    "startup": {
        "monthly_usd": 500,
        "annual_usd":  5_000,
        "requests":    1_000_000,
        "label":       "Startup",
    },
    "professional": {
        "monthly_usd": 2_000,
        "annual_usd":  20_000,
        "requests":    10_000_000,
        "label":       "Professional",
    },
    "enterprise": {
        "monthly_usd": 8_000,
        "annual_usd":  80_000,
        "requests":    -1,    # unlimited
        "label":       "Enterprise",
    },
}


# ── Main calculator ────────────────────────────────────────────────────────────

class DollarImpactCalculator:
    """
    Calculates the dollar impact of deploying Shadow Warden AI.

    Parameters
    ----------
    industry         : Industry sector — drives incident cost multipliers and attack rates.
    monthly_requests : Total monthly LLM requests proxied through Warden.
    avg_inference_cost : Average cost per upstream LLM call (USD).
    secops_hourly_rate : Fully-loaded hourly cost of a security analyst (USD).
    """

    # Shadow Warden detection rate (fraction of attacks caught)
    DETECTION_RATE = 0.95
    # Fraction of caught attacks that result in a full incident if unprotected
    INCIDENT_PROBABILITY = 0.30

    def __init__(
        self,
        industry:             Industry = Industry.SAAS,
        monthly_requests:     int      = 1_000_000,
        avg_inference_cost:   float    = 0.002,
        secops_hourly_rate:   float    = 120.0,
    ) -> None:
        self.industry           = industry
        self.monthly_requests   = monthly_requests
        self.avg_inference_cost = avg_inference_cost
        self.secops_hourly_rate = secops_hourly_rate

        # Populated by load_live_metrics() or estimated by _estimate_from_traffic()
        self.threats_blocked:         dict[ThreatCategory, int] = {}
        self.shadow_banned_entities:  int   = 0
        self.pii_redactions:          int   = 0
        self.shadow_ban_cost_saved_usd: float = 0.0  # from Prometheus counter if available

    # ── Data loading ──────────────────────────────────────────────────────────

    def load_live_metrics(self, reader) -> None:
        """Populate from a MetricsReader instance (reads real logs/Redis data)."""
        self.monthly_requests        = reader.monthly_requests()
        self.threats_blocked         = reader.threats_blocked_by_category()
        self.shadow_banned_entities  = reader.shadow_banned_count()
        self.pii_redactions          = reader.pii_redactions_count()
        self.shadow_ban_cost_saved_usd = reader.shadow_ban_cost_saved_usd()

    def estimate_from_traffic(self) -> None:
        """Estimate threat distribution from traffic volume when live data unavailable."""
        rate         = _INDUSTRY_ATTACK_RATES.get(self.industry, 0.05)
        total_attacks = int(self.monthly_requests * rate)
        for cat, share in _ATTACK_DISTRIBUTION.items():
            detected = int(total_attacks * share)
            self.threats_blocked[cat] = int(detected * self.DETECTION_RATE)
        # Estimate shadow bans: roughly 1 banned entity per 50 detected attacks
        self.shadow_banned_entities = max(1, sum(self.threats_blocked.values()) // 50)

    # ── Cost lookups ──────────────────────────────────────────────────────────

    def _incident_cost(self, cat: ThreatCategory) -> float:
        base  = _DEFAULT_COSTS[cat].total
        mult  = _INDUSTRY_MULTIPLIERS.get(self.industry, {}).get(cat, 1.0)
        return base * mult

    # ── Sub-calculations ──────────────────────────────────────────────────────

    def calc_inference_savings(self) -> dict:
        """LLM calls avoided because shadow-banned attackers never reach the upstream model."""
        # If Prometheus has real data, use it; otherwise estimate
        if self.shadow_ban_cost_saved_usd > 0:
            cost_saved = self.shadow_ban_cost_saved_usd
        else:
            avg_requests_before_ban  = 50
            saved_requests           = self.shadow_banned_entities * avg_requests_before_ban
            cost_saved               = saved_requests * self.avg_inference_cost

        saved_requests = int(cost_saved / max(self.avg_inference_cost, 1e-9))
        return {
            "shadow_banned_entities": self.shadow_banned_entities,
            "requests_saved":         saved_requests,
            "cost_saved_usd":         round(cost_saved, 2),
        }

    def calc_incident_prevention(self) -> dict:
        """Cost of incidents that would have occurred without Warden."""
        breakdown = {}
        total     = 0.0
        for cat, blocked in self.threats_blocked.items():
            if blocked == 0:
                continue
            # Not every blocked attack would have become an incident
            incidents_prevented = blocked * self.INCIDENT_PROBABILITY
            unit_cost           = self._incident_cost(cat)
            prevented_cost      = incidents_prevented * unit_cost
            breakdown[cat.value] = {
                "attacks_blocked":     blocked,
                "incidents_prevented": round(incidents_prevented, 1),
                "cost_per_incident":   round(unit_cost, 2),
                "total_prevented_usd": round(prevented_cost, 2),
            }
            total += prevented_cost
        return {"breakdown": breakdown, "total_usd": round(total, 2)}

    def calc_compliance_savings(self) -> dict:
        """
        Audit automation (Evidence Vault vs. manual review) + GDPR fine risk reduction.
        """
        # Manual audit: 1 engineer-hour per 1,000 logged events
        monthly_log_events   = self.monthly_requests * 0.01  # ~1% trigger log events
        manual_hours         = monthly_log_events / 1_000
        analyst_rate         = 150.0  # compliance engineer $/hr
        manual_cost          = manual_hours * analyst_rate
        automated_cost       = manual_cost * 0.10             # 90% reduction via Evidence Vault
        audit_savings        = manual_cost - automated_cost

        # GDPR fine risk reduction from PII vault + redaction
        gdpr_max_fine        = 20_000_000  # €20M absolute max
        pii_incidents_prevented = self.pii_redactions * 0.001  # 0.1% would have become incidents
        fine_reduction       = gdpr_max_fine * (pii_incidents_prevented / max(1, self.pii_redactions))

        return {
            "audit_hours_saved":    round(manual_hours * 0.90, 1),
            "audit_savings_usd":    round(audit_savings, 2),
            "gdpr_fine_reduction":  round(fine_reduction, 2),
            "total_usd":            round(audit_savings + fine_reduction, 2),
        }

    def calc_secops_efficiency(self) -> dict:
        """Time saved by automated triage vs. manual alert review."""
        # Estimate alerts per month (1% of requests trigger an alert)
        monthly_alerts       = int(self.monthly_requests * 0.01)
        # Manual: 15 min per alert; with Warden: 95% auto-triaged
        manual_hours         = monthly_alerts * 0.25
        automated_hours      = monthly_alerts * 0.05 * 0.25
        secops_savings       = (manual_hours - automated_hours) * self.secops_hourly_rate

        # MTTR reduction: 240h → 48h
        incidents_per_month  = sum(self.threats_blocked.values()) * self.INCIDENT_PROBABILITY
        mttr_saving_hrs      = 192  # 240 - 48
        response_savings     = incidents_per_month * mttr_saving_hrs * self.secops_hourly_rate

        return {
            "alerts_per_month":   monthly_alerts,
            "analyst_hours_saved": round(manual_hours - automated_hours, 1),
            "triage_savings_usd":  round(secops_savings, 2),
            "mttr_reduction_hrs":  mttr_saving_hrs,
            "response_savings_usd": round(response_savings, 2),
            "total_usd":           round(secops_savings + response_savings, 2),
        }

    def calc_reputational_value(self) -> dict:
        """Customer churn prevention + brand trust premium."""
        estimated_customers  = max(1, self.monthly_requests // 100)
        avg_ltv              = 5_000
        churn_rate_without   = 0.05
        churn_rate_with      = 0.01
        churn_prevented      = estimated_customers * (churn_rate_without - churn_rate_with)
        churn_value          = churn_prevented * avg_ltv
        trust_premium        = estimated_customers * 100  # $100 LTV uplift for "secure" positioning
        return {
            "estimated_customers": estimated_customers,
            "churn_prevented":     round(churn_prevented, 1),
            "churn_value_usd":     round(churn_value, 2),
            "trust_premium_usd":   round(trust_premium, 2),
            "total_usd":           round(churn_value + trust_premium, 2),
        }

    # ── Full impact calculation ────────────────────────────────────────────────

    def calculate_total_impact(self, years: int = 3) -> dict:
        """
        Full impact calculation with multi-year projection.

        Args:
            years: Projection horizon.

        Returns:
            Structured dict with monthly breakdown, annual totals, ROI, and proposal tiers.
        """
        inference  = self.calc_inference_savings()
        incidents  = self.calc_incident_prevention()
        compliance = self.calc_compliance_savings()
        secops     = self.calc_secops_efficiency()
        reputation = self.calc_reputational_value()

        monthly_total = (
            inference["cost_saved_usd"]
            + incidents["total_usd"]
            + compliance["total_usd"]
            + secops["total_usd"]
            + reputation["total_usd"] / 12
        )

        growth_rate     = 0.20  # 20% annual growth in traffic + attacks
        yearly_impacts  = []
        cumulative      = 0.0
        for y in range(years):
            year_impact = monthly_total * 12 * ((1 + growth_rate) ** y)
            cumulative += year_impact
            yearly_impacts.append({
                "year":       y + 1,
                "impact_usd": round(year_impact, 2),
                "cumulative": round(cumulative, 2),
            })

        # ROI tiers
        tier_roi = {}
        for tier_name, tier in PRICING.items():
            annual_cost = tier["annual_usd"]
            if annual_cost == 0:
                continue
            net       = monthly_total * 12 - annual_cost
            roi_pct   = (net / annual_cost) * 100
            payback   = (annual_cost / monthly_total / 12) if monthly_total > 0 else 0
            tier_roi[tier_name] = {
                "label":           tier["label"],
                "annual_cost_usd": annual_cost,
                "annual_savings":  round(monthly_total * 12, 2),
                "net_benefit_usd": round(net, 2),
                "roi_pct":         round(roi_pct, 1),
                "payback_months":  round(payback * 12, 1),
            }

        return {
            "generated_at":     datetime.now(UTC).isoformat(),
            "industry":         self.industry.value,
            "monthly_requests": self.monthly_requests,
            "monthly_breakdown": {
                "inference_savings_usd":   round(inference["cost_saved_usd"], 2),
                "incident_prevention_usd": round(incidents["total_usd"], 2),
                "compliance_savings_usd":  round(compliance["total_usd"], 2),
                "secops_efficiency_usd":   round(secops["total_usd"], 2),
                "reputational_value_usd":  round(reputation["total_usd"] / 12, 2),
            },
            "monthly_total_usd":   round(monthly_total, 2),
            "annual_total_usd":    round(monthly_total * 12, 2),
            "yearly_projection":   yearly_impacts,
            "cumulative_3y_usd":   round(cumulative, 2),
            "tier_roi":            tier_roi,
            "detail": {
                "inference":  inference,
                "incidents":  incidents,
                "compliance": compliance,
                "secops":     secops,
                "reputation": reputation,
            },
        }

    # ── Report generation ─────────────────────────────────────────────────────

    def generate_report(self) -> str:
        """Return a formatted ASCII report suitable for CLI or plaintext API response."""
        impact = self.calculate_total_impact(years=3)
        bd     = impact["monthly_breakdown"]
        proj   = impact["yearly_projection"]
        tiers  = impact["tier_roi"]
        det    = impact["detail"]

        W = 74  # noqa: N806
        border = "═" * W

        lines = [
            f"╔{border}╗",
            f"║{'SHADOW WARDEN AI — DOLLAR IMPACT ANALYSIS':^{W}}║",
            f"║{'Industry: ' + self.industry.value.upper() + ' | ' + datetime.now(UTC).strftime('%Y-%m-%d'):^{W}}║",
            f"╚{border}╝",
            "",
            "┌─ MONTHLY IMPACT BREAKDOWN " + "─" * (W - 27) + "┐",
            f"│  {'Inference Cost Savings (Shadow Ban)':<44}  ${bd['inference_savings_usd']:>12,.0f}  │",
            f"│  {'Prevented Incident Costs':<44}  ${bd['incident_prevention_usd']:>12,.0f}  │",
            f"│  {'Compliance Automation Savings':<44}  ${bd['compliance_savings_usd']:>12,.0f}  │",
            f"│  {'SecOps Efficiency Gains':<44}  ${bd['secops_efficiency_usd']:>12,.0f}  │",
            f"│  {'Reputational Value Protection':<44}  ${bd['reputational_value_usd']:>12,.0f}  │",
            "│" + "─" * W + "│",
            f"│  {'TOTAL MONTHLY IMPACT':<44}  ${impact['monthly_total_usd']:>12,.0f}  │",
            f"│  {'TOTAL ANNUAL IMPACT':<44}  ${impact['annual_total_usd']:>12,.0f}  │",
            "└" + "─" * W + "┘",
            "",
            "┌─ 3-YEAR PROJECTION " + "─" * (W - 20) + "┐",
        ]

        for yp in proj:
            lines.append(
                f"│  {'Year ' + str(yp['year']) + ' Impact':<44}  ${yp['impact_usd']:>12,.0f}  │"
            )
        lines += [
            "│" + "─" * W + "│",
            f"│  {'CUMULATIVE 3-YEAR IMPACT':<44}  ${impact['cumulative_3y_usd']:>12,.0f}  │",
            "└" + "─" * W + "┘",
            "",
            "┌─ ROI BY PRICING TIER " + "─" * (W - 22) + "┐",
            f"│  {'Tier':<18}  {'Annual Cost':>12}  {'Net Benefit':>12}  {'ROI':>7}  {'Payback':>8}  │",
            "│" + "─" * W + "│",
        ]
        for _tier_name, t in tiers.items():
            lines.append(
                f"│  {t['label']:<18}  "
                f"${t['annual_cost_usd']:>11,.0f}  "
                f"${t['net_benefit_usd']:>11,.0f}  "
                f"{t['roi_pct']:>6.0f}%  "
                f"{t['payback_months']:>5.1f} mo  │"
            )
        lines.append("└" + "─" * W + "┘")

        lines += [
            "",
            "┌─ PROTECTION METRICS " + "─" * (W - 21) + "┐",
            f"│  {'Threats Blocked / Month':<44}  {sum(self.threats_blocked.values()):>13,}  │",
            f"│  {'Shadow-Banned Entities':<44}  {self.shadow_banned_entities:>13,}  │",
            f"│  {'PII Redactions':<44}  {self.pii_redactions:>13,}  │",
            f"│  {'Inference Cost Saved / Month':<44}  ${det['inference']['cost_saved_usd']:>12,.2f}  │",
            "└" + "─" * W + "┘",
            "",
            f"  Assumptions: IBM Cost of Data Breach 2024 · {self.DETECTION_RATE*100:.0f}% detection rate",
            f"  Incident probability if undetected: {self.INCIDENT_PROBABILITY*100:.0f}%",
            f"  Monthly request volume: {self.monthly_requests:,} · LLM cost: ${self.avg_inference_cost:.4f}/req",
        ]

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Return full impact as structured dict (for JSON API)."""
        return self.calculate_total_impact(years=3)

    def export_json(self, path: str = "impact_report.json") -> None:
        """Write full impact report to a JSON file."""
        data = self.to_dict()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        log.info("Dollar impact report exported: %s", path)
