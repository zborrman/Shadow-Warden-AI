/**
 * portal/src/services/impact.ts
 * ──────────────────────────────
 * Business logic layer for the Dollar Impact Calculator.
 * Separates calculation logic from API calls and UI components.
 */
import { IBM_2024, INDUSTRY_MAP, type Industry } from '@/data/constants'
import type { ImpactReport, ImpactBreakdown, ImpactTotals } from '@/api/financial'

export interface ImpactInput {
  industry:        string
  monthlyRequests: number
  annualCostUsd?:  number   // Shadow Warden subscription cost for ROI calculation
  years?:          number   // projection horizon (default: 3)
}

export interface ImpactResult {
  industry:    Industry
  breakdown:   ImpactBreakdown
  totals:      ImpactTotals
  generatedAt: string
}

/** Run the full 5-layer ROI model client-side (mirrors impact_calculator.py). */
export function calculateImpact(input: ImpactInput): ImpactResult {
  const industry     = INDUSTRY_MAP[input.industry] ?? INDUSTRY_MAP['generic']
  const mul          = industry.multiplier
  const reqs         = input.monthlyRequests
  const years        = input.years ?? 3
  const annualCost   = input.annualCostUsd ?? 5_988 // Pro plan × 12

  // 1 — Inference savings (shadow-banned requests × avg token cost × 12 months)
  const inference_savings_usd = reqs * IBM_2024.shadowBanRate * IBM_2024.avgCostPerRequest * 12

  // 2 — Incident prevention (IBM breach cost × multiplier × monthly incident rate × 12)
  const incident_prevention_usd = IBM_2024.avgBreachCostUsd * mul * IBM_2024.incidentBaseRate * 12

  // 3 — Compliance automation (estimated manual audit hours avoided)
  const compliance_automation_usd = mul * 12_000

  // 4 — SecOps efficiency (triage hours × hourly rate × incidents/year)
  const incidentsPerYear = Math.max(1, Math.round(reqs / 50_000))
  const secops_efficiency_usd =
    incidentsPerYear * IBM_2024.triageHoursPerInc * IBM_2024.socHourlyRate * 12

  // 5 — Reputational value (15% of incident prevention — reduced churn/brand damage)
  const reputational_value_usd = incident_prevention_usd * 0.15

  const annual_value_usd =
    inference_savings_usd +
    incident_prevention_usd +
    compliance_automation_usd +
    secops_efficiency_usd +
    reputational_value_usd

  const total_value = annual_value_usd * years
  const roi_3yr_pct = Math.round(((total_value - annualCost * years) / (annualCost * years)) * 100)
  const payback_months = Math.ceil((annualCost / (annual_value_usd / 12)))

  return {
    industry,
    breakdown: {
      inference_savings_usd,
      incident_prevention_usd,
      compliance_automation_usd,
      secops_efficiency_usd,
      reputational_value_usd,
    },
    totals: {
      annual_value_usd,
      incident_prevention_usd,
      inference_savings_usd,
      roi_3yr_pct,
      payback_months,
    },
    generatedAt: new Date().toISOString(),
  }
}

/** Merge a live ImpactReport from the API with the client-side model's structure. */
export function normaliseApiReport(report: ImpactReport): ImpactResult {
  return {
    industry:    INDUSTRY_MAP[report.industry] ?? INDUSTRY_MAP['generic'],
    breakdown:   report.breakdown,
    totals:      report.totals,
    generatedAt: report.generated_at,
  }
}
