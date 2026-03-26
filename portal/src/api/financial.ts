/**
 * portal/src/api/financial.ts
 * ────────────────────────────
 * Typed API functions for the /financial/* endpoints (v2.3).
 */
import { api } from '@/lib/api'

export interface ImpactBreakdown {
  inference_savings_usd:    number
  incident_prevention_usd:  number
  compliance_automation_usd: number
  secops_efficiency_usd:    number
  reputational_value_usd:   number
}

export interface ImpactTotals {
  annual_value_usd:        number
  incident_prevention_usd: number
  inference_savings_usd:   number
  roi_3yr_pct:             number
  payback_months:          number
}

export interface LiveMetrics {
  monthly_requests:         number
  shadow_banned_entities:   number
  pii_redactions:           number
  threats_blocked:          Record<string, number>
  shadow_ban_cost_saved_usd: number
}

export interface ImpactReport {
  industry:      string
  multiplier:    number
  totals:        ImpactTotals
  breakdown:     ImpactBreakdown
  live_metrics?: LiveMetrics
  generated_at:  string
}

export interface RoiSummary {
  roi_1yr_pct:    number
  roi_3yr_pct:    number
  payback_months: number
  annual_value:   number
}

export interface CostSaved {
  shadow_ban_cost_saved_usd: number
  pii_redactions:            number
  threats_blocked_total:     number
}

export interface ImpactParams {
  industry?:         string
  monthly_requests?: number
  live?:             boolean
}

export async function fetchImpactReport(params: ImpactParams = {}): Promise<ImpactReport> {
  const r = await api.get<ImpactReport>('/financial/impact', { params })
  return r.data
}

export async function fetchRoi(): Promise<RoiSummary> {
  const r = await api.get<RoiSummary>('/financial/roi')
  return r.data
}

export async function fetchCostSaved(): Promise<CostSaved> {
  const r = await api.get<CostSaved>('/financial/cost-saved')
  return r.data
}

export async function generateProposal(params: ImpactParams): Promise<{ proposal: string }> {
  const r = await api.post<{ proposal: string }>('/financial/generate-proposal', params)
  return r.data
}
