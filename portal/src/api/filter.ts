/**
 * portal/src/api/filter.ts
 * ─────────────────────────
 * Typed API functions for analytics/filter stats endpoints.
 */
import { api } from '@/lib/api'

export interface RiskDist {
  low:    number
  medium: number
  high:   number
  block:  number
}

export interface FilterSummary {
  total:    number
  blocked:  number
  allowed:  number
  risk_dist: RiskDist
}

export interface DailyPoint {
  date:    string
  total:   number
  blocked: number
  allowed: number
}

export interface FlagCount {
  flag:  string
  count: number
}

export interface FilterStats {
  summary:      FilterSummary
  daily:        DailyPoint[]
  top_flags:    FlagCount[]
  period_days:  number
}

export async function fetchFilterStats(days = 30): Promise<FilterStats> {
  const r = await api.get<FilterStats>('/stats', { params: { days } })
  return r.data
}

export async function fetchSummary(): Promise<FilterSummary> {
  const r = await api.get<FilterSummary>('/stats/summary')
  return r.data
}
