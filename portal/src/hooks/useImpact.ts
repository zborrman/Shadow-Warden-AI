/**
 * portal/src/hooks/useImpact.ts
 * ──────────────────────────────
 * React Query hook for the /financial/impact endpoint.
 * Optional: client-side estimate when API is unavailable.
 */
import { useQuery } from '@tanstack/react-query'
import { fetchImpactReport, type ImpactReport, type ImpactParams } from '@/api/financial'
import { IBM_2024, INDUSTRY_MAP } from '@/data/constants'

export function useImpact(params: ImpactParams = {}) {
  return useQuery<ImpactReport>({
    queryKey:  ['impact', params],
    queryFn:   () => fetchImpactReport(params),
    staleTime: 5 * 60_000,
    retry:     1,
  })
}

/**
 * Client-side ROI estimate — runs instantly without an API call.
 * Used when the /financial/impact endpoint is unavailable or for
 * live slider updates before debouncing the API call.
 */
export function estimateImpact(params: ImpactParams): {
  annual:    number
  incident:  number
  inference: number
  secops:    number
} {
  const mul      = INDUSTRY_MAP[params.industry ?? 'generic']?.multiplier ?? 1.0
  const reqs     = params.monthly_requests ?? 100_000
  const incident = IBM_2024.avgBreachCostUsd * mul * IBM_2024.incidentBaseRate
  const inference = reqs * IBM_2024.shadowBanRate * IBM_2024.avgCostPerRequest * 12
  const incsPerYr = Math.max(1, Math.round(reqs / 50_000))
  const secops    = incsPerYr * IBM_2024.triageHoursPerInc * IBM_2024.socHourlyRate * 12
  return { annual: incident + inference + secops, incident, inference, secops }
}
