/**
 * portal/src/hooks/useFilterStats.ts
 * ────────────────────────────────────
 * React Query hook for filter analytics stats.
 */
import { useQuery } from '@tanstack/react-query'
import { fetchFilterStats, type FilterStats } from '@/api/filter'

export function useFilterStats(days = 30) {
  return useQuery<FilterStats>({
    queryKey:  ['filter-stats', days],
    queryFn:   () => fetchFilterStats(days),
    staleTime: 60_000,
  })
}

/** Derived: block rate as a fraction 0–1 from summary data. */
export function useBlockRate(days = 30): number {
  const { data } = useFilterStats(days)
  if (!data || data.summary.total === 0) return 0
  return data.summary.blocked / data.summary.total
}
