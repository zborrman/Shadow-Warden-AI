/**
 * portal/src/hooks/useHealth.ts
 * ──────────────────────────────
 * React Query hook for the /health endpoint.
 * Auto-refreshes every 30 seconds.
 */
import { useQuery } from '@tanstack/react-query'
import { fetchHealth, type HealthResponse } from '@/api/health'

export function useHealth(options?: { refetchInterval?: number }) {
  return useQuery<HealthResponse>({
    queryKey:       ['health'],
    queryFn:        fetchHealth,
    refetchInterval: options?.refetchInterval ?? 30_000,
    staleTime:      10_000,
  })
}

/** Convenience: returns true if the gateway is healthy and responding. */
export function useIsHealthy(): boolean {
  const { data } = useHealth()
  return data?.status === 'ok'
}
