/**
 * portal/src/api/health.ts
 * ─────────────────────────
 * Typed API functions for the /health endpoint.
 */
import { api } from '@/lib/api'

export interface CacheStatus {
  status:     string
  latency_ms: number
}

export interface HealthResponse {
  status:          string
  service:         string
  evolution:       boolean
  tenants:         string[]
  strict:          boolean
  fail_strategy:   string
  cache:           CacheStatus
  ws_clients:      number
  bypass_rate_1m:  number
  bypasses_1m:     number
  filter_rps_1m:   number
  s3_enabled?:     boolean
  circuit_breaker: {
    status:              string
    bypasses_in_window:  number
    window_secs:         number
    threshold:           number
    cooldown_remaining_s: number
  }
}

export async function fetchHealth(): Promise<HealthResponse> {
  const r = await api.get<HealthResponse>('/health')
  return r.data
}
