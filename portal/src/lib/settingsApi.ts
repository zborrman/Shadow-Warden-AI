/**
 * Settings API client — wraps all /settings/* endpoints.
 * Uses the same axios instance (with auth interceptors) as api.ts.
 */
import { api } from './api'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ApiKeyOut {
  id: string
  label: string
  prefix: string
  created_at: string
  last_used_at: string | null
  request_count: number
  active: boolean
}

export interface ApiKeyCreated extends ApiKeyOut {
  key: string   // full key — shown once on creation
}

export interface SecretOut {
  id: string
  name: string
  description: string
  created_at: string
  updated_at: string
  expires_at: string | null
}

export interface AgentConfig {
  high_risk_threshold: number
  block_threshold: number
  sova_max_iterations: number
  sova_enabled: boolean
  master_agent_enabled: boolean
  evolution_engine_enabled: boolean
  scan_interval_minutes: number
  causal_arbiter_enabled: boolean
  phish_guard_enabled: boolean
}

export interface NotificationChannel {
  id: string
  type: string
  label: string
  config: Record<string, string>
  enabled: boolean
  created_at: string
  verified: boolean
}

export interface SettingsSummary {
  api_key_count: number
  secret_count: number
  channel_count: number
  agent_config: AgentConfig
  has_expiring_keys: boolean
  has_expiring_secrets: boolean
  unverified_channels: number
}

export interface TestResult {
  ok: boolean
  message: string
  latency_ms: number | null
}

// ── API methods ───────────────────────────────────────────────────────────────

export const settingsApi = {

  // Summary
  getSummary: () =>
    api.get<SettingsSummary>('/settings').then(r => r.data),

  // API Keys
  listApiKeys: () =>
    api.get<ApiKeyOut[]>('/settings/api-keys').then(r => r.data),

  createApiKey: (label: string) =>
    api.post<ApiKeyCreated>('/settings/api-keys', { label }).then(r => r.data),

  revokeApiKey: (keyId: string) =>
    api.delete(`/settings/api-keys/${keyId}`),

  // Secrets
  listSecrets: () =>
    api.get<SecretOut[]>('/settings/secrets').then(r => r.data),

  createSecret: (payload: { name: string; value: string; description?: string; expires_at?: string }) =>
    api.post<SecretOut>('/settings/secrets', payload).then(r => r.data),

  updateSecret: (secretId: string, payload: { value: string; description?: string; expires_at?: string }) =>
    api.put<SecretOut>(`/settings/secrets/${secretId}`, payload).then(r => r.data),

  deleteSecret: (secretId: string) =>
    api.delete(`/settings/secrets/${secretId}`),

  // Agent Config
  getAgentConfig: () =>
    api.get<AgentConfig>('/settings/agents').then(r => r.data),

  updateAgentConfig: (config: AgentConfig) =>
    api.patch<AgentConfig>('/settings/agents', config).then(r => r.data),

  // Notification Channels
  listChannels: () =>
    api.get<NotificationChannel[]>('/settings/notifications').then(r => r.data),

  addChannel: (payload: { type: string; label: string; config: Record<string, string> }) =>
    api.post<NotificationChannel>('/settings/notifications/channels', payload).then(r => r.data),

  testChannel: (channelId: string) =>
    api.post<TestResult>(`/settings/notifications/channels/${channelId}/test`).then(r => r.data),

  deleteChannel: (channelId: string) =>
    api.delete(`/settings/notifications/channels/${channelId}`),
}
