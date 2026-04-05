/**
 * portal/src/lib/hubApi.ts
 * ─────────────────────────
 * Typed client helpers for the Warden Hub (Syndicates).
 * Calls go to /api/hub/... which is the secure server-side proxy.
 */

import axios from 'axios'

const hub = axios.create({ baseURL: '/api/hub' })

// ── Types ─────────────────────────────────────────────────────────────────────

export interface Tunnel {
  tunnel_id:     string
  initiator_sid: string
  responder_sid: string | null
  status:        'ACTIVE' | 'PENDING' | 'EXPIRED' | 'REVOKED'
  ttl_hours:     number
  expires_at:    string | null
  safety_number: string | null
}

export interface Syndicate {
  syndicate_id:   string
  public_key_b64: string
  display_name:   string
  created_at:     string
}

export interface Invite {
  invite_code:  string
  invite_type:  'SINGLE_USER' | 'PLATFORM_FEDERATION'
  target_email: string
  is_used:      boolean
  expires_at:   string | null
  created_at:   string | null
}

export interface BandwidthUsage {
  used_bytes:  number
  limit_bytes: number | null
  plan:        string
  used_gb:     number
  limit_gb:    number | null
  pct:         number
}

export interface HandshakeManifest {
  version:          string
  manifest_type:    string
  invite_code:      string
  inviter_sid:      string
  inviter_pub_key:  string
  nexus_endpoint:   string
  one_time_code:    string
  ttl_hours:        number
  permissions:      Record<string, unknown>
  expires_at:       string
}

// ── Tunnels ───────────────────────────────────────────────────────────────────

export const getTunnels = () =>
  hub.get<{ tunnels: Tunnel[] }>('/tunnels').then(r => r.data.tunnels)

export const revokeTunnel = (tunnelId: string) =>
  hub.delete(`/tunnels/${tunnelId}`).then(r => r.data)

export const initHandshake = (payload: {
  ttl_hours: number
  permissions?: Record<string, unknown>
  target_display_name?: string
}) => hub.post('/tunnels/handshake/init', payload).then(r => r.data)

export const completeHandshake = (payload: {
  tunnel_id:               string
  responder_pub_key:       string
  expected_safety_number?: string
}) => hub.post('/tunnels/handshake/complete', payload).then(r => r.data)

// ── Syndicates ────────────────────────────────────────────────────────────────

export const registerSyndicate = (payload: { display_name: string; ttl_hours_default?: number }) =>
  hub.post<Syndicate>('/syndicates/register', payload).then(r => r.data)

// ── Invites ───────────────────────────────────────────────────────────────────

export const getInvites = () =>
  hub.get<{ invites: Invite[] }>('/invites').then(r => r.data.invites)

export const generateUserInvite = (payload: {
  target_email?: string
  role?: string
  target_group?: string
  ttl_hours?: number
}) => hub.post('/invites/user/generate', payload).then(r => r.data)

export const generatePlatformManifest = (payload: {
  ttl_hours?: number
  permissions?: Record<string, unknown>
  own_endpoint?: string
  peer_display_name?: string
}) => hub.post<HandshakeManifest>('/invites/platform/init', payload).then(r => r.data)

// ── Utilities ─────────────────────────────────────────────────────────────────

export function timeUntil(iso: string | null): string {
  if (!iso) return '∞'
  const ms = new Date(iso).getTime() - Date.now()
  if (ms <= 0) return 'expired'
  const h = Math.floor(ms / 3_600_000)
  const m = Math.floor((ms % 3_600_000) / 60_000)
  if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`
  if (h > 0)   return `${h}h ${m}m`
  return `${m}m`
}

export function fmtBytes(bytes: number): string {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`
  return `${(bytes / 1e3).toFixed(0)} KB`
}
