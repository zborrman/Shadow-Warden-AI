/**
 * portal/src/lib/communitiesApi.ts
 * ──────────────────────────────────
 * Typed client helpers for the Business Communities API.
 * All calls go through /api/communities/... (server-side proxy).
 */

import { api } from '@/lib/api'

const BASE = '/api/communities'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface Community {
  community_id:  string
  tenant_id:     string
  display_name:  string
  description:   string
  tier:          string
  active_kid:    string
  status:        string
  created_by:    string
  created_at:    string
  member_count?: number
}

export interface Member {
  member_id:    string
  community_id: string
  external_id:  string
  display_name: string
  clearance:    string
  role:         string
  status:       string
  joined_at:    string
}

export interface EntityMeta {
  entity_id:    string
  community_id: string
  kid:          string
  clearance:    string
  sender_mid:   string
  byte_size:    number
  content_type: string
  status:       string
  created_at:   string
  expires_at:   string | null
}

export interface EntityDetail {
  entity:       EntityMeta
  download_url: string | null
}

// ── Community CRUD ────────────────────────────────────────────────────────────

export async function listCommunities(): Promise<Community[]> {
  const r = await api.get<Community[]>(`${BASE}`)
  return r.data
}

export async function createCommunity(display_name: string, description = ''): Promise<Community> {
  const r = await api.post<Community>(`${BASE}`, { display_name, description })
  return r.data
}

export async function getCommunity(communityId: string): Promise<Community> {
  const r = await api.get<Community>(`${BASE}/${communityId}`)
  return r.data
}

export async function initiateRotation(communityId: string): Promise<Record<string, string>> {
  const r = await api.post<Record<string, string>>(`${BASE}/${communityId}/rotate`)
  return r.data
}

// ── Members ───────────────────────────────────────────────────────────────────

export async function listMembers(communityId: string): Promise<Member[]> {
  const r = await api.get<Member[]>(`${BASE}/${communityId}/members`)
  return r.data
}

export async function inviteMember(
  communityId: string,
  payload: {
    external_id:  string
    display_name: string
    clearance:    string
    role:         string
  },
): Promise<Member> {
  const r = await api.post<Member>(`${BASE}/${communityId}/members`, payload)
  return r.data
}

export async function updateMemberClearance(
  communityId: string,
  memberId:    string,
  clearance:   string,
): Promise<{ member: Member; rotation_required: boolean }> {
  const r = await api.patch<{ member: Member; rotation_required: boolean }>(
    `${BASE}/${communityId}/members/${memberId}/clearance`,
    { clearance },
  )
  return r.data
}

export async function removeMember(communityId: string, memberId: string): Promise<void> {
  await api.delete(`${BASE}/${communityId}/members/${memberId}`)
}

// ── Entities ──────────────────────────────────────────────────────────────────

export async function listEntities(communityId: string): Promise<EntityMeta[]> {
  const r = await api.get<EntityMeta[]>(`${BASE}/${communityId}/entities`)
  return r.data
}

export async function uploadEntity(
  communityId: string,
  payload: {
    content_b64:  string
    clearance:    string
    content_type: string
    sender_mid:   string
  },
): Promise<EntityMeta> {
  const r = await api.post<EntityMeta>(`${BASE}/${communityId}/entities`, payload)
  return r.data
}

export async function getEntityDetail(communityId: string, entityId: string): Promise<EntityDetail> {
  const r = await api.get<EntityDetail>(`${BASE}/${communityId}/entities/${entityId}`)
  return r.data
}

export async function deleteEntity(communityId: string, entityId: string): Promise<void> {
  await api.delete(`${BASE}/${communityId}/entities/${entityId}`)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function fmtBytes(n: number): string {
  if (n < 1024)        return `${n} B`
  if (n < 1024 ** 2)   return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3)   return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}

export function fmtDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  })
}

export const CLEARANCE_COLORS: Record<string, string> = {
  PUBLIC:       'bg-slate-500/15 text-slate-300',
  INTERNAL:     'bg-blue-500/15 text-blue-400',
  CONFIDENTIAL: 'bg-amber-500/15 text-amber-400',
  RESTRICTED:   'bg-red-500/15 text-red-400',
}
