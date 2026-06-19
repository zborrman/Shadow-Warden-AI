/**
 * portal/src/lib/communityHubApi.ts
 * Typed API client for the Warden Community Hub (/communities/* endpoints).
 * Distinct from communitiesApi.ts which handles the encrypted-vault SEP system.
 */

import { api, getAccessToken } from '@/lib/api'

// ── JWT tenant helper ────────────────────────────────────────────────────────

export function getMyTenantId(): string {
  try {
    const token = getAccessToken()
    if (!token) return ''
    const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    const payload = JSON.parse(atob(b64)) as Record<string, string>
    return payload.tid || payload.tenant_id || ''
  } catch {
    return ''
  }
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface HubCommunity {
  community_id:      string
  name:              string
  description:       string
  creator_tenant_id: string
  created_at:        string
  status:            string          // active | suspended
  visibility:        string          // private | public
  join_policy:       string          // invite | open | approval
  settings:          Record<string, unknown>
  member_count?:     number
  data_stats?: {
    total_files:     number
    total_mb:        number
    total_downloads: number
    total_bytes:     number
  }
}

export interface HubMember {
  member_id:    string
  tenant_id:    string
  community_id: string
  role:         string   // owner | admin | member | observer
  joined_at:    string
  public_key:   string
  display_name: string
  status:       string
}

export interface HubFile {
  file_id:            string
  community_id:       string
  uploader_tenant_id: string
  filename:           string
  content_type:       string
  size_bytes:         number
  ueciid:             string
  s3_key:             string
  sha256:             string
  uploaded_at:        string
  download_count:     number
  status:             string
  context:            string
}

export interface ComplianceControl {
  control: string
  status:  'PASS' | 'FAIL' | 'WARN' | 'SKIP' | 'INFO'
  detail:  string
  color?:  string
}

export interface ComplianceReport {
  community_id: string
  score:        number
  status:       'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT'
  controls:     ComplianceControl[]
  gaps:         Array<{ control: string; detail: string }>
  generated_at: string
}

export interface EvolutionBundle {
  bundle_id:            string
  community_id:         string
  publisher_tenant_id:  string
  rule_type:            string
  rule_content:         string
  ueciid:               string
  status:               'pending_review' | 'approved' | 'rejected' | 'imported'
  published_at:         string
  reviewed_at:          string
  import_count:         number
  threat_score:         number
}

export interface EvolutionStats {
  total:         number
  approved:      number
  pending:       number
  rejected:      number
  total_imports: number
}

export interface CommunityStats {
  total:     number
  active:    number
  public:    number
  private:   number
  suspended: number
}

// ── Helpers ──────────────────────────────────────────────────────────────────

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 ** 2).toFixed(1)} MB`
}

export function fmtDate(iso: string): string {
  try { return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) }
  catch { return iso.slice(0, 10) }
}

export function fmtDateShort(iso: string): string {
  try {
    const d = new Date(iso)
    const dd = String(d.getDate()).padStart(2, '0')
    const mm = String(d.getMonth() + 1).padStart(2, '0')
    const yy = String(d.getFullYear()).slice(-2)
    return `${dd}/${mm}/${yy}`
  } catch { return iso.slice(0, 10) }
}

// ── Community CRUD ────────────────────────────────────────────────────────────

export async function listMyCommunities(tenantId?: string): Promise<HubCommunity[]> {
  const tid = tenantId || getMyTenantId()
  const r = await api.get<HubCommunity[]>('/api/communities', { params: { tenant_id: tid } })
  return Array.isArray(r.data) ? r.data : []
}

export async function listPublicCommunities(): Promise<HubCommunity[]> {
  const r = await api.get<HubCommunity[]>('/api/communities', { params: { visibility: 'public' } })
  return Array.isArray(r.data) ? r.data : []
}

export async function getCommunity(id: string): Promise<HubCommunity> {
  const r = await api.get<HubCommunity>(`/api/communities/${id}`)
  return r.data
}

export async function createCommunity(
  name: string,
  description: string,
  visibility = 'private',
  joinPolicy = 'invite',
): Promise<HubCommunity> {
  const tid = getMyTenantId()
  const r = await api.post<HubCommunity>('/api/communities', {
    display_name: name,
    description,
    creator_tenant_id: tid,
    visibility,
    join_policy: joinPolicy,
  })
  return r.data
}

export async function patchCommunity(
  id: string,
  patch: { name?: string; description?: string },
): Promise<{ status: string }> {
  const r = await api.patch<{ status: string }>(`/api/communities/${id}`, patch)
  return r.data
}

export async function deleteCommunity(id: string): Promise<boolean> {
  const tid = getMyTenantId()
  await api.delete(`/api/communities/${id}`, { params: { requester_tenant_id: tid } })
  return true
}

export async function getCommunityStats(): Promise<CommunityStats> {
  const r = await api.get<CommunityStats>('/api/communities/stats')
  return r.data
}

// ── Members ──────────────────────────────────────────────────────────────────

export async function listMembers(communityId: string): Promise<HubMember[]> {
  const r = await api.get<HubMember[]>(`/api/communities/${communityId}/members`)
  return Array.isArray(r.data) ? r.data : []
}

export async function addMember(
  communityId: string,
  tenantId: string,
  role = 'member',
  displayName = '',
): Promise<HubMember> {
  const r = await api.post<HubMember>(`/api/communities/${communityId}/members`, {
    tenant_id: tenantId,
    role,
    display_name: displayName,
  })
  return r.data
}

export async function removeMember(communityId: string, memberId: string): Promise<boolean> {
  await api.delete(`/api/communities/${communityId}/members/${memberId}`)
  return true
}

// ── Data / Files ─────────────────────────────────────────────────────────────

export async function listFiles(communityId: string): Promise<HubFile[]> {
  const r = await api.get<HubFile[]>(`/api/communities/${communityId}/data`)
  return Array.isArray(r.data) ? r.data : []
}

export async function uploadFile(
  communityId: string,
  file: File,
  context = '',
): Promise<HubFile> {
  const token = getAccessToken()
  const tid   = getMyTenantId()
  const form  = new FormData()
  form.append('file', file)
  form.append('context', context)

  const res = await fetch(
    `/api/communities/${communityId}/data/upload?uploader_tenant_id=${encodeURIComponent(tid)}`,
    {
      method:  'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body:    form,
    },
  )
  if (!res.ok) {
    const err = await res.text()
    throw new Error(err || `Upload failed (${res.status})`)
  }
  return res.json() as Promise<HubFile>
}

// ── Compliance ────────────────────────────────────────────────────────────────

export async function getCompliance(communityId: string): Promise<ComplianceReport> {
  const r = await api.get<ComplianceReport>(`/api/communities/${communityId}/compliance`)
  return r.data
}

// ── Evolution Rules ───────────────────────────────────────────────────────────

export async function getEvolutionStats(communityId: string): Promise<EvolutionStats> {
  const r = await api.get<EvolutionStats>(`/api/communities/${communityId}/evolution/stats`)
  return r.data
}

export async function listEvolutionBundles(
  communityId: string,
  status?: string,
): Promise<EvolutionBundle[]> {
  const params: Record<string, string> = {}
  if (status) params.status = status
  const r = await api.get<EvolutionBundle[]>(
    `/api/communities/${communityId}/evolution/bundles`,
    { params },
  )
  return Array.isArray(r.data) ? r.data : []
}

export async function shareRule(
  communityId: string,
  ruleType: string,
  ruleContent: string,
): Promise<EvolutionBundle> {
  const tid = getMyTenantId()
  const r = await api.post<EvolutionBundle>(
    `/api/communities/${communityId}/evolution/share`,
    { publisher_tenant_id: tid, rule_type: ruleType, rule_content: ruleContent },
  )
  return r.data
}

export async function approveRule(communityId: string, bundleId: string): Promise<void> {
  const tid = getMyTenantId()
  await api.post(`/api/communities/${communityId}/evolution/bundles/${bundleId}/approve`, {
    reviewer_tenant_id: tid,
  })
}

export async function rejectRule(communityId: string, bundleId: string): Promise<void> {
  await api.post(`/api/communities/${communityId}/evolution/bundles/${bundleId}/reject`, {})
}

export async function importRule(communityId: string, bundleId: string): Promise<void> {
  await api.post(
    `/api/communities/${communityId}/evolution/bundles/${bundleId}/import`,
    {},
  )
}

// ── Wizard helpers (Create Community Wizard) ──────────────────────────────────

/** Upgrade community keypair to Hybrid PQC (Ed25519 + ML-DSA-65). Enterprise only. */
export async function upgradeToPQC(communityId: string): Promise<void> {
  await api.post(`/api/communities/${communityId}/upgrade-pqc`, {})
}

/** Upload or update the community charter text. */
export async function uploadCharter(communityId: string, content: string): Promise<void> {
  await api.post(`/api/communities/${communityId}/charter`, { content, version: 1 })
}

/** Apply extended community settings (peering, compliance, evolution, webhooks). */
export async function updateSettings(
  communityId: string,
  settings: Record<string, unknown>,
): Promise<void> {
  await api.patch(`/api/communities/${communityId}`, { settings })
}
