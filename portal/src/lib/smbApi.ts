import { api, API_URL } from './api'

const SMB = API_URL

async function smb<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(`${SMB}${path}`)
  if (params) Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v))
  const r = await api.get<T>(url.pathname + url.search)
  return r.data
}

async function smbPost<T>(path: string, body: unknown): Promise<T> {
  const r = await api.post<T>(path, body)
  return r.data
}

// ── Types ─────────────────────────────────────────────────────────────────────

export type Vendor = {
  vendor_id: string; tenant_id: string; display_name: string
  website: string; provider_type: string; risk_tier: string
  status: string; contact_email: string; created_at: string
}

export type DPA = {
  dpa_id: string; vendor_id: string; dpa_type: string
  expires_at: string | null; status: string; doc_ref: string; created_at: string
}

export type Incident = {
  incident_id: string; tenant_id: string; title: string
  severity: string; category: string; status: string; description: string; created_at: string
}

export type PromptEntry = {
  prompt_id: string; community_id: string; title: string; description: string
  category: string; tags: string[]; use_count: number; visibility: string
  version: number; status: string; created_at: string
}

export type Training = {
  program_id: string; community_id: string; title: string
  passing_score: number; valid_days: number; created_at: string
}

export type SupplierAssessment = {
  assessment_id: string; vendor_id: string; composite_score: number
  risk_label: string; assessed_at: string
}

// ── Vendor Governance ─────────────────────────────────────────────────────────

export const vendorApi = {
  list:     (tenantId: string) =>
    smb<{ vendors: Vendor[] }>(`/vendor-gov/vendors?tenant_id=${tenantId}`),
  stats:    (tenantId: string) =>
    smb<Record<string, unknown>>(`/vendor-gov/stats?tenant_id=${tenantId}`),
  expiring: (tenantId: string) =>
    smb<{ dpas: DPA[] }>(`/vendor-gov/dpa/expiring?tenant_id=${tenantId}&within_days=30`),
  create:   (body: { tenant_id: string; display_name: string; website: string; provider_type?: string }) =>
    smbPost<Vendor>('/vendor-gov/vendors', body),
  addDpa:   (vendorId: string, body: object) =>
    smbPost<DPA>(`/vendor-gov/vendors/${vendorId}/dpa`, body),
}

// ── Incident Register ─────────────────────────────────────────────────────────

export const incidentApi = {
  list:   (tenantId: string) =>
    smb<{ incidents: Incident[] }>(`/incidents?tenant_id=${tenantId}&limit=50`),
  stats:  (tenantId: string) =>
    smb<Record<string, unknown>>(`/incidents/stats?tenant_id=${tenantId}`),
  create: (body: object) =>
    smbPost<Incident>('/incidents', body),
  updateStatus: (incidentId: string, status: string) =>
    api.put(`/incidents/${incidentId}/status`, { status }).then(r => r.data),
}

// ── Cost Allocation ───────────────────────────────────────────────────────────

export const costApi = {
  summary:     (tenantId: string, month: string) =>
    smb<Record<string, unknown>>(`/financial/allocation/summary?tenant_id=${tenantId}&period_month=${month}`),
  departments: (tenantId: string) =>
    smb<{ departments: Array<{ department: string; total_usd: number }> }>(
      `/financial/allocation/departments?tenant_id=${tenantId}`),
  record: (body: object) =>
    smbPost<{ alloc_id: string }>('/financial/allocation', body),
}

// ── Prompt Library ────────────────────────────────────────────────────────────

export const promptApi = {
  list:    (communityId: string) =>
    smb<{ prompts: PromptEntry[] }>(`/prompt-library?community_id=${communityId}`),
  create:  (body: { community_id: string; created_by: string; title: string; prompt_text: string; category?: string }) =>
    smbPost<PromptEntry>('/prompt-library', body),
  use:     (promptId: string) =>
    smbPost<{ use_count: number }>(`/prompt-library/${promptId}/use`, {}),
}

// ── Training Records ──────────────────────────────────────────────────────────

export const trainingApi = {
  programs:   (communityId: string) =>
    smb<{ programs: Training[] }>(`/training/programs?community_id=${communityId}`),
  compliance: (communityId: string) =>
    smb<Record<string, unknown>>(`/training/compliance-report?community_id=${communityId}`),
  create:     (body: object) =>
    smbPost<Training>('/training/programs', body),
}

// ── Supplier Risk ─────────────────────────────────────────────────────────────

export const supplierApi = {
  report: (communityId: string) =>
    smb<{ assessments: SupplierAssessment[]; by_risk_label: Record<string, number> }>(
      `/supplier-risk/report/${communityId}`),
  assess: (body: { community_id: string; vendor_id: string; context?: Record<string, number> }) =>
    smbPost<SupplierAssessment>('/supplier-risk/assess', body),
}
